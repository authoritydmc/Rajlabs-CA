import os
import ipaddress
import secrets
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID

from app.config import (
    ROOT_CERT_PATH,
    INTERMEDIATES,
    BASE_URL,
    CA_ORGANIZATION,
    CA_COUNTRY,
    CA_STATE,
    CA_CITY,
    CRL_DAYS_VALID,
    CRL_FALLBACK_URLS,
    OCSP_FALLBACK_URLS,
)
from app.crypto.profiles import PROFILES
from app.crypto.crl_service import CRLService
from app.database.database import (
    db_save_certificate,
    db_list_certificates,
    db_get_certificate,
    db_revoke_certificate,
    db_get_revoked_certificates,
    db_get_stats
)


class CAManager:
    def __init__(self):
        self.crl_service = CRLService(days_valid=CRL_DAYS_VALID)
        self.root_cert: Optional[x509.Certificate] = None
        self.root_cert_pem: str = ""
        self.intermediates: Dict[str, Dict[str, Any]] = {}
        self.load_cas()

    def load_cas(self):
        """Loads Root CA public certificate and Intermediate CAs dynamically."""
        root_path = Path(os.getenv("ROOT_CA_CERT_PATH", str(ROOT_CERT_PATH)))

        # Check if CA files exist; if missing and AUTO_BOOTSTRAP is true, generate them
        if not root_path.exists() and os.getenv("AUTO_BOOTSTRAP", "false").lower() in ("true", "1", "yes"):
            self.bootstrap_pki(root_path)

        # 1. Load Root CA public cert (never needs root private key at runtime)
        if root_path.exists():
            pem_bytes = root_path.read_bytes()
            self.root_cert = x509.load_pem_x509_certificate(pem_bytes)
            self.root_cert_pem = pem_bytes.decode("utf-8")
        elif os.getenv("ROOT_CA_CERT_PEM"):
            pem_str = os.getenv("ROOT_CA_CERT_PEM", "")
            self.root_cert = x509.load_pem_x509_certificate(pem_str.encode("utf-8"))
            self.root_cert_pem = pem_str

        # 2. Load Intermediates
        for key, conf in INTERMEDIATES.items():
            cert_path = Path(os.getenv(f"INT_{key.upper().replace('-', '_')}_CERT_PATH", str(conf["cert"])))
            key_path = Path(os.getenv(f"INT_{key.upper().replace('-', '_')}_KEY_PATH", str(conf["key"])))
            chain_path = Path(os.getenv(f"INT_{key.upper().replace('-', '_')}_CHAIN_PATH", str(conf["chain"])))

            intermediate_data: Dict[str, Any] = {
                "name": key,
                "description": conf["description"],
                "cert": None,
                "cert_pem": "",
                "key": None,
                "chain_pem": "",
                "crl_pem_path": conf["crl"],
                "crl_der_path": conf["crl_der"],
                "default_for": conf.get("default_for", []),
            }

            if cert_path.exists():
                cert_bytes = cert_path.read_bytes()
                intermediate_data["cert"] = x509.load_pem_x509_certificate(cert_bytes)
                intermediate_data["cert_pem"] = cert_bytes.decode("utf-8")

            if key_path.exists():
                key_bytes = key_path.read_bytes()
                intermediate_data["key"] = serialization.load_pem_private_key(key_bytes, password=None)

            if chain_path.exists():
                intermediate_data["chain_pem"] = chain_path.read_text(encoding="utf-8")
            elif intermediate_data["cert_pem"] and self.root_cert_pem:
                intermediate_data["chain_pem"] = f"{intermediate_data['cert_pem'].strip()}\n{self.root_cert_pem.strip()}"

            self.intermediates[key] = intermediate_data

    def bootstrap_pki(self, root_path: Path):
        """Automatically initializes a new Root CA and Intermediate CAs for fresh installs."""
        print("🌱 Bootstrapping new PKI hierarchy (Root CA & Intermediates)...")
        root_dir = root_path.parent.parent
        root_key_path = root_dir / "private" / "root-ca.key.pem"
        root_dir.mkdir(parents=True, exist_ok=True)
        (root_dir / "private").mkdir(parents=True, exist_ok=True)
        (root_dir / "certs").mkdir(parents=True, exist_ok=True)

        # 1. Generate Root CA Key & Cert (4096-bit RSA, 20-year validity)
        root_key, root_key_pem = self.generate_private_key("rsa4096")
        root_key_path.write_text(root_key_pem)

        root_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_STATE),
            x509.NameAttribute(NameOID.LOCALITY_NAME, CA_CITY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"{CA_ORGANIZATION} Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{CA_ORGANIZATION} Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        root_cert_builder = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(secrets.randbits(64))
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=7300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        )
        root_cert = root_cert_builder.sign(private_key=root_key, algorithm=hashes.SHA256())
        root_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

        # 2. Generate Intermediates (int-server, int-wifi, int-iot)
        for key, conf in INTERMEDIATES.items():
            int_dir = conf["dir"]
            int_cert_path = conf["cert"]
            int_key_path = conf["key"]
            int_chain_path = conf["chain"]

            int_dir.mkdir(parents=True, exist_ok=True)
            (int_dir / "private").mkdir(parents=True, exist_ok=True)
            (int_dir / "certs").mkdir(parents=True, exist_ok=True)
            (int_dir / "crl").mkdir(parents=True, exist_ok=True)

            int_key, int_key_pem = self.generate_private_key("rsa4096")
            int_key_path.write_text(int_key_pem)

            int_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_STATE),
                x509.NameAttribute(NameOID.LOCALITY_NAME, CA_CITY),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, conf["description"]),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{CA_ORGANIZATION} {conf['name'].replace('int-', '').capitalize()} Intermediate CA"),
            ])
            # Root CRL Distribution Points with Fallbacks
            root_crl_urls = [f"{BASE_URL}/crl/root-ca.crl"]
            for fb in CRL_FALLBACK_URLS:
                fb_url = f"{fb}/crl/root-ca.crl"
                if fb_url not in root_crl_urls:
                    root_crl_urls.append(fb_url)

            root_crl_dp = x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(u) for u in root_crl_urls],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ])

            # Root AIA with Fallbacks
            root_aia_descriptions = [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(f"{BASE_URL}/api/v1/ca/root/cert")
                )
            ]
            for fb in CRL_FALLBACK_URLS:
                fb_root_cert = f"{fb}/certs/root-ca.crt"
                root_aia_descriptions.append(
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(fb_root_cert)
                    )
                )

            int_builder = (
                x509.CertificateBuilder()
                .subject_name(int_subject)
                .issuer_name(root_subject)
                .public_key(int_key.public_key())
                .serial_number(secrets.randbits(64))
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
                .add_extension(root_crl_dp, critical=False)
                .add_extension(x509.AuthorityInformationAccess(root_aia_descriptions), critical=False)
            )
            int_cert = int_builder.sign(private_key=root_key, algorithm=hashes.SHA256())
            int_cert_pem = int_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            int_cert_path.write_text(int_cert_pem)
            root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            int_chain_path.write_text(f"{int_cert_pem.strip()}\n{root_cert_pem.strip()}\n")

        print("✅ PKI hierarchy bootstrapped successfully.")

    def get_intermediate(self, ca_name: str) -> Dict[str, Any]:
        if ca_name not in self.intermediates:
            raise ValueError(f"Intermediate CA '{ca_name}' not found. Available: {list(self.intermediates.keys())}")
        ca = self.intermediates[ca_name]
        if not ca["cert"] or not ca["key"]:
            raise ValueError(f"Intermediate CA '{ca_name}' is not fully loaded (missing cert or private key).")
        return ca

    def generate_private_key(self, algorithm: str = "rsa2048") -> Tuple[Any, str]:
        """Generates a private key based on requested algorithm."""
        algo = algorithm.lower()
        if algo == "rsa2048":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algo == "rsa4096":
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        elif algo in ("ecdsa256", "p256", "secp256r1"):
            key = ec.generate_private_key(ec.SECP256R1())
        elif algo in ("ecdsa384", "p384", "secp384r1"):
            key = ec.generate_private_key(ec.SECP384R1())
        elif algo == "ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        return key, pem

    def issue_certificate(
        self,
        common_name: str,
        sans: List[str],
        ca_name: str = "int-server",
        profile_name: str = "server",
        key_algorithm: str = "rsa2048",
        days: Optional[int] = None,
        csr_pem: Optional[str] = None,
        organization: Optional[str] = None,
        issued_by: str = "manual"
    ) -> Dict[str, Any]:
        """
        Signs and issues a leaf certificate.
        Supports either server-side key generation or user-submitted CSR (Zero Trust).
        """
        ca = self.get_intermediate(ca_name)
        ca_cert = ca["cert"]
        ca_key = ca["key"]

        profile = PROFILES.get(profile_name, PROFILES["server"])
        validity_days = days if days is not None else profile["default_days"]

        # Handle Public Key: either from CSR or generate new private key
        priv_key_pem = None
        if csr_pem:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
            if not csr.is_signature_valid:
                raise ValueError("CSR signature verification failed.")
            subject_public_key = csr.public_key()
            # If SANs empty, try extract from CSR
            if not sans:
                try:
                    ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(name.value) for name in ext.value]
                except Exception:
                    pass
        else:
            key_obj, priv_key_pem = self.generate_private_key(key_algorithm)
            subject_public_key = key_obj.public_key()

        # Build Subject DN
        org = organization or CA_ORGANIZATION
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_STATE),
            x509.NameAttribute(NameOID.LOCALITY_NAME, CA_CITY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # RFC 5280 64-bit random positive serial number
        serial_number = secrets.randbits(64)

        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = now - datetime.timedelta(minutes=5) # Allow 5m clock skew
        not_after = now + datetime.timedelta(days=validity_days)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject_name)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(subject_public_key)
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)

        # 1. Basic Constraints: End Entity (not a CA)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        # 2. Key Usage from profile
        ku_cfg = profile["key_usages"]
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=ku_cfg.get("digital_signature", True),
                content_commitment=ku_cfg.get("content_commitment", False),
                key_encipherment=ku_cfg.get("key_encipherment", True),
                data_encipherment=ku_cfg.get("data_encipherment", False),
                key_agreement=ku_cfg.get("key_agreement", False),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # 3. Extended Key Usage from profile
        if profile.get("extended_key_usages"):
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(profile["extended_key_usages"]),
                critical=False
            )

        # 4. Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_public_key),
            critical=False
        )

        # 5. Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False
        )

        # 6. Subject Alternative Names (SANs)
        san_items = []
        # Ensure common_name is in SANs if it looks like a DNS name or IP
        all_sans = list(set([common_name] + sans))
        for item in all_sans:
            item = item.strip()
            if not item:
                continue
            try:
                ip_obj = ipaddress.ip_address(item)
                san_items.append(x509.IPAddress(ip_obj))
            except ValueError:
                san_items.append(x509.DNSName(item))

        if san_items:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_items),
                critical=False
            )

        # 7. CRL Distribution Points (Primary active host + fallback domains)
        crl_urls = [f"{BASE_URL}/crl/{ca_name}.crl"]
        for fb in CRL_FALLBACK_URLS:
            fb_crl = f"{fb}/crl/{ca_name}.crl"
            if fb_crl not in crl_urls:
                crl_urls.append(fb_crl)

        crl_dp = x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(u) for u in crl_urls],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
        ])
        builder = builder.add_extension(crl_dp, critical=False)

        # 8. Authority Information Access (AIA) - OCSP + CA Issuer with Fallbacks
        ocsp_urls = [f"{BASE_URL}/ocsp"]
        for fb in OCSP_FALLBACK_URLS:
            if fb not in ocsp_urls:
                ocsp_urls.append(fb)

        issuer_urls = [f"{BASE_URL}/api/v1/ca/{ca_name}/cert"]
        for fb in CRL_FALLBACK_URLS:
            fb_issuer = f"{fb}/certs/{ca_name}.crt"
            if fb_issuer not in issuer_urls:
                issuer_urls.append(fb_issuer)

        aia_descriptions = []
        for u in ocsp_urls:
            aia_descriptions.append(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(u)
                )
            )
        for u in issuer_urls:
            aia_descriptions.append(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(u)
                )
            )

        aia = x509.AuthorityInformationAccess(aia_descriptions)
        builder = builder.add_extension(aia, critical=False)

        # Sign Certificate with Intermediate CA
        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Compute Fingerprints
        fp_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
        formatted_fp = ":".join(fp_sha256[i:i+2] for i in range(0, len(fp_sha256), 2))

        # Build full chain
        full_chain_pem = f"{cert_pem.strip()}\n{ca['chain_pem'].strip()}"

        # Save to SQLite Database
        serial_str = hex(serial_number)[2:]
        cert_id = db_save_certificate(
            serial_number=serial_str,
            common_name=common_name,
            sans=[str(s) for s in all_sans],
            ca_name=ca_name,
            profile=profile_name,
            key_algorithm=key_algorithm,
            not_before=not_before,
            not_after=not_after,
            cert_pem=cert_pem,
            priv_key_pem=priv_key_pem,
            csr_pem=csr_pem,
            fingerprint_sha256=formatted_fp,
            issued_by=issued_by
        )

        return {
            "id": cert_id,
            "serial_number": serial_str,
            "common_name": common_name,
            "sans": all_sans,
            "ca_name": ca_name,
            "profile": profile_name,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "cert_pem": cert_pem,
            "priv_key_pem": priv_key_pem,
            "chain_pem": full_chain_pem,
            "fingerprint_sha256": formatted_fp,
        }

    def renew_certificate(self, serial_or_id: str, new_days: Optional[int] = None) -> Dict[str, Any]:
        """Renews an existing certificate with a new expiration date."""
        old = db_get_certificate(serial_or_id)
        if not old:
            raise ValueError(f"Certificate {serial_or_id} not found.")

        return self.issue_certificate(
            common_name=old["common_name"],
            sans=old["sans"],
            ca_name=old["ca_name"],
            profile_name=old["profile"],
            key_algorithm=old["key_algorithm"],
            days=new_days,
            issued_by="renewal"
        )

    def revoke_certificate(self, serial_or_id: str, reason: str = "unspecified", actor: str = "admin") -> bool:
        """Revokes a certificate and rebuilds the intermediate CRL immediately."""
        cert_record = db_get_certificate(serial_or_id)
        if not cert_record:
            raise ValueError(f"Certificate {serial_or_id} not found.")

        serial_str = cert_record["serial_number"]
        success = db_revoke_certificate(serial_str, reason=reason, actor=actor)
        if success:
            # Rebuild CRL for this intermediate
            self.rebuild_crl(cert_record["ca_name"])
            return True
        return False

    def rebuild_crl(self, ca_name: str):
        """Generates and writes an updated CRL for an intermediate CA."""
        ca = self.get_intermediate(ca_name)
        revoked_list = db_get_revoked_certificates(ca_name)
        crl = self.crl_service.generate_crl(
            ca_cert=ca["cert"],
            ca_private_key=ca["key"],
            revoked_certs=revoked_list
        )
        self.crl_service.save_crl(
            crl=crl,
            pem_path=ca["crl_pem_path"],
            der_path=ca["crl_der_path"]
        )

    def export_pkcs12(self, cert_pem: str, key_pem: str, password: str, name: str = "rajlabs-cert") -> bytes:
        """Packages a certificate, private key, and CA chain into a PKCS#12 (.pfx/.p12) bundle."""
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)

        cas = []
        if self.root_cert:
            cas.append(self.root_cert)

        pfx_data = pkcs12.serialize_key_and_certificates(
            name=name.encode("utf-8"),
            key=key,
            cert=cert,
            cas=cas,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
        )
        return pfx_data


# Global CA Singleton
ca_manager = CAManager()
