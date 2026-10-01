import os
import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import CRLEntryExtensionOID

REASON_MAPPING = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aACompromise": x509.ReasonFlags.aa_compromise,
}

class CRLService:
    def __init__(self, days_valid: int = 7):
        self.days_valid = days_valid

    def generate_crl(
        self,
        ca_cert: x509.Certificate,
        ca_private_key: Any,
        revoked_certs: List[Dict[str, Any]],
        crl_number: int = 1000
    ) -> x509.CertificateRevocationList:
        """
        Builds and signs an RFC 5280 compliant X.509 Certificate Revocation List.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        next_update = now + datetime.timedelta(days=self.days_valid)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(next_update)

        # Add CRL Number extension
        builder = builder.add_extension(
            x509.CRLNumber(crl_number),
            critical=False
        )

        # Add Authority Key Identifier extension
        try:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False
            )
        except Exception:
            pass

        # Add each revoked certificate
        for item in revoked_certs:
            serial_raw = item["serial_number"]
            # Handle hex or decimal serial
            if isinstance(serial_raw, str):
                try:
                    serial_num = int(serial_raw, 16)
                except ValueError:
                    serial_num = int(serial_raw)
            else:
                serial_num = int(serial_raw)

            rev_date_str = item.get("revocation_date")
            if rev_date_str:
                try:
                    rev_date = datetime.datetime.fromisoformat(rev_date_str)
                except Exception:
                    rev_date = now
            else:
                rev_date = now

            reason_str = item.get("revocation_reason", "unspecified")
            reason_flag = REASON_MAPPING.get(reason_str, x509.ReasonFlags.unspecified)

            revoked_builder = x509.RevokedCertificateBuilder()
            revoked_builder = revoked_builder.serial_number(serial_num)
            revoked_builder = revoked_builder.revocation_date(rev_date)
            revoked_builder = revoked_builder.add_extension(
                x509.CRLReason(reason_flag),
                critical=False
            )
            builder = builder.add_revoked_certificate(revoked_builder.build())

        # Sign CRL with intermediate CA private key
        crl = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
        return crl

    def save_crl(
        self,
        crl: x509.CertificateRevocationList,
        pem_path: Path,
        der_path: Path
    ):
        """Saves CRL in both PEM and DER formats."""
        pem_path.parent.mkdir(parents=True, exist_ok=True)
        der_path.parent.mkdir(parents=True, exist_ok=True)

        pem_bytes = crl.public_bytes(serialization.Encoding.PEM)
        der_bytes = crl.public_bytes(serialization.Encoding.DER)

        pem_path.write_bytes(pem_bytes)
        der_path.write_bytes(der_bytes)
        return pem_bytes, der_bytes
