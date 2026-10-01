from typing import Dict, Any, List
from cryptography.x509.oid import ExtendedKeyUsageOID

PROFILES: Dict[str, Dict[str, Any]] = {
    "server": {
        "id": "server",
        "name": "TLS Web Server",
        "description": "Standard SSL/TLS certificate for Web servers, reverse proxies, APIs, routers, NAS",
        "default_ca": "int-server",
        "key_usages": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usages": [
            ExtendedKeyUsageOID.SERVER_AUTH,
        ],
        "default_days": 365,
    },
    "client": {
        "id": "client",
        "name": "mTLS Client Authentication",
        "description": "Client certificate for mutual TLS, VPN users, API client authentication, SSH certificates",
        "default_ca": "int-server",
        "key_usages": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usages": [
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ],
        "default_days": 365,
    },
    "wifi": {
        "id": "wifi",
        "name": "WiFi & 802.1X EAP-TLS",
        "description": "Certificate for WPA2/WPA3 Enterprise RADIUS servers (FreeRADIUS) and EAP-TLS client authentication",
        "default_ca": "int-wifi",
        "key_usages": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usages": [
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ],
        "default_days": 730,
    },
    "iot": {
        "id": "iot",
        "name": "IoT & Embedded Device",
        "description": "Lightweight mutual TLS certificate for microcontrollers (ESP32), MQTT brokers, Home Assistant",
        "default_ca": "int-iot",
        "key_usages": {
            "digital_signature": True,
            "key_encipherment": True,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usages": [
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ],
        "default_days": 1825, # 5 years for embedded devices
    },
    "codesign": {
        "id": "codesign",
        "name": "Code Signing",
        "description": "Signs executables, scripts, and software packages for internal trust",
        "default_ca": "int-server",
        "key_usages": {
            "digital_signature": True,
            "key_encipherment": False,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "extended_key_usages": [
            ExtendedKeyUsageOID.CODE_SIGNING,
        ],
        "default_days": 730,
    }
}
