#!/usr/bin/env python3
"""
Script per scaricare i certificati delle CA italiane accreditate.
Include CA root e intermedie dei principali provider.
"""

import sys
import ssl
import urllib.request
import base64
from pathlib import Path
from xml.etree import ElementTree as ET

# URL della Trust List italiana
TSL_IT_URL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"

# URL diretti dei certificati delle principali CA italiane
# Questi includono sia root che intermediate
DIRECT_CA_URLS = [
    # ArubaPEC
    ("ArubaPEC EU Root CA", "https://www.pec.it/crl/ArubaPEC_Root.crt"),
    ("ArubaPEC EU Qualified CA G1", "https://www.pec.it/crl/ArubaPEC_EU_Qualified_Certificates_CA_G1.crt"),
    # InfoCert
    ("InfoCert Qualified CA 3", "https://www.firma.infocert.it/crl/InfoCert_Qualified_Electronic_Signature_CA_3.crt"),
    # Namirial
    ("Namirial CA Firma Qualificata", "https://www.namirialtsp.com/repository/NAMIRIAL_CA_FIRMA_QUALIFICATA.cer"),
    # Intesi Group
    ("Intesi Group EU Qualified CA G2", "https://www.intesigroup.com/repository/Intesi_Group_EU_Qualified_Electronic_Signature_CA_G2.cer"),
]


def download_url(url: str, timeout: int = 30) -> bytes:
    """Download content from URL."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
        return response.read()


def extract_certs_from_tsl(xml_content: bytes) -> list[tuple[str, bytes]]:
    """Extract all certificates from Trust Service List XML."""
    certs = []

    try:
        root = ET.fromstring(xml_content)

        # Find all X509Certificate elements anywhere in the document
        for elem in root.iter():
            if elem.tag.endswith("}X509Certificate") or elem.tag == "X509Certificate":
                if elem.text:
                    try:
                        cert_b64 = "".join(elem.text.split())
                        cert_der = base64.b64decode(cert_b64)
                        if len(cert_der) > 100:  # Sanity check
                            certs.append(("TSL Certificate", cert_der))
                    except Exception:
                        continue

    except ET.ParseError as e:
        print(f"Warning: Error parsing TSL XML: {e}", file=sys.stderr)

    return certs


def der_to_pem(der_cert: bytes) -> str:
    """Convert DER certificate to PEM format."""
    b64 = base64.b64encode(der_cert).decode("ascii")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def get_cert_subject_cn(der_cert: bytes) -> str:
    """Try to extract CN from certificate."""
    try:
        from cryptography.x509 import load_der_x509_certificate
        from cryptography import x509 as crypto_x509
        cert = load_der_x509_certificate(der_cert)
        for attr in cert.subject:
            if attr.oid == crypto_x509.oid.NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return "Unknown"


def main():
    output_file = Path("ca-italiane.pem")

    if len(sys.argv) > 1:
        output_file = Path(sys.argv[1])

    print("Downloading Italian Trusted CA certificates...")
    print()

    all_certs = []

    # Download from direct URLs first (most reliable)
    print("Downloading from known CA URLs...")
    for name, url in DIRECT_CA_URLS:
        try:
            print(f"  {name}...", end=" ", flush=True)
            content = download_url(url, timeout=15)

            # Check if PEM or DER
            if b"-----BEGIN CERTIFICATE-----" in content:
                # PEM format - extract DER
                import re
                match = re.search(
                    b"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
                    content,
                    re.DOTALL
                )
                if match:
                    cert_der = base64.b64decode(match.group(1))
                    all_certs.append((name, cert_der))
                    print("OK (PEM)")
            else:
                # DER format
                all_certs.append((name, content))
                print("OK (DER)")

        except Exception as e:
            print(f"FAILED ({e})")

    # Try to download from official TSL
    print(f"\nFetching EU Trust List from: {TSL_IT_URL}")
    try:
        tsl_content = download_url(TSL_IT_URL, timeout=60)
        tsl_certs = extract_certs_from_tsl(tsl_content)
        print(f"  Found {len(tsl_certs)} certificates in TSL")
        all_certs.extend(tsl_certs)
    except Exception as e:
        print(f"  Warning: Could not fetch TSL: {e}", file=sys.stderr)

    # Deduplicate by certificate content
    seen = set()
    unique_certs = []
    for name, cert_der in all_certs:
        if cert_der not in seen:
            seen.add(cert_der)
            cn = get_cert_subject_cn(cert_der)
            unique_certs.append((cn or name, cert_der))

    if not unique_certs:
        print("Error: No certificates found!", file=sys.stderr)
        sys.exit(1)

    # Write PEM bundle
    print()
    print(f"Writing {len(unique_certs)} unique certificates to: {output_file}")

    with open(output_file, "w") as f:
        f.write("# Italian Trusted CA Certificates\n")
        f.write(f"# Total certificates: {len(unique_certs)}\n\n")

        for name, cert_der in unique_certs:
            f.write(f"# {name}\n")
            f.write(der_to_pem(cert_der))
            f.write("\n")

    print()
    print("Certificates included:")
    for name, _ in unique_certs:
        print(f"  - {name}")

    print()
    print("Done! Use with:")
    print(f"  python3 verify_cades.py documento.p7m --ca-bundle {output_file}")
    print(f"  python3 verify_pades.py documento.pdf --ca-bundle {output_file}")


if __name__ == "__main__":
    main()
