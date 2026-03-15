#!/usr/bin/env python3
"""
Universal digital signature verification script.
Supports both CAdES (.p7m) and PAdES (PDF embedded) signatures.
Automatically detects signature type based on file extension.
"""

import sys
import argparse
import warnings
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

# Suppress warnings
warnings.filterwarnings('ignore')

# CAdES imports
from asn1crypto import cms, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature

# PAdES imports
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


# ============================================================================
# Common data structures
# ============================================================================

@dataclass
class SignerInfo:
    """Information about a signer extracted from the certificate."""
    common_name: Optional[str] = None
    given_name: Optional[str] = None
    surname: Optional[str] = None
    organization: Optional[str] = None
    serial_number: Optional[str] = None
    email: Optional[str] = None

    @property
    def full_name(self) -> str:
        """Return the full name of the signer."""
        if self.given_name and self.surname:
            return f"{self.given_name} {self.surname}"
        return self.common_name or "Unknown"


@dataclass
class SignatureResult:
    """Result of signature verification."""
    is_valid: bool
    signature_type: str  # "CAdES" or "PAdES"
    signer: Optional[SignerInfo] = None
    signing_time: Optional[datetime] = None
    error: Optional[str] = None
    certificate_chain_valid: bool = False
    certificate_expired: bool = False  # True if certificate is currently expired
    content: Optional[bytes] = None  # For CAdES: extracted content
    covers_whole_document: bool = True  # For PAdES
    level: int = 1  # Nesting level (1 = outermost signature)


# ============================================================================
# Certificate utilities (shared)
# ============================================================================

def get_default_ca_bundle() -> Optional[Path]:
    """Get the default CA bundle path (ca-italiane.pem in script directory)."""
    script_dir = Path(__file__).parent
    default_bundle = script_dir / "ca-italiane.pem"
    if default_bundle.exists():
        return default_bundle
    return None


def load_ca_certificates_cryptography(ca_bundle_path: Optional[Path] = None) -> list[x509.Certificate]:
    """Load CA certificates for CAdES verification (cryptography library format)."""
    import re
    ca_certs = []

    # Use default bundle if not specified
    if ca_bundle_path is None:
        ca_bundle_path = get_default_ca_bundle()

    paths_to_try = []
    if ca_bundle_path and ca_bundle_path.exists():
        paths_to_try.append(ca_bundle_path)

    system_ca_paths = [
        Path("/etc/ssl/certs/ca-certificates.crt"),
        Path("/etc/pki/tls/certs/ca-bundle.crt"),
        Path("/etc/ssl/cert.pem"),
        Path("/usr/local/etc/openssl/cert.pem"),
    ]
    paths_to_try.extend(system_ca_paths)

    for ca_path in paths_to_try:
        if ca_path.exists() and not ca_certs:
            try:
                content = ca_path.read_bytes()
                if b"-----BEGIN CERTIFICATE-----" in content:
                    pem_certs = re.findall(
                        b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                        content,
                        re.DOTALL
                    )
                    for pem_cert in pem_certs:
                        try:
                            cert = load_pem_x509_certificate(pem_cert)
                            ca_certs.append(cert)
                        except Exception:
                            continue
                else:
                    try:
                        cert = load_der_x509_certificate(content)
                        ca_certs.append(cert)
                    except Exception:
                        pass
                if ca_certs:
                    break
            except Exception:
                continue

    return ca_certs


def load_ca_certificates_asn1(ca_bundle_path: Optional[Path] = None) -> list:
    """Load CA certificates for PAdES verification (asn1crypto format)."""
    from asn1crypto import pem, x509 as asn1_x509

    # Use default bundle if not specified
    if ca_bundle_path is None:
        ca_bundle_path = get_default_ca_bundle()

    ca_certs = []

    paths_to_try = []
    if ca_bundle_path and ca_bundle_path.exists():
        paths_to_try.append(ca_bundle_path)

    system_ca_paths = [
        Path("/etc/ssl/certs/ca-certificates.crt"),
        Path("/etc/pki/tls/certs/ca-bundle.crt"),
        Path("/etc/ssl/cert.pem"),
        Path("/usr/local/etc/openssl/cert.pem"),
    ]
    paths_to_try.extend(system_ca_paths)

    for ca_path in paths_to_try:
        if ca_path.exists():
            try:
                content = ca_path.read_bytes()
                if pem.detect(content):
                    for type_name, headers, der_bytes in pem.unarmor(content, multiple=True):
                        if type_name == "CERTIFICATE":
                            try:
                                cert = asn1_x509.Certificate.load(der_bytes)
                                ca_certs.append(cert)
                            except Exception:
                                continue
                else:
                    try:
                        cert = asn1_x509.Certificate.load(content)
                        ca_certs.append(cert)
                    except Exception:
                        pass

                if ca_certs:
                    break
            except Exception:
                continue

    return ca_certs


def extract_signer_info_cryptography(cert: x509.Certificate) -> SignerInfo:
    """Extract signer information from X.509 certificate (cryptography library)."""
    info = SignerInfo()

    for attr in cert.subject:
        oid = attr.oid
        value = attr.value

        if oid == x509.oid.NameOID.COMMON_NAME:
            info.common_name = value
        elif oid == x509.oid.NameOID.GIVEN_NAME:
            info.given_name = value
        elif oid == x509.oid.NameOID.SURNAME:
            info.surname = value
        elif oid == x509.oid.NameOID.ORGANIZATION_NAME:
            info.organization = value
        elif oid == x509.oid.NameOID.SERIAL_NUMBER:
            info.serial_number = value
        elif oid == x509.oid.NameOID.EMAIL_ADDRESS:
            info.email = value

    return info


def extract_signer_info_asn1(cert) -> SignerInfo:
    """Extract signer information from certificate (asn1crypto format)."""
    info = SignerInfo()
    subject = cert.subject

    for rdn in subject.chosen:
        for attr in rdn:
            oid = attr["type"].native
            value = attr["value"].native

            if oid == "common_name":
                info.common_name = value
            elif oid == "given_name":
                info.given_name = value
            elif oid == "surname":
                info.surname = value
            elif oid == "organization_name":
                info.organization = value
            elif oid == "serial_number":
                info.serial_number = value
            elif oid == "email_address":
                info.email = value

    return info


# ============================================================================
# CAdES verification
# ============================================================================

def names_match(name1: x509.Name, name2: x509.Name) -> bool:
    """Compare two X.509 Names by key attributes."""
    def get_attr(name, oid):
        for attr in name:
            if attr.oid == oid:
                return attr.value
        return None

    cn1 = get_attr(name1, x509.oid.NameOID.COMMON_NAME)
    cn2 = get_attr(name2, x509.oid.NameOID.COMMON_NAME)
    if cn1 != cn2:
        return False

    o1 = get_attr(name1, x509.oid.NameOID.ORGANIZATION_NAME)
    o2 = get_attr(name2, x509.oid.NameOID.ORGANIZATION_NAME)
    if o1 and o2 and o1 != o2:
        return False

    c1 = get_attr(name1, x509.oid.NameOID.COUNTRY_NAME)
    c2 = get_attr(name2, x509.oid.NameOID.COUNTRY_NAME)
    if c1 and c2 and c1 != c2:
        return False

    return True


def _get_signature_params(cert: x509.Certificate):
    """Get signature verification parameters based on algorithm."""
    sig_algo = cert.signature_algorithm_oid

    if sig_algo in [
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256,
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384,
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512,
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1,
    ]:
        hash_algo = {
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
        }.get(sig_algo, hashes.SHA256())
        return padding.PKCS1v15(), hash_algo

    if sig_algo in [
        x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384,
        x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512,
    ]:
        hash_algo = {
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
        }.get(sig_algo, hashes.SHA256())
        return ec.ECDSA(hash_algo)

    return padding.PKCS1v15(), hashes.SHA256()


def verify_certificate_chain(
    signer_cert: x509.Certificate,
    intermediate_certs: list[x509.Certificate],
    ca_certs: list[x509.Certificate]
) -> tuple[bool, str]:
    """Verify the certificate chain from signer to trusted CA."""
    if not ca_certs:
        return False, "No trusted CA certificates available"

    all_certs = intermediate_certs + ca_certs
    current_cert = signer_cert
    max_depth = 10

    for _ in range(max_depth):
        if names_match(current_cert.issuer, current_cert.subject):
            for ca in ca_certs:
                if names_match(ca.subject, current_cert.subject):
                    try:
                        sig_params = _get_signature_params(current_cert)
                        ca.public_key().verify(
                            current_cert.signature,
                            current_cert.tbs_certificate_bytes,
                            *sig_params if isinstance(sig_params, tuple) else sig_params
                        )
                        return True, ""
                    except Exception:
                        continue
            return False, "Root certificate not trusted"

        issuer_found = False
        for cert in all_certs:
            if names_match(cert.subject, current_cert.issuer):
                try:
                    sig_params = _get_signature_params(current_cert)
                    cert.public_key().verify(
                        current_cert.signature,
                        current_cert.tbs_certificate_bytes,
                        *sig_params if isinstance(sig_params, tuple) else sig_params
                    )
                    current_cert = cert
                    issuer_found = True
                    break
                except Exception:
                    continue

        if not issuer_found:
            return False, f"Could not find issuer for certificate"

    return False, "Certificate chain too long"


def verify_cms_signature(
    signer_info: cms.SignerInfo,
    signer_cert: x509.Certificate,
    encap_content: bytes
) -> tuple[bool, str]:
    """Verify the CMS signature."""
    try:
        signature = signer_info["signature"].native
        digest_algo_oid = signer_info["digest_algorithm"]["algorithm"].native
        hash_algo_map = {
            "sha1": hashes.SHA1(),
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }
        hash_algo = hash_algo_map.get(digest_algo_oid, hashes.SHA256())

        signed_attrs = signer_info["signed_attrs"]
        if signed_attrs:
            from cryptography.hazmat.primitives.hashes import Hash
            hasher = Hash(hash_algo)
            hasher.update(encap_content)
            content_digest = hasher.finalize()

            for attr in signed_attrs:
                if attr["type"].native == "message_digest":
                    attr_digest = attr["values"][0].native
                    if attr_digest != content_digest:
                        return False, "Message digest mismatch"
                    break

            signed_attrs_bytes = signed_attrs.untag().dump()
            data_to_verify = signed_attrs_bytes
        else:
            data_to_verify = encap_content

        public_key = signer_cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data_to_verify, padding.PKCS1v15(), hash_algo)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data_to_verify, ec.ECDSA(hash_algo))
        else:
            return False, f"Unsupported key type: {type(public_key)}"

        return True, ""

    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Signature verification error: {e}"


def verify_cades(
    p7m_path: Path,
    ca_bundle_path: Optional[Path] = None
) -> SignatureResult:
    """Verify a CAdES (.p7m) signature."""
    try:
        p7m_data = p7m_path.read_bytes()
        content_info = cms.ContentInfo.load(p7m_data)

        if content_info["content_type"].native != "signed_data":
            return SignatureResult(
                is_valid=False,
                signature_type="CAdES",
                error="Not a signed CMS message"
            )

        signed_data = content_info["content"]
        encap_content_info = signed_data["encap_content_info"]
        encap_content = encap_content_info["content"].native

        if encap_content is None:
            return SignatureResult(
                is_valid=False,
                signature_type="CAdES",
                error="No encapsulated content found (detached signature not supported)"
            )

        cms_certs = signed_data["certificates"]
        intermediate_certs = []

        if cms_certs:
            for cert_choice in cms_certs:
                if cert_choice.name == "certificate":
                    cert_der = cert_choice.chosen.dump()
                    try:
                        cert = load_der_x509_certificate(cert_der)
                        intermediate_certs.append(cert)
                    except Exception:
                        continue

        ca_certs = load_ca_certificates_cryptography(ca_bundle_path)
        signer_infos = signed_data["signer_infos"]

        if not signer_infos:
            return SignatureResult(
                is_valid=False,
                signature_type="CAdES",
                error="No signer information found"
            )

        signer_info_cms = signer_infos[0]
        sid = signer_info_cms["sid"]
        signer_cert = None

        if sid.name == "issuer_and_serial_number":
            serial = sid.chosen["serial_number"].native
            for cert in intermediate_certs:
                if cert.serial_number == serial:
                    signer_cert = cert
                    break

        if signer_cert is None:
            return SignatureResult(
                is_valid=False,
                signature_type="CAdES",
                error="Could not find signer certificate"
            )

        sig_valid, sig_error = verify_cms_signature(signer_info_cms, signer_cert, encap_content)

        if not sig_valid:
            return SignatureResult(
                is_valid=False,
                signature_type="CAdES",
                error=f"Signature verification failed: {sig_error}",
                signer=extract_signer_info_cryptography(signer_cert),
                content=encap_content
            )

        chain_valid, chain_error = verify_certificate_chain(signer_cert, intermediate_certs, ca_certs)
        signer = extract_signer_info_cryptography(signer_cert)

        # Check if certificate is expired
        cert_expired = False
        try:
            from datetime import datetime, timezone
            not_after = signer_cert.not_valid_after_utc if hasattr(signer_cert, 'not_valid_after_utc') else signer_cert.not_valid_after
            if not_after.tzinfo:
                now = datetime.now(timezone.utc)
            else:
                now = datetime.utcnow()
            if not_after < now:
                cert_expired = True
        except Exception:
            pass

        return SignatureResult(
            is_valid=sig_valid and chain_valid,
            signature_type="CAdES",
            signer=signer,
            certificate_chain_valid=chain_valid,
            certificate_expired=cert_expired,
            error=chain_error if not chain_valid else None,
            content=encap_content
        )

    except Exception as e:
        return SignatureResult(
            is_valid=False,
            signature_type="CAdES",
            error=f"Error processing P7M file: {e}"
        )


def verify_cades_all_levels(
    p7m_path: Path,
    ca_bundle_path: Optional[Path] = None
) -> list[SignatureResult]:
    """
    Verify ALL nested CAdES signatures in a .p7m file.
    Returns a list of SignatureResult, one for each nesting level.
    Level 1 is the outermost (first) signature.
    """
    results = []
    current_data = p7m_path.read_bytes()
    level = 1

    while True:
        try:
            content_info = cms.ContentInfo.load(current_data)

            if content_info["content_type"].native != "signed_data":
                break

            signed_data = content_info["content"]
            encap_content_info = signed_data["encap_content_info"]
            encap_content = encap_content_info["content"].native

            if encap_content is None:
                break

            # Verify this level
            ca_certs = load_ca_certificates_cryptography(ca_bundle_path)
            cms_certs = signed_data["certificates"]
            intermediate_certs = []

            if cms_certs:
                for cert_choice in cms_certs:
                    if cert_choice.name == "certificate":
                        cert_der = cert_choice.chosen.dump()
                        try:
                            cert = load_der_x509_certificate(cert_der)
                            intermediate_certs.append(cert)
                        except Exception:
                            continue

            signer_infos = signed_data["signer_infos"]
            if not signer_infos:
                break

            signer_info_cms = signer_infos[0]
            sid = signer_info_cms["sid"]
            signer_cert = None

            if sid.name == "issuer_and_serial_number":
                serial = sid.chosen["serial_number"].native
                for cert in intermediate_certs:
                    if cert.serial_number == serial:
                        signer_cert = cert
                        break

            if signer_cert is None:
                results.append(SignatureResult(
                    is_valid=False,
                    signature_type="CAdES",
                    error="Could not find signer certificate",
                    level=level,
                    content=encap_content
                ))
                break

            sig_valid, sig_error = verify_cms_signature(signer_info_cms, signer_cert, encap_content)
            chain_valid, chain_error = verify_certificate_chain(signer_cert, intermediate_certs, ca_certs)
            signer = extract_signer_info_cryptography(signer_cert)

            # Check if certificate is expired
            cert_expired = False
            try:
                from datetime import timezone
                not_after = signer_cert.not_valid_after_utc if hasattr(signer_cert, 'not_valid_after_utc') else signer_cert.not_valid_after
                if not_after.tzinfo:
                    now = datetime.now(timezone.utc)
                else:
                    now = datetime.utcnow()
                if not_after < now:
                    cert_expired = True
            except Exception:
                pass

            results.append(SignatureResult(
                is_valid=sig_valid and chain_valid,
                signature_type="CAdES",
                signer=signer,
                certificate_chain_valid=chain_valid,
                certificate_expired=cert_expired,
                error=chain_error if not chain_valid else (sig_error if not sig_valid else None),
                content=encap_content,
                level=level
            ))

            # Check if content is another p7m (nested signature)
            try:
                next_content_info = cms.ContentInfo.load(encap_content)
                if next_content_info["content_type"].native == "signed_data":
                    current_data = encap_content
                    level += 1
                    continue
            except Exception:
                pass

            break

        except Exception as e:
            if level == 1:
                results.append(SignatureResult(
                    is_valid=False,
                    signature_type="CAdES",
                    error=f"Error processing P7M file: {e}",
                    level=level
                ))
            break

    return results


# ============================================================================
# PAdES verification
# ============================================================================

def verify_pades(
    pdf_path: Path,
    ca_bundle_path: Optional[Path] = None
) -> SignatureResult:
    """Verify a PAdES (PDF embedded) signature."""
    try:
        ca_certs = load_ca_certificates_asn1(ca_bundle_path)

        with open(pdf_path, "rb") as f:
            reader = PdfFileReader(f, strict=False)
            sig_fields = reader.embedded_signatures

            if not sig_fields:
                return SignatureResult(
                    is_valid=False,
                    signature_type="PAdES",
                    error="No signatures found in PDF"
                )

            # Process first signature (most PDFs have one)
            sig = sig_fields[0]

            # Extract signer info first
            signer = None
            signer_cert = None
            cert_expired = False
            try:
                signer_cert = sig.signer_cert
                if signer_cert:
                    signer = extract_signer_info_asn1(signer_cert)
                    # Check if certificate is currently expired
                    not_after = signer_cert.not_valid_after
                    if not_after < datetime.now(not_after.tzinfo) if not_after.tzinfo else datetime.utcnow():
                        cert_expired = True
            except Exception:
                pass

            signing_time = None
            if hasattr(sig, 'self_reported_timestamp') and sig.self_reported_timestamp:
                signing_time = sig.self_reported_timestamp
            elif hasattr(sig, 'external_timestamp') and sig.external_timestamp:
                signing_time = sig.external_timestamp

            # First try: validate at signing time (for expired certificates)
            vc_at_signing = None
            vc_current = None
            if ca_certs:
                if signing_time:
                    vc_at_signing = ValidationContext(
                        trust_roots=ca_certs,
                        allow_fetching=False,
                        revocation_mode='soft-fail',
                        moment=signing_time
                    )
                vc_current = ValidationContext(
                    trust_roots=ca_certs,
                    allow_fetching=False,
                    revocation_mode='soft-fail'
                )

            # Try validation at signing time first (handles expired certs)
            is_valid = False
            chain_valid = False
            covers_whole = True
            error_msg = None

            for vc in [vc_at_signing, vc_current]:
                if vc is None:
                    continue
                try:
                    status = validate_pdf_signature(sig, vc, skip_diff=False)
                    is_valid = status.bottom_line
                    covers_whole = status.coverage == "ENTIRE_FILE" or \
                        (hasattr(status, 'modification_level') and
                         status.modification_level is not None and
                         status.modification_level.name in ["NONE", "LTA_UPDATES"])

                    if hasattr(status, 'trust_problem_indic') and status.trust_problem_indic is None:
                        chain_valid = True
                    else:
                        chain_valid = status.bottom_line

                    if is_valid:
                        break
                except Exception as e:
                    error_str = str(e)
                    # Check if it's an expiry error
                    if "expired" in error_str.lower():
                        cert_expired = True
                        continue  # Try next validation context
                    error_msg = error_str
                    continue

            return SignatureResult(
                is_valid=is_valid,
                signature_type="PAdES",
                signer=signer,
                signing_time=signing_time,
                certificate_chain_valid=chain_valid,
                certificate_expired=cert_expired,
                covers_whole_document=covers_whole,
                error=error_msg if not is_valid else None
            )

    except Exception as e:
        return SignatureResult(
            is_valid=False,
            signature_type="PAdES",
            error=f"Error processing PDF file: {e}"
        )


# ============================================================================
# Main entry point
# ============================================================================

def detect_signature_type(file_path: Path) -> str:
    """Detect signature type based on file extension."""
    suffix = file_path.suffix.lower()

    if suffix == ".p7m":
        return "CAdES"
    elif suffix == ".pdf":
        return "PAdES"
    else:
        # Check if it's a nested p7m (e.g., file.pdf.p7m.p7m)
        if ".p7m" in file_path.name.lower():
            return "CAdES"
        return "Unknown"


def verify_signature(
    file_path: Path,
    ca_bundle_path: Optional[Path] = None,
    extract_path: Optional[Path] = None
) -> SignatureResult:
    """
    Verify a digital signature (CAdES or PAdES).
    Automatically detects signature type based on file extension.
    """
    sig_type = detect_signature_type(file_path)

    if sig_type == "CAdES":
        result = verify_cades(file_path, ca_bundle_path)
        if extract_path and result.content:
            extract_path.write_bytes(result.content)
        return result
    elif sig_type == "PAdES":
        return verify_pades(file_path, ca_bundle_path)
    else:
        return SignatureResult(
            is_valid=False,
            signature_type="Unknown",
            error=f"Unknown file type: {file_path.suffix}"
        )


def print_signature_result(result: SignatureResult, show_level: bool = False):
    """Print a single signature result."""
    if show_level:
        print(f"--- Signature Level {result.level} ---")

    print("Status:", "VALID" if result.is_valid else "INVALID")
    print("Expired:", "Yes" if result.certificate_expired else "No")

    if result.error and not result.is_valid:
        print(f"Error: {result.error}")

    print("Certificate Chain:", "Valid" if result.certificate_chain_valid else "Invalid")

    if result.signature_type == "PAdES":
        print("Covers Whole Document:", "Yes" if result.covers_whole_document else "No")

    if result.signing_time:
        print(f"Signing Time: {result.signing_time}")

    if result.signer:
        print()
        print("Signer Information:")
        print(f"  Full Name: {result.signer.full_name}")
        if result.signer.common_name:
            print(f"  Common Name: {result.signer.common_name}")
        if result.signer.given_name:
            print(f"  Given Name: {result.signer.given_name}")
        if result.signer.surname:
            print(f"  Surname: {result.signer.surname}")
        if result.signer.organization:
            print(f"  Organization: {result.signer.organization}")
        if result.signer.serial_number:
            print(f"  Serial Number: {result.signer.serial_number}")
        if result.signer.email:
            print(f"  Email: {result.signer.email}")


def get_extracted_filename(p7m_path: Path) -> Path:
    """Get the output filename by removing all .p7m extensions."""
    name = p7m_path.name
    while name.lower().endswith(".p7m"):
        name = name[:-4]
    return p7m_path.parent / name


def main():
    parser = argparse.ArgumentParser(
        description="Verify digital signatures (CAdES .p7m or PAdES PDF)"
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Path to the signed file (.p7m or .pdf)"
    )

    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Check for CA bundle
    if get_default_ca_bundle() is None:
        print("Warning: ca-italiane.pem not found in script directory", file=sys.stderr)

    sig_type = detect_signature_type(args.file)

    print("=" * 60)
    print(f"{sig_type} Signature Verification")
    print("=" * 60)
    print(f"File: {args.file}")
    print()

    if sig_type == "CAdES":
        # Verify all nested levels
        results = verify_cades_all_levels(args.file)

        if not results:
            print("Status: ERROR - Could not parse signature")
            sys.exit(1)

        if len(results) > 1:
            print(f"Total Signatures: {len(results)} (nested)")
            print()

        all_valid = all(r.is_valid for r in results)
        innermost_content = results[-1].content if results else None

        for result in results:
            print_signature_result(result, show_level=(len(results) > 1))
            print()

        # Auto-extract innermost content
        if innermost_content:
            extract_path = get_extracted_filename(args.file)
            extract_path.write_bytes(innermost_content)
            print(f"Extracted: {extract_path}")

        print("=" * 60)
        sys.exit(0 if all_valid else 1)

    elif sig_type == "PAdES":
        result = verify_pades(args.file)
        print_signature_result(result)
        print()
        print("=" * 60)
        sys.exit(0 if result.is_valid else 1)

    else:
        print(f"Status: ERROR - Unknown file type: {args.file.suffix}")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
