# This is a sample Python script.

import pefile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
from cryptography.x509.ocsp import OCSPRequestBuilder
import asn1crypto.cms
import asn1crypto.tsp
import struct
from asn1crypto import cms
from pyasn1.codec.der.decoder import decode
from pyasn1_modules.rfc2315 import ContentInfo
import win32crypt
import os
import subprocess
import json
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from datetime import datetime
from dateutil import parser


def extract_certificate_info(pe, address_security, size_security_section):
    """Extracts the certificate information from a PE file's security directory."""
    with open(pe, 'rb') as fh:
        fh.seek(address_security)
        signature_data = fh.read(size_security_section)

    # Skip the first 8 bytes (header), then load the signature
    signature = signature_data[8:]
    cms_content_info = x509.load_der_x509_certificate(signature, backend=default_backend())

    # Print the certificate details
    print("Certificate Details:")
    print(f"  Issued To: {cms_content_info.subject}")
    print(f"  Issued By: {cms_content_info.issuer}")
    print(f"  Valid From: {cms_content_info.not_valid_before}")
    print(f"  Valid To: {cms_content_info.not_valid_after}")
    print(f"  Serial Number: {cms_content_info.serial_number}")




def check_certificate(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Check the security directory
        address_security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
        size_security_section = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size

        if address_security == 0:
            # No embedded signature, check for catalog signature
            #print("No embedded signature found. Checking catalog signature...")
            signature_info = check_signature_with_powershell(file_path)
            if signature_info:
                print("Catalog signature found:")
                print(json.dumps(signature_info, indent=2))
            else:
                print("No catalog signature found.")
        else:
            # Extract embedded signature
            print("Embedded signature found.")
            extract_certificate_info(file_path, address_security, size_security_section)
    except Exception as e:
        print("Error:", e)




def check_certificate_revocation(file_path):
    try:
        # Open the file in binary mode
        with open(file_path, 'rb') as f:
            data = f.read()

        # Parse the PE header to find the security directory
        pe_offset = struct.unpack_from('<L', data, 0x3C)[0]
        security_directory_rva, security_directory_size = struct.unpack_from('<LL', data, pe_offset + 0x94)

        if security_directory_rva == 0:
            print("No security directory found in the PE file.")
            return

        print(f"Security directory found at offset: {security_directory_rva}, size: {security_directory_size}")

        # Read the signature
        signature_data = data[security_directory_rva:security_directory_rva + security_directory_size]

        # Extract the certificate
        cert = extract_certificate_from_signature(signature_data)
        if cert:
            print("Certificate extracted successfully.")
            check_crl(cert)
        else:
            print("Failed to extract the certificate.")
    except Exception as e:
        print("Error while parsing PE file:", e)


def extract_certificate_from_signature(signature_data):
    try:
        # Decode the signature using pyasn1
        content_info, _ = decode(signature_data, asn1Spec=ContentInfo())

        # Extract the certificates from the ContentInfo
        signed_data = content_info['content']
        certificates = signed_data['certificates']
        for cert in certificates:
            cert_data = bytes(cert['certificate'].asOctets())
            return x509.load_der_x509_certificate(cert_data, default_backend())
    except Exception as e:
        print("Error extracting certificate:", e)
        return None


def check_crl(cert):
    try:
        crl_distribution_points = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value

        for dp in crl_distribution_points:
            crl_url = dp.full_name[0].value
            print(f"Checking CRL at: {crl_url}")
            response = requests.get(crl_url)
            if response.status_code == 200:
                crl = x509.load_der_x509_crl(response.content, default_backend())
                if cert.serial_number in [rev.serial_number for rev in crl]:
                    print("Certificate is revoked!")
                else:
                    print("Certificate is not revoked.")
            else:
                print(f"Failed to fetch CRL from {crl_url}")
    except Exception as e:
        print("Error checking CRL:", e)



def check_certificate_with_win32(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Extract the signature
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            security_entry = pe.DIRECTORY_ENTRY_SECURITY[0]
            signature = pe.get_data(security_entry.struct.VirtualAddress, security_entry.struct.Size)

            # Use win32crypt to parse the signature
            cert_store = win32crypt.CertOpenStore(
                win32crypt.CERT_STORE_PROV_PKCS7,
                0,
                None,
                win32crypt.CERT_STORE_OPEN_EXISTING_FLAG | win32crypt.CERT_STORE_READONLY_FLAG,
                signature
            )

            cert_context = win32crypt.CertFindCertificateInStore(
                cert_store,
                win32crypt.X509_ASN_ENCODING,
                0,
                win32crypt.CERT_FIND_ANY,
                None
            )

            while cert_context:
                cert = win32crypt.CertGetCertificateContextProperty(cert_context, win32crypt.CERT_KEY_PROV_INFO_PROP_ID)
                print("Certificate found:", cert)
                cert_context = win32crypt.CertFindCertificateInStore(
                    cert_store,
                    win32crypt.X509_ASN_ENCODING,
                    0,
                    win32crypt.CERT_FIND_ANY,
                    cert_context
                )
        else:
            print("No security directory found.")
    except Exception as e:
        print("Error:", e)




def check_ocsp(cert, issuer_cert):
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, cert.signature_hash_algorithm)
    ocsp_request = builder.build()

    # Send the OCSP request to the responder URL
    ocsp_url = cert.extensions.get_extension_for_class(
        x509.AuthorityInformationAccess
    ).value[0].access_location.value

    response = requests.post(ocsp_url, data=ocsp_request.public_bytes())
    if b'REVOKED' in response.content:
        print("Certificate is revoked.")
    else:
        print("Certificate is valid.")


def load_certificate(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    return x509.load_der_x509_certificate(cert_data, default_backend())



def verify_chain(cert, trusted_cert_store):
    try:
        trusted_cert_store.verify_certificate(cert)
        print("Certificate chain is valid.")
    except Exception as e:
        print("Chain verification failed:", e)


def extract_cert(file_path):
    pe = pefile.PE(file_path)
    for entry in pe.DIRECTORY_ENTRY_SECURITY:
        print("Certificate found:", entry.struct)


def extract_certificate(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Check the security directory
        address_security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
        size_security_section = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size

        if address_security == 0:
            signature_info = check_signature_with_powershell(file_path)
            if signature_info:
                print("Catalog signature found:")
                print(json.dumps(signature_info, indent=2))
            else:
                print("No catalog signature found.")

        # Read the security directory
        with open(file_path, 'rb') as f:
            f.seek(address_security)
            signature_data = f.read(size_security_section)

        # Skip the first 8 bytes (header)
        signature_data = signature_data[8:]

        # Parse the signature using asn1crypto
        content_info = cms.ContentInfo.load(signature_data)
        signed_data = content_info['content']

        if 'certificates' in signed_data:
            certificates = signed_data['certificates']
            print(f"Found {len(certificates)} certificate(s).")

            for cert in certificates:
                if cert.name == 'certificate':
                    x509_cert = x509.load_der_x509_certificate(cert.chosen.dump(), default_backend())
                    print(f"Certificate Subject: {x509_cert.subject}")
                    print(f"Certificate Issuer: {x509_cert.issuer}")
                    print(f"Valid From: {x509_cert.not_valid_before_utc}")
                    print(f"Valid To: {x509_cert.not_valid_after_utc}")

                    # Check revocation status
                    check_crl(x509_cert)
                    check_ocsp(x509_cert)

        else:
            print("No certificates found in the signature.")

    except Exception as e:
        print(f"Error: {e}")




def check_crl(cert):
    """Checks the certificate's revocation status using CRL (Certificate Revocation List)."""
    try:
        crl_distribution_points = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value

        for dp in crl_distribution_points:
            crl_url = dp.full_name[0].value
            print(f"Checking CRL at: {crl_url}")

            # Fetch the CRL
            response = requests.get(crl_url)
            if response.status_code == 200:
                crl = x509.load_der_x509_crl(response.content, default_backend())
                if cert.serial_number in [rev.serial_number for rev in crl]:
                    print("❌ Certificate is revoked (CRL)!")
                else:
                    print("✅ Certificate is not revoked (CRL).")
            else:
                print(f"Failed to fetch CRL from {crl_url}")
    except Exception as e:
        print(f"Error checking CRL: {e}")



def check_ocsp(cert):
    try:
        # Find OCSP URL from the certificate's Authority Information Access extension
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp_url = None

        for access_description in aia:
            if access_description.access_method.dotted_string == '1.3.6.1.5.5.7.48.1':  # OCSP
                ocsp_url = access_description.access_location.value
                break

        if not ocsp_url:
            print("❌ No OCSP URL found.")
            return

        print(f"Checking OCSP at: {ocsp_url}")

        # Build the OCSP request
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, cert, cert.signature_hash_algorithm)
        ocsp_request = builder.build()

        # Send the OCSP request
        response = requests.post(
            ocsp_url,
            data=ocsp_request.public_bytes(Encoding.DER),  # Corrected public_bytes() usage
            headers={'Content-Type': 'application/ocsp-request'}
        )

        if response.status_code == 200:
            ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)
            if ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL:
                if ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED:
                    print("❌ Certificate is revoked (OCSP)!")
                else:
                    print("✅ Certificate is not revoked (OCSP).")
            else:
                print(f"OCSP response status: {ocsp_response.response_status}")
        else:
            print(f"❌ Failed to fetch OCSP response from {ocsp_url} (HTTP {response.status_code}).")
    except Exception as e:
        print(f"Error checking OCSP: {e}")




def check_signature_with_powershell(file_path):
    ps_script = f"""
    $ErrorActionPreference = 'Stop';
    try {{
        $sig = Get-AuthenticodeSignature -LiteralPath '{file_path}';
        if ($sig -ne $null) {{
            $certs = @();
            $index = 1;

            if ($sig.SignerCertificate -ne $null) {{
                $cert = $sig.SignerCertificate;
            }} elseif ($sig.CatalogCertificate -ne $null) {{
                $cert = $sig.CatalogCertificate;
            }} else {{
                $cert = $null;
            }}

            if ($cert -ne $null) {{
                $certInfo = [PSCustomObject]@{{
                    Index = $index;
                    Subject = $cert.Subject;
                    Issuer = $cert.Issuer;
                    NotBefore = $cert.NotBefore.ToUniversalTime().ToString('o');
                    NotAfter = $cert.NotAfter.ToUniversalTime().ToString('o');
                    Thumbprint = $cert.Thumbprint;
                    SerialNumber = $cert.SerialNumber;
                    Version = $cert.Version;
                    SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
                    SignatureHashAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
                }};
                $certs += $certInfo;
                $index += 1;
            }}

            $output = [PSCustomObject]@{{
                Status = $sig.Status;
                StatusMessage = $sig.StatusMessage;
                Path = $sig.Path;
                SignatureType = $sig.SignatureType;
                Certificates = $certs;
            }};
            $output | ConvertTo-Json -Compress;
        }} else {{
            '{{}}';  # Output an empty JSON object
        }}
    }} catch {{
        Write-Error $_.Exception.Message;
        exit 1;
    }}
    """

    # Run the PowerShell script
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_script],
        capture_output=True,
        text=True,
        encoding='utf-8'
    )

    if result.returncode == 0 and result.stdout.strip():
        try:
            signature_info = json.loads(result.stdout.strip())
            if signature_info:
                res = {}
                # Extract signature status
                res['SignatureStatus'] = signature_info.get('Status')
                res['SignatureStatusMessage'] = signature_info.get('StatusMessage')
                res['SignatureType'] = signature_info.get('SignatureType')

                certificates = signature_info.get('Certificates', [])
                for cert_info in certificates:
                    index = cert_info.get('Index', 0)
                    res[f'CertificateSubject{index}'] = cert_info.get('Subject', -1)
                    res[f'CertificateIssuer{index}'] = cert_info.get('Issuer', -1)

                    not_before_str = cert_info.get('NotBefore')
                    not_after_str = cert_info.get('NotAfter')

                    if not_before_str:
                        not_before = parser.parse(not_before_str).replace(tzinfo=None)
                        res[f'CertificateValidityStart{index}'] = not_before
                    else:
                        res[f'CertificateValidityStart{index}'] = -1

                    if not_after_str:
                        not_after = parser.parse(not_after_str).replace(tzinfo=None)
                        res[f'CertificateValidityEnd{index}'] = not_after
                    else:
                        res[f'CertificateValidityEnd{index}'] = -1

                    res[f'CertificateSerialNumber{index}'] = cert_info.get('SerialNumber', -1)
                    res[f'CertificateVersion{index}'] = cert_info.get('Version', -1)

                    # Perform OCSP check for revocation status
                    is_revoked = check_ocsp_revocation(cert_info)
                    res[f'CertificateIsRevoked{index}'] = int(is_revoked)

                # Determine if the leaf certificate is currently valid
                if certificates:
                    leaf_cert = certificates[0]
                    not_before_str = leaf_cert.get('NotBefore')
                    not_after_str = leaf_cert.get('NotAfter')
                    if not_before_str and not_after_str:
                        not_before = parser.parse(not_before_str).replace(tzinfo=None)
                        not_after = parser.parse(not_after_str).replace(tzinfo=None)
                        current_time = datetime.now()
                        res['CertificateIsValid'] = int(not_before <= current_time <= not_after)
                    else:
                        res['CertificateIsValid'] = -1
                else:
                    res['CertificateIsValid'] = -1

                return res
            else:
                # No signature information available
                return None
        except json.JSONDecodeError as e:
            print(f"Failed to parse PowerShell output: {e}")
            return None
    else:
        print(f"Failed to retrieve signature information for '{file_path}'.")
        return None


def check_ocsp_revocation(cert_info):
    """Checks OCSP revocation status for a certificate."""
    try:
        cert = x509.load_pem_x509_certificate(cert_info.get('Thumbprint').encode(), backend=default_backend())
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value

        ocsp_url = None
        for access_description in aia:
            if access_description.access_method.dotted_string == '1.3.6.1.5.5.7.48.1':
                ocsp_url = access_description.access_location.value
                break

        if not ocsp_url:
            print("❌ No OCSP URL found.")
            return False

        print(f"Checking OCSP at: {ocsp_url}")
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, cert, cert.signature_hash_algorithm)
        ocsp_request = builder.build()

        response = requests.post(
            ocsp_url,
            data=ocsp_request.public_bytes(Encoding.DER),
            headers={'Content-Type': 'application/ocsp-request'}
        )

        if response.status_code == 200:
            ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)
            if ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL:
                if ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED:
                    print("❌ Certificate is revoked (OCSP)!")
                    return True
                else:
                    print("✅ Certificate is not revoked (OCSP).")
                    return False
            else:
                print(f"OCSP response status: {ocsp_response.response_status}")
        else:
            print(f"❌ Failed to fetch OCSP response from {ocsp_url} (HTTP {response.status_code}).")
    except Exception as e:
        print(f"Error checking OCSP: {e}")
    return False



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    extract_certificate(r"C:\Windows\System32\WalletProxy.dll")  # catalog signature
    #extract_certificate(r"E:\malware_datalake_abuse.ch_urlhaus\mdnsNSP.dll")  #revoked
    #check_certificate_with_win32(r"E:\malware_datalake_abuse.ch_urlhaus\mdnsNSP.dll")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
