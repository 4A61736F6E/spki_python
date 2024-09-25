# coding: utf-8
"""Network module for name resolution and certificate collection."""

import concurrent.futures
from ipaddress import ip_address
import json
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PublicFormat

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

from spki_python.utilities import logger
from spki_python.certificates import get_byte_digests
from spki_python.certificates import parse_signed_public_key


# Constants
# IP Stack test sites
IP_STACK_TEST_SITES = {
    "IPv6": "ipv6.google.com",
    "IPv4": "ipv4.google.com"
}
# Default cipher suite
DEFAULT_CIPHER_SUITE = 'DHE-RSA-AES128-SHA256'




def get_domain_certificates(domain: str, addresses: list, port: int):
    """Retrieves certificates for a given domain.
    
    Args:
        domain (str): Domain or website
        addresses (list): IPv4 or IPv6 addresses
        port (int): TCP port.

    Returns:
        dict: Certificates for each IP|Port|SNI combination.   

    """
    all_session_results = set()

    # Function to process each (address, sni) combination
    def process_certificate(address, use_sni):
        alt_cipher_suites = None

        server_cipher_suites, session_details_default = get_certificate(
            domain, address, port, sni=use_sni
        )

        if server_cipher_suites:
            session_details_default_json = json.dumps(session_details_default)
            all_session_results.add(session_details_default_json)

            alt_cipher_suites = get_inverse_cipher_suites(
                session_details_default['Certificate']['Key Type'], server_cipher_suites
            )

        # Only attempt alternative cipher suite if available
        if alt_cipher_suites:
            server_cipher_suites, session_details_alt = get_certificate(
                domain, address, port, sni=use_sni, cipher_suite=alt_cipher_suites[0]
            )

            if server_cipher_suites:
                session_details_alt_json = json.dumps(session_details_alt)
                all_session_results.add(session_details_alt_json)

    # Use concurrent futures for parallel execution
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for address in addresses:
            for use_sni in [True, False]:
                futures.append(executor.submit(process_certificate, address, use_sni))

        # Wait for all threads to finish
        concurrent.futures.wait(futures)

    # Convert the set back to a list of dictionaries
    return [json.loads(item) for item in all_session_results]



def get_certificate(domain: str, address: str, port: int, cipher_suite=None, sni=False):
    """Obtains a single certificate from a target using automatic protocol negotiation.
    
    Supports TLS 1.2 and TLS 1.3
    
    Args:
        domain (str): The domain or website.
        address (str): The IPv4 or IPv6 address.
        port (int): The port number.
        cipher_suite (str, optional): Cipher suite to use. Defaults to None.
        sni (bool, optional): Server Name Indication boolean. Defaults to False.

    Returns:
        tuple(list, dict): 
            list: Server-side cipher suites. Empty list upon failure.
            dict: Minimal session details. Empt dict upon failure.    

    """

    # TODO: Refactor `get_certificate` into a more modular design.

    session_details = {
        "Domain": domain,
        "Address": address,
        "Port": port,
        "SNI": sni,
        "Protocol": "",
        "Cipher Suite": "",
        "Certificate": {
            "PEM": ""
        },
        "Status": None,
        "Error Message": None
    }

    server_cipher_suites = None
    cert_binary = None

    try:
        logger.debug("Acquiring Certificate: %s:%d [%s] Cipher Suite: %s, SNI: %s",
                     domain, port, address, cipher_suite, sni)

        # Use the default context with automatic protocol negotiation
        # (including TLS 1.3 and TLS 1.2)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)

        # Disable hostname verification and certificate validation
        # Not a practice to follow for produciton handling of sensitive data.
        # Necessary for collecting inventory of certificates globally.
        context.check_hostname = False
        logger.warning ("Certificate hostname checking purposefully disabled.")
        context.verify_mode = ssl.CERT_NONE
        logger.warning ("Certificate validation purposefully disabled.")

        if cipher_suite:
            context.set_ciphers(cipher_suite)

        family = get_socket_family(address)
        if not family:
            raise ValueError("Could not determine if 'address' was IPv4 or IPv6.")

        with socket.create_connection((address, port), timeout=5) as sock:
            if sni:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    session_details['Protocol'] = secure_sock.version()
                    session_details['Cipher Suite'] = secure_sock.cipher()[0]
                    server_cipher_suites = secure_sock.context.get_ciphers()
                    cert_binary = secure_sock.getpeercert(binary_form=True)
                    session_details['Certificate']['PEM'] = ssl.DER_cert_to_PEM_cert(cert_binary)
                    session_details['Status'] = "Success"
            else:
                with context.wrap_socket(sock) as secure_sock:
                    session_details['Protocol'] = secure_sock.version()
                    session_details['Cipher Suite'] = secure_sock.cipher()[0]
                    server_cipher_suites = secure_sock.context.get_ciphers()
                    cert_binary = secure_sock.getpeercert(binary_form=True)
                    session_details['Certificate']['PEM'] = ssl.DER_cert_to_PEM_cert(cert_binary)
                    session_details['Status'] = "Success"

    except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as ex:
        logger.warning("Connection error: %s. %s:%d [%s]", ex, domain, port, address)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = str(ex)

    except ssl.SSLError as ex:
        logger.warning("SSL error: %s[%d]. %s:%d [%s]",
                       ex.strerror, ex.errno, domain, port, address)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = ex.strerror

    except Exception as ex:
        logger.warning("Unexpected error: %s", ex)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = f"Unexpected Error: {ex}"
        return None, session_details

    return server_cipher_suites, session_details



def get_socket_family(address:str):
    """Determines the socket family based on the IP address.

    Args:
        address (str): IP address.

    Returns:
        int: Socket family (AF_INET or AF_INET6). None if address is invalid.

    """
    addr = ip_address(address)
    family = None
    if addr.version == 6:
        family = socket.AF_INET6
    elif addr.version == 4:
        family = socket.AF_INET
    return family


def is_ipv6_available():
    """Tests whether or not IPv6 is available.

    Returns:
        bool: True if available, False otherwise.

    """
    try:
        # Attempt to create an IPv6 socket
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.connect((IP_STACK_TEST_SITES['IPv6'], 80))
        logger.debug("IPv6 Networking Enabled")
        return True
    except (socket.error, OSError):
        logger.debug("IPv6 Networking Disabled")
        return False


def is_ipv4_available():
    """Tests whether or not IPv4 is available.

    Returns:
        bool: True if available, False otherwise.

    """
    try:
        # Attempt to create an IPv4 socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((IP_STACK_TEST_SITES['IPv4'], 80))
        logger.debug("IPv4 Networking Enabled")
        return True
    except (socket.error, OSError):
        logger.debug("IPv4 Networking Disabled")
        return False


def get_inverse_cipher_suites(auth_type:str, cipher_suites:list) -> list:
    """Provides a list of cipher suites based on the inverse of the provided auth type.

    If RSA based auth provided, ECDSA cipher suites offered.
    If ECDSA based auth provided, RSA cipher suites offered.

    Args:
        auth_type (str): Authentication type to find the inverse of.
        cipher_suites (list): List of negotiated cipher suites (dict) from connection.

    Returns:
        list: List of cipher suite names (str) matching the inverse of auth_type.

    """
    logger.debug("Getting inverse cipher suites for '%s'.", auth_type)
    #print(json.dumps(cipher_suites, indent=2))

    inverse_suite_names = []

    inverse_auth_map = {
        "rsa": "auth-ecdsa",
        "auth-rsa": "auth-ecdsa",
        "ecdsa": "auth-rsa",
        "auth-ecdsa": "auth-rsa"
    }

    try:
        auth_name = inverse_auth_map[auth_type.lower()]
    except KeyError:
        logger.warning("Could not find '%s' in inverse_auth_map.", auth_type.lower())
        return inverse_suite_names
    inverse_suite_names = get_cipher_suites_by_suite_auth(auth_name, cipher_suites)

    logger.debug("Found %d inverse cipher suites: %s",
                 len(inverse_suite_names), inverse_suite_names)
    return inverse_suite_names


def get_cipher_suite_auth_value(suite_name:str, cipher_suites:list) -> str:
    """Provides cipher suite authentication based on suite name.

    Args:
        suite_name (str): Name of the cipher suite to find.
        cipher_suites (list): List of negotiated cipher suites (dict) from connection.

    Returns:
        str: Value of the cipher suite 'auth' field.

    """
    suite_auth = None
    print(f"Suite Name: {suite_name}")
    print(json.dumps(cipher_suites, indent=2))
    for suite in cipher_suites:
        if suite['name'] == suite_name.upper():
            suite_auth = suite['auth']
    return suite_auth


def get_cipher_suites_by_suite_auth(suite_auth:str, cipher_suites:list) -> list:
    """Provides a list of cipher suite names based on suite authentication.

    Args:
        suite_auth (str): Type of cipher suite authentication to find.
        cipher_suites (list): List of negotiated cipher suites (dict) from connection.

    Returns:
        list: List of cipher suite names (str) matching suite_auth.
        
    """
    auth_value = None
    cipher_suite_names = []
    key_map = {
        "rsa": "auth-rsa",
        "ecdsa": "auth-ecdsa",
        "auth-rsa":"auth-rsa",
        "auth-ecdsa":"auth-ecdsa",
        "any":"auth-any",
        "auth-any":"auth-any"
    }
    try:
        auth_value = key_map[suite_auth.lower()]
    except KeyError:
        logger.warning("Could not find key type '%s' within the key map.", suite_auth.lower())
        return cipher_suite_names
    for suite in cipher_suites:
        if suite['auth'] == auth_value:
            cipher_suite_names.append(suite['name'])

    return cipher_suite_names


def parse_certificate(certificate:dict, digest_algorithms: list):
    """Extends the certificate dictionary with select details from within the X.509.

    Example fields include:
    - Subject
    - Issuer
    - Validity Period
    - Serial Number
    - Certificate Thumbprint (or Fingerprint)
    - SubjectPublicKeyInfo Thumbprint (or Fingerprint)

    Args:
        certificate (dict): Certificate dictionary.
    """
    # TODO: Extend `parse_certificate` to include subject alternative names.

    if not certificate['PEM']:
        return

    x509_cert = x509.load_pem_x509_certificate(
        bytes(certificate['PEM'], 'utf-8'), default_backend())

  
    # convert the certificate to DER format
    x509_cert_der = x509_cert.public_bytes(encoding=Encoding.DER)
    
    certificate_digests = get_byte_digests(x509_cert_der, digest_algorithms)
    if certificate_digests:
        certificate['Certificate Thumbprint'] = certificate_digests

    certificate.update(parse_signed_public_key(x509_cert_der, digest_algorithms))



