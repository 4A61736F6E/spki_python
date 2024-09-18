# coding: utf-8
"""Network module for name resolution and certrificate collection."""

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


# Constants
# IP Stack test sites
IP_STACK_TEST_SITES = {
    "IPv6": "ipv6.google.com",
    "IPv4": "ipv4.google.com"
}
# Default cipher suite
DEFAULT_CIPHER_SUITE = 'DHE-RSA-AES128-SHA256'



def get_domain_certificates_og(domain:str, addresses:list, port:int):
    """Retrieves certificates for a given domain.

    Args:
        domain (str): Domain or website
        addresses (list): IPv4 or IPv6 addresses
        port (int): TCP port.

    Returns:
        dict: Certificates for each IP|Port|SNI combination.

    """
    all_session_results = set()

    for address in addresses:
        for use_sni in [True, False]:
            alt_cipher_suites = None

            server_cipher_suites, session_details_default = get_certificate(
                domain,
                address,
                port,
                sni=use_sni
            )

            if server_cipher_suites:
                session_details_default_json = json.dumps(session_details_default)
                all_session_results.add(session_details_default_json)

                alt_cipher_suites = get_inverse_cipher_suites(
                    session_details_default['Certificate']['Key Type'],
                    server_cipher_suites
                )

            if alt_cipher_suites:
                server_cipher_suites, session_details_alt = get_certificate(
                    domain,
                    address,
                    port,
                    sni=use_sni,
                    cipher_suite=alt_cipher_suites[0]
                )

                if server_cipher_suites:
                    session_details_alt_json = json.dumps(session_details_alt)
                    all_session_results.add(session_details_alt_json)

    return [json.loads(item) for item in all_session_results]


def get_certificate_og(domain:str, address:str, port:int, cipher_suite=None, sni=False):
    """Obtains a single certificate from a target given parameters provided.

    Note, cipher_suite=None means we are using the default cipher suite by the client.
    It does not mean we are not selecting any ciphersuite.

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

    log_msg =  f"Acquiring Certificate: {domain}:{port} [{address}] "
    log_msg += f"Cipher Suite: {cipher_suite}, SNI:{sni}"
    logger.debug(log_msg)

    session_details = {
            "Domain": domain,
            "Address": address,
            "Port": port,
            "SNI": sni,
            "Protocol": "",
            "Cipher Suite": "",
            "Certificate": {
                "Key Type": "",
                "Key Length": 0,
                "PEM": ""
            },
            "Status": None,
            "Error Message": None
        }

    # server-side session cipher suites
    server_cipher_suites = None
    cert_binary = None

    try:
        # Create an SSL context.
        default_context = ssl.create_default_context()

        # WARNING: We are disabling normal checks on purpose to collect certificates without SNI.
        # You would not use these arguments in any production environment handling production data.
        default_context.check_hostname = False
        default_context.verify_mode = ssl.CERT_NONE
        logger.debug("Certificate validation has been purposefully disabled.")
        # Use cases where certificate validation need to be disabled:
        # - accessing self-signed certificates
        # - accessing default hosting provider certificates (without SNI)

        try:
            if cipher_suite:
                default_context.set_ciphers(cipher_suite)
        except ssl.SSLError:
            log_msg = f"Could not set cipher suite to `{cipher_suite}`.  "
            log_msg += f"Defaulting to `{DEFAULT_CIPHER_SUITE}` instead."
            logger.warning(log_msg)
            cipher_suite = DEFAULT_CIPHER_SUITE
            default_context.set_ciphers(cipher_suite)

        family = get_socket_family(address)
        if not family:
            raise ValueError("Could not determine if 'address' was IPv4 or IPv6.")

        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((address, port))
        except OSError as ex:
            logger.warning("Encountered an OSError. [%s] %s, %s %s:%d",
                           ex.errno, ex, domain, address, port )
            raise

        if sni:
            with default_context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                session_details['Protocol'] = secure_sock.version()
                session_details['Cipher Suite'] = secure_sock.cipher()[0]
                server_cipher_suites = secure_sock.context.get_ciphers()
                cert_binary = secure_sock.getpeercert(binary_form=True)
                session_details['Certificate']['PEM'] = ssl.DER_cert_to_PEM_cert(cert_binary)
                session_details['Status'] = "Success"

        else:
            with default_context.wrap_socket(sock) as secure_sock:
                session_details['Protocol'] = secure_sock.version()
                session_details['Cipher Suite'] = secure_sock.cipher()[0]
                server_cipher_suites = secure_sock.context.get_ciphers()
                cert_binary = secure_sock.getpeercert(binary_form=True)
                session_details['Certificate']['PEM'] = ssl.DER_cert_to_PEM_cert(cert_binary)
                session_details['Status'] = "Success"

    except socket.timeout:
        log_msg = f"Session timeout. {domain}:{port} [{address}] {cipher_suite}"
        logger.warning(log_msg)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = "Session Timeout"
    except ConnectionRefusedError:
        log_msg = f"Connection refused. {domain}:{port} [{address}] {cipher_suite}"
        logger.warning(log_msg)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = "Connection Refused"
    except ConnectionResetError:
        log_msg = f"Connection reset. {domain}:{port} [{address}] {cipher_suite}"
        logger.warning(log_msg)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = "Connection Reset"
    except ssl.SSLError as ex:
        log_msg = f"{ex.strerror}[{ex.errno}]. {domain}:{port} [{address}] {cipher_suite}"
        logger.warning(log_msg)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = f"{ex.strerror}"
    except ValueError as ex:
        log_msg = f"{ex}. {domain}:{port} [{address}] {cipher_suite}"
        logger.warning(log_msg)
        session_details['Status'] = "Failure"
        session_details['Error Message'] = f"{ex}."
    except Exception as ex:
        log_msg = f"Unexpected Error: {ex}"
        session_details['Status'] = "Failure"
        session_details['Error Message'] = f"Unexpected Error: {ex}"
        logger.warning(log_msg)
        return None, session_details

    if cert_binary:
        cert_der =  x509.load_der_x509_certificate(cert_binary, default_backend())
        key_type, key_length = get_key_info(cert_der.public_key())
        session_details['Certificate']['Key Type'] = key_type
        session_details['Certificate']['Key Length'] = key_length

        log_msg =  f"Found a {key_length}-bit {key_type} certificate "
        log_msg += f"at {domain}:{port} [{address}]. "
        log_msg += f"Cipher Suite: {session_details['Cipher Suite']}, SNI: {sni}."
        logger.debug(log_msg)
    else:
        log_msg = f"Encountered one or more errors: {domain}:{port} [{address}]"
        logger.warning(log_msg)

    return server_cipher_suites, session_details



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

    # TODO: break down `get_certificate`into a more modular design.

    session_details = {
        "Domain": domain,
        "Address": address,
        "Port": port,
        "SNI": sni,
        "Protocol": "",
        "Cipher Suite": "",
        "Certificate": {
            "Key Type": "",
            "Key Length": 0,
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

    # Process the certificate if it was retrieved
    if cert_binary:
        cert_der = x509.load_der_x509_certificate(cert_binary, default_backend())
        key_type, key_length = get_key_info(cert_der.public_key())
        session_details['Certificate']['Key Type'] = key_type
        session_details['Certificate']['Key Length'] = key_length
        logger.debug("Found a %d-bit %s certificate at %s:%d [%s]. Cipher Suite: %s, SNI: %s.",
                     key_length, key_type, domain, port,
                     address, session_details['Cipher Suite'], sni)

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


def parse_certificate(certificate:dict):
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
    # TODO: Extend this function to support more hashing functions.
    # TODO: Extend parsing to include subject alternative names.


    if not certificate['PEM']:
        return

    x509_cert = x509.load_pem_x509_certificate(
        bytes(certificate['PEM'], 'utf-8'), default_backend())

    subject = x509_cert.subject.rfc4514_string()
    certificate['Subject'] = subject
    issuer = x509_cert.issuer.rfc4514_string()
    certificate['Issuer'] = issuer

    hex_string = hex(x509_cert.serial_number).replace('0x', '').upper()
    padding_length = (len(hex_string)+1) // 2*2 # calcuate dynamic padding requirement
    padded_serial_number = hex_string.zfill(padding_length)
    serial_number_str = ":".join(padded_serial_number[i:i+2] \
                                 for i in range(0, len(padded_serial_number), 2))
    certificate['Serial Number'] = serial_number_str

    certificate['Not Before'] = f"{x509_cert.not_valid_before_utc}"
    certificate['Not After'] = f"{x509_cert.not_valid_after_utc}"
    certificate['SPKI Digests'] = []
    spki_bytes = x509_cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    certificate['SPKI Digests'] = []
    sha256sum_buffer = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256sum_buffer.update(spki_bytes)
    sha256_digest = sha256sum_buffer.finalize()
    sha256_digest_str = ":".join("{:02x}".upper().format(byte) for byte in sha256_digest)
    certificate['SPKI Digests'].append( {"SHA256": sha256_digest_str} )

    certificate['Fingerprints'] = []
    sha256_fingerprint = x509_cert.fingerprint(hashes.SHA256())
    sha256_fingerprint_str = ":".join("{:02x}".upper().format(byte) for byte in sha256_fingerprint)
    certificate['Fingerprints'].append( {"SHA256": sha256_fingerprint_str} )


def get_key_info(public_key):
    """Determines key type and length.

    Args:
        public_key (x509.load_der_x509_certificate): Public key to parse.

    Returns:
        tuple: Key type (str), Key length (int)

    """

    key_type = "Unknown"
    key_length = None
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_length = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = "ECDSA"
        key_length = public_key.curve.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_type = "DSA"
        key_length = public_key.key_size
    return key_type, key_length
