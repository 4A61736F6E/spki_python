# coding: utf-8
"""Certificates module which runs the spki_python package.
"""


import json
import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec




from spki_python.utilities import logger




def create_dynamic_hash_mapping():
    """Creates a mapping of lowercase hash algorithm names to their corresponding classes.

    Returns:
        dict: A dictionary mapping hash algorithm names to their classes.

    """
    hash_algorithms = {}

    # Iterate over all attributes in the 'hashes' module
    for name in dir(hashes):
        # Get the attribute from the module
        algorithm = getattr(hashes, name)
        # Check if it is a hash class (subclass of HashAlgorithm)
        if isinstance(algorithm, type) and issubclass(algorithm, hashes.HashAlgorithm):
            # Map the lowercased name (e.g., 'SHA256' -> 'sha256') to the class
            hash_algorithms[name.lower()] = algorithm

    return hash_algorithms


def get_byte_digest(byte_data: bytes, digest_algorithm: hashes.HashAlgorithm) -> str:
    """Computes a single thumbprint of the byte data using the digest algorithm.

    Args:
        byte_data (bytes): The byte_data to compute the thumbprint.
        digest_algorithm (str): The digest algorithm to use.

    Returns:
        str: The thumbprint of the byte_data.
    """
    # Create a hash object using the specified digest algorithm
    digest = hashes.Hash(digest_algorithm, backend=default_backend())
    # Update the hash object with the byte_data
    digest.update(byte_data)
    # Compute the digest of the byte_data
    byte_digest = digest.finalize()
    
    return byte_digest


def get_byte_digests(byte_data: bytes, digest_algorithms: list) -> dict:
    """Computes or more thumbprints of the byte data using the specified digest algorithms.

    Args:
        byte_data (bytes): The byte_data to compute the thumbprints.
        digest_algorithms (list): The list of digest algorithms to use.

    Returns:
        dict: A dictionary mapping digest algorithm names to their thumbprints.
    """
    byte_digests = {}
    hash_algorithms = create_dynamic_hash_mapping()
    for algorithm in digest_algorithms:
        # Get the hash algorithm class from the mapping
        hash_algorithm_class = hash_algorithms.get(algorithm.lower())
        if hash_algorithm_class:
            # Compute the digest of the byte_data using the specified algorithm
            byte_digest = get_byte_digest(byte_data, hash_algorithm_class())
            # Store the byte digest in the byte_digests dictionary
            byte_digests[hash_algorithm_class.name] = byte_digest.hex()
        else:
            logger.warning("Unsupported digest algorithm: %s", algorithm)
    return byte_digests


def read_private_key(file_path: str, key_password: str = None):
    """
    Reads a private key from a given file in either PEM or DER format.

    Args:
        file_path (str): The path to the private key file.
        key_password (str): The password to decrypt the private key, if encrypted.

    Returns:
        serialization.PrivateKey: The parsed private key object.

    """
    logger.info("Reading private key from file '%s'...", file_path)
    try:
        with open(file_path, 'rb') as key_file:
            key_data = key_file.read()

            # Regex pattern to match 'BEGIN PRIVATE KEY' with 
            # optional 'EC' or 'RSA' PRIVATE KEY prefix
            regex_pem_header = re.compile(rb'-----BEGIN (EC |RSA )?PRIVATE KEY-----')

            # Check if it's a PEM private key
            if regex_pem_header.search(key_data):
                # Load PEM private key (supports both EC and general private keys)
                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=key_password,  # Assumes the private key is not encrypted
                    backend=default_backend()
                )
                return private_key

            # Check for DER format (DER files are binary and won't have ASCII headers)
            # DER private keys often start with byte 0x30 (ASN.1 SEQUENCE tag)
            elif key_data[:1] == b'\x30':
                try:
                    # Load DER private key
                    private_key = serialization.load_der_private_key(
                        key_data,
                        password=key_password,  # Assumes the DER key is not encrypted
                        backend=default_backend()
                    )
                    return private_key
                except ValueError:
                    logger.error("File '%s' appears to be DER, but could not be parsed.", file_path)
            else:
                # Unexpected file type
                # print in binary format the first few bytes of the file
                print(key_data[:10])
                logger.error("Unexpected or unsupported private key format in file '%s'.", file_path)

    except Exception as ex:
        logger.error("Error reading private key from file %s: %s", file_path, ex)


def parse_private_key(private_key_bytes: bytes, digest_algorithms: list, key_password: str = None):
    """Parses a private key object and calculates the DER and SPKI digests for each digest algorithm.
    
    Args:
        private_key_bytes (bytes): The private key bytes.
        digest_algorithms (list): A list of digest algorithm names.

    Returns:
        dict: A dictionary containing the parsed attributes of the private key.
    
    """
    logger.info("Parsing private key...")
    # Create a mapping of lowercase hash algorithm names to their classes
    hash_algorithms = create_dynamic_hash_mapping()

    # Initialize a dictionary to store parsed attributes
    attributes = {}

    # Convert the private key bytes to a private key object
    private_key_object = private_key_bytes_to_object(private_key_bytes, key_password)

    # Determine the key type
    if isinstance(private_key_object, rsa.RSAPrivateKey):
        attributes['Key Type'] = 'RSA'
    elif isinstance(private_key_object, ec.EllipticCurvePrivateKey):
        attributes['Key Type'] = 'EC'
    else:
        logger.warning("Detected an unknown private key type: %s", type(private_key_object))
        attributes['Key Type'] = 'Unknown'

    # Determine key size or length
    key_size = private_key_object.key_size
    attributes['Key Size'] = key_size

    spki_thumbprints = {} # SPKI thumbprints

    # Calculate the SPKI digest for each digest algorithm
    for algorithm in digest_algorithms:
        # Get the hash algorithm class from the mapping
        hash_algorithm_class = hash_algorithms.get(algorithm.lower())
        if hash_algorithm_class:
            # Compute the digest of the key SubjectPublicKeyInfo (SPKI) field
            spki_digest = get_private_key_spki_digest(private_key_object, hash_algorithm_class())
            spki_thumbprints[hash_algorithm_class.name] = spki_digest.hex()
        else:
            logger.warning("Unsupported digest algorithm: %s", algorithm)

    # Add SPKI thumbprints to the attributes
    attributes["SPKI Thumbprint"] = spki_thumbprints

    return attributes


def private_key_bytes_to_object(private_key_bytes: bytes, key_password: str = None):
    """Converts private key bytes to a private key object.

    Args:
        private_key_bytes (bytes): The private key bytes.
        key_password (str): The password to decrypt the private key, if encrypted.

    Returns:
        serialization.PrivateKey: The private key object.
    """
    logger.info("Converting private key bytes to private key object...")
    try:
        # Convert key_password from str to bytes, if it's provided and not None
        if key_password is not None:
            key_password = key_password.encode('utf-8')  # Ensure the password is in bytes

        # Regex pattern to match 'BEGIN PRIVATE KEY' with optional 'EC' or 'RSA' PRIVATE KEY prefix
        regex_pem_header = re.compile(rb'-----BEGIN (EC |RSA )?PRIVATE KEY-----')

        # Check if it's a PEM private key
        if regex_pem_header.search(private_key_bytes):
            # Load PEM private key (supports both EC and general private keys)
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=key_password,  # Ensure the private key password is in bytes
                backend=default_backend()
            )
            return private_key

        # Check for DER format (DER files are binary and won't have ASCII headers)
        # DER private keys often start with byte 0x30 (ASN.1 SEQUENCE tag)
        elif private_key_bytes[:1] == b'\x30':
            try:
                # Load DER private key
                private_key = serialization.load_der_private_key(
                    private_key_bytes,
                    password=key_password,  # Ensure the private key password is in bytes
                    backend=default_backend()
                )
                return private_key
            except ValueError:
                logger.error("Private key bytes appear to be DER, but could not be parsed.")
        else:
            # Unexpected file type
            print(private_key_bytes[:10])  # Print first few bytes for debugging
            logger.error("Unexpected or unsupported private key format in the byte data.")

    except Exception as ex:
        logger.error("Error converting private key bytes to private key object: %s", ex)
        return None


def get_private_key_spki_digest(private_key_object, digest_algorithm: hashes.HashAlgorithm):
    """Calculates the SPKI digest of a private key's public key using the provided hash algorithm.

    Args:
        private_key_object: The private key object.
        digest_algorithm: The hash algorithm object from the 'hashes' module.

    Returns:
        bytes: The digest of the SPKI (SubjectPublicKeyInfo) in binary format.
    """
    logger.debug ("Computing the SPKI digest of the private key's public key using %s", digest_algorithm.name)
    # Get the public key from the private key
    public_key = private_key_object.public_key()

    # Get the SubjectPublicKeyInfo (SPKI) bytes
    spki_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculate the digest of the SPKI bytes using the provided hash algorithm
    digest = hashes.Hash(digest_algorithm, backend=default_backend())
    digest.update(spki_bytes)
    spki_digest = digest.finalize()

    return spki_digest



def read_signing_request(file_path: str):
    """Reads a certificate signing request from a given file in either PEM or DER format.

    Args:
        file_path (str): The path to the signing request file.

    Returns:
        x509.CertificateSigningRequest: The parsed signing request object.

    """
    logger.info("Reading certificate signing request from file '%s'...", file_path)
    try:
        with open(file_path, 'rb') as csr_file:
            csr_data = csr_file.read()

            # Check if it's PEM format (starts with '-----BEGIN CERTIFICATE REQUEST-----')
            if b'-----BEGIN CERTIFICATE REQUEST-----' in csr_data:
                # Load PEM certificate signing request
                csr = x509.load_pem_x509_csr(csr_data, default_backend())
            
            # Check for DER file characteristics (typically binary, no ASCII markers)
            elif csr_data[:1] == b'\x30':  # DER often starts with byte 0x30 (ASN.1 SEQUENCE tag)
                try:
                    # Load DER certificate signing request
                    csr = x509.load_der_x509_csr(csr_data, default_backend())
                except ValueError:
                    logger.error("File '%s' appears to be DER, but could not be parsed.", file_path)
            
            else:
                # Unexpected file type
                logger.error("Unexpected or unsupported certificate signing request format in file '%s'.", file_path)
                return None

            return csr

    except Exception as ex:
        logger.error("Error reading certificate signing request from file '%s': %s", file_path, ex)


def parse_signing_request(signing_request_bytes: bytes, digest_algorithms: list) -> dict:
    """Parses a signing request object and calculates the SPKI digest for each digest algorithm.

    Args:
        signing_request_bytes (bytes): The signing request bytes.
        digest_algorithms (list): A list of digest algorithm names.

    Returns:
        dict: A dictionary mapping digest algorithm names to their SPKI digests.
    """
    logger.info("Parsing certificate signing request...")
    # Create a mapping of lowercase hash algorithm names to their classes
    hash_algorithms = create_dynamic_hash_mapping()

    # Initialize a dictionary to store parsed attributes
    attributes = {}

    # Convert the signing request bytes to a signing request object
    signing_request_object = signing_request_bytes_to_object(signing_request_bytes)

    # Determine the key type
    public_key = signing_request_object.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        attributes['Key Type'] = 'RSA'
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        attributes['Key Type'] = 'EC'
    else:
        attributes['Key Type'] = 'Unknown'

    # Determine key size or length
    key_size = public_key.key_size
    attributes['Key Size'] = key_size
    
    # Get signing request Subject as a string
    attributes['Subject'] = signing_request_object.subject.rfc4514_string()

    spki_thumbprints = {}  # SPKI thumbprints

    # Calculate the SPKI digest for each digest algorithm
    for algorithm in digest_algorithms:
        # Get the hash algorithm class from the mapping
        hash_algorithm_class = hash_algorithms.get(algorithm.lower())
        if hash_algorithm_class:
            # Compute the digest of the key SubjectPublicKeyInfo (SPKI) field
            spki_digest = get_signing_request_spki_digest(signing_request_object, hash_algorithm_class())
            spki_thumbprints[hash_algorithm_class.name] = spki_digest.hex()
        else:
            logger.warning("Unsupported digest algorithm: %s", algorithm)

    # Add SPKI thumbprints to the attributes
    attributes["SPKI Thumbprint"] = spki_thumbprints

    return attributes


def signing_request_bytes_to_object(signing_request_bytes: bytes):
    """Converts signing request bytes to a signing request object.

    Args:
        signing_request_bytes (bytes): The signing request bytes.

    Returns:
        x509.CertificateSigningRequest: The signing request object.
    """
    logger.info("Converting signing request bytes to signing request object...")
    try:
        # Regex pattern to match 'BEGIN CERTIFICATE REQUEST'
        regex_pem_header = re.compile(rb'-----BEGIN CERTIFICATE REQUEST-----')

        # Check if it's a PEM certificate signing request
        if regex_pem_header.search(signing_request_bytes):
            # Load PEM certificate signing request
            csr = x509.load_pem_x509_csr(signing_request_bytes, default_backend())
            return csr

        # Check for DER format (DER files are binary and won't have ASCII headers)
        # DER certificate signing requests often start with byte 0x30 (ASN.1 SEQUENCE tag)
        elif signing_request_bytes[:1] == b'\x30':
            try:
                # Load DER certificate signing request
                csr = x509.load_der_x509_csr(signing_request_bytes, default_backend())
                return csr
            except ValueError:
                logger.error("Signing request bytes appear to be DER, but could not be parsed.")
        else:
            # Unexpected file type
            print(signing_request_bytes[:10])  # Print first few bytes for debugging
            logger.error("Unexpected or unsupported signing request format in the byte data.")

    except Exception as ex:
        logger.error("Error converting signing request bytes to signing request object: %s", ex)
        return None


def get_signing_request_spki_digest(signing_request_object, digest_algorithm: hashes.HashAlgorithm):
    """Calculates the SPKI digest of a signing request's public key using the provided hash algorithm.

    Args:
        signing_request_object: The signing request object.
        digest_algorithm: The hash algorithm object from the 'hashes' module.

    Returns:
        bytes: The digest of the SPKI (SubjectPublicKeyInfo) in binary format.
    """
    logger.debug ("Computing the SPKI digest of the signing request's public key using %s", digest_algorithm.name)
    # Get the public key from the signing request
    public_key = signing_request_object.public_key()

    # Get the SubjectPublicKeyInfo (SPKI) bytes
    spki_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculate the digest of the SPKI bytes using the provided hash algorithm
    digest = hashes.Hash(digest_algorithm, backend=default_backend())
    digest.update(spki_bytes)
    spki_digest = digest.finalize()

    return spki_digest



def read_signed_public_key(file_path: str):
    """Reads a certificate from a given file in either PEM or DER format.

    Args:
        file_path (str): The path to the certificate file.

    Returns:
        x509.Certificate: The parsed certificate object.

    """
    logger.info("Reading certificate from file '%s'...", file_path)
    try:
        with open(file_path, 'rb') as cert_file:
            cert_data = cert_file.read()

            # Check if it's PEM format (starts with '-----BEGIN CERTIFICATE-----')
            if b'-----BEGIN CERTIFICATE-----' in cert_data:
                # Load PEM certificate
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check for DER file characteristics (typically binary, no ASCII markers)
            elif cert_data[:1] == b'\x30':  # DER often starts with byte 0x30 (ASN.1 SEQUENCE tag)
                try:
                    # Load DER certificate
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                except ValueError:
                    logger.error("File '%s' appears to be DER, but could not be parsed.", file_path)
            
            else:
                # Unexpected file type
                logger.error("Unexpected or unsupported certificate format in file '%s'.", file_path)
                return None

            return cert

    except Exception as ex:
        logger.error("Error reading certificate from file '%s': %s", file_path, ex)
    


def parse_signed_public_key(signed_public_key_bytes, digest_algorithms: list):
    """Parses a certificate object and calculates the SPKI digest for each digest algorithm.

    Args:
        certificate_object (x509.Certificate): The certificate object.
        digest_algorithms (list): A list of digest algorithm names.

    Returns:
        dict: A dictionary mapping digest algorithm names to their SPKI digests.
    """
    logger.info("Parsing signed public key...")
    # Create a mapping of lowercase hash algorithm names to their classes
    hash_algorithms = create_dynamic_hash_mapping()

    # Initialize a dictionary to store parsed attributes
    attributes = {}

    certificate_object = signed_public_key_bytes_to_object(signed_public_key_bytes)

    # Determine the key type
    public_key = certificate_object.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        attributes['Key Type'] = 'RSA'
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        attributes['Key Type'] = 'EC'
    else:
        attributes['Key Type'] = 'Unknown'

    # Determine key size or length
    key_size = public_key.key_size
    attributes['Key Size'] = key_size

    # Get publie key subject as string
    attributes['Subject'] = certificate_object.subject.rfc4514_string()
    # Get issuer as string
    attributes['Issuer'] = certificate_object.issuer.rfc4514_string()
    # get serial number as minimal hex string
    attributes['Serial Number'] = hex(certificate_object.serial_number)[2:]
    # attributes['Serial Number'] = certificate_object.serial_number.to_bytes(32, 'big').hex()

    # get validity period
    attributes['Validity Period'] = {
        'Not Before': certificate_object.not_valid_before_utc.isoformat(),
        'Not After': certificate_object.not_valid_after_utc.isoformat()
    }

    spki_thumbprints = {}  # SPKI thumbprints

    # Calculate the SPKI digest for each digest algorithm
    for algorithm in digest_algorithms:
        # Get the hash algorithm class from the mapping
        hash_algorithm_class = hash_algorithms.get(algorithm.lower())
        if hash_algorithm_class:
            # Compute the digest of the key SubjectPublicKeyInfo (SPKI) field
            spki_digest = get_signed_public_key_spki_digest(certificate_object, hash_algorithm_class())
            spki_thumbprints[hash_algorithm_class.name] = spki_digest.hex()
        else:
            logger.warning("Unsupported digest algorithm: %s", algorithm)

    # Add SPKI thumbprints to the attributes
    attributes["SPKI Thumbprint"] = spki_thumbprints

    return attributes


def signed_public_key_bytes_to_object(signed_public_key_bytes: bytes):
    """Converts signed public key bytes to a certificate object.

    Args:
        signed_public_key_bytes (bytes): The signed public key bytes.

    Returns:
        x509.Certificate: The certificate object.
    """
    logger.info("Converting signed public key bytes to certificate object...")
    try:
        # Regex pattern to match 'BEGIN CERTIFICATE'
        regex_pem_header = re.compile(rb'-----BEGIN CERTIFICATE-----')

        # Check if it's a PEM certificate
        if regex_pem_header.search(signed_public_key_bytes):
            # Load PEM certificate
            cert = x509.load_pem_x509_certificate(signed_public_key_bytes, default_backend())
            return cert

        # Check for DER format (DER files are binary and won't have ASCII headers)
        # DER certificates often start with byte 0x30 (ASN.1 SEQUENCE tag)
        elif signed_public_key_bytes[:1] == b'\x30':
            try:
                # Load DER certificate
                cert = x509.load_der_x509_certificate(signed_public_key_bytes, default_backend())
                return cert
            except ValueError:
                  # Print first few bytes for debugging
                logger.error("Signed public key bytes appear to be DER, but could not be parsed.\nFirst bytes: %s", signed_public_key_bytes[:20])
        else:
            # Unexpected file type
            logger.error("Unexpected or unsupported signed public key format in the byte data.\nFirst bytes: %s", signed_public_key_bytes[:20])

    except Exception as ex:
        logger.error("Error converting signed public key bytes to certificate object: %s", ex)
        return None


def get_signed_public_key_spki_digest(certificate_object, digest_algorithm: hashes.HashAlgorithm):
    """Calculates the SPKI digest of a certificate's public key using the provided hash algorithm.

    Args:
        certificate_object: The certificate object.
        digest_algorithm: The hash algorithm object from the 'hashes' module.

    Returns:
        bytes: The digest of the SPKI (SubjectPublicKeyInfo) in binary format.
    """
    logger.debug ("Computing the SPKI digest of the certificate's public key using %s", digest_algorithm.name)
    # Get the public key from the certificate
    public_key = certificate_object.public_key()

    # Get the SubjectPublicKeyInfo (SPKI) bytes
    spki_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculate the digest of the SPKI bytes using the provided hash algorithm
    digest = hashes.Hash(digest_algorithm, backend=default_backend())
    digest.update(spki_bytes)
    spki_digest = digest.finalize()

    return spki_digest


