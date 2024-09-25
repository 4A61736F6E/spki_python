# coding: utf-8
"""Console module which runs the spki_python package.
"""


import argparse
import glob
import json
import logging
import os
import re
import sys

from spki_python.certificates import get_byte_digests
from spki_python.certificates import parse_private_key
from spki_python.certificates import parse_signing_request
from spki_python.certificates import parse_signed_public_key
from spki_python.utilities import read_file_as_bytes




from spki_python.utilities import logger


def main():
    """Main function for the console module.

    Returns:
        int: The exit code.
    """
    
    args = parse_arguments()
    if not args:
        return 1

    results = {
        'Private Keys': [],
        'Signing Requests': [],
        'Signed Public Keys': []
    }

    logger.info("Signed Public Keys: %s", args.signed_public_key)

    # split args.algorithm into a list of digest algorithms
    digest_algorithms = args.digest_algorithm.split(',')

    # Process private key files (with support for wildcards)
    if args.private_key:
        file_patterns = args.private_key if isinstance(args.private_key, list) else [args.private_key]
        for file_pattern in file_patterns:
            for private_key_file in glob.glob(file_pattern):
                results['Private Keys'].append(
                    process_private_key(private_key_file, digest_algorithms, args.password))

    # Process signing request files (with support for wildcards)
    if args.signing_request:
        file_patterns = args.signing_request if isinstance(args.signing_request, list) else [args.signing_request]
        logger.info("File Patterns: %s", file_patterns)
        for file_pattern in file_patterns:
            for signing_request_file in glob.glob(file_pattern):
                results['Signing Requests'].append(
                    process_signing_request(signing_request_file, digest_algorithms))

    # Process signed public key files (with support for wildcards)
    if args.signed_public_key:
        file_patterns = args.signed_public_key if isinstance(args.signed_public_key, list) else [args.signed_public_key]
        for file_pattern in file_patterns:
            for signed_public_key_file in glob.glob(file_pattern):
                results['Signed Public Keys'].append(
                    process_signed_public_key(signed_public_key_file, digest_algorithms))

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as output_file:
                output_file.write(json.dumps(results, indent=4))
        except Exception as ex:
            logger.error("Error writing to output file: %s", ex)
    else:
        print(json.dumps(results, indent=4))

    logger.info("Done.")


def parse_arguments():
    """Parses command-line arguments and returns the parsed arguments.

    Returns:
        argparse.Namespace: The parsed arguments.

    """
    parser = argparse.ArgumentParser(
        description="Python module comparing certificate and SubjectPublicKeyInfo thumbprints"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Verbose output (-v is info, -vv is debug)"
    )

    parser.add_argument(
        '--private-key',
        action='store',
        dest='private_key',
        help='Path to private key file.'
    )

    parser.add_argument(
        '--signing-request',
        action='append',
        dest='signing_request',
        help='Path to signing request file.'
    )

    parser.add_argument(
        '--signed-public-key',
        action='append',
        dest='signed_public_key',
        help='Path to signed public key file.'
    )

    parser.add_argument(
        '--password',
        action='store',
        default=None,
        dest='password',
        help='Password for the private key.'
    )

    parser.add_argument(
        '--digest-algorithm',
        action='store',
        default='sha256',
        dest='digest_algorithm',
        help='Digest algorithm for the thumbprint calculation.'
    )

    parser.add_argument(
        '--output',
        action='store',
        dest='output',
        help='Output JSON file for the results.'
    )

    args = parser.parse_args()

    logger.info("Signing Requests: %s", args.signing_request)

    logging.basicConfig(
            format='%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    # setup logging level based on verbosity
    if args.verbose == 1:
        logger.setLevel(logging.INFO)
        logger.info("Logging level set: INFO")
    elif args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
        logger.debug("Logging level set: DEBUG")
        arguments = vars(args).copy()
        if arguments['password']:
            arguments['password'] = '********'
        logger.debug("Arguments: \n%s", json.dumps(arguments, indent=4))

    # check if at least one of the required arguments is provided
    if not args.private_key and not args.signing_request and not args.signed_public_key:
        logger.error("At least one of --private-key, --signing-request, or --signed-public-key must be provided.")
        return None

    return parser.parse_args()



def process_private_key(file_path, digest_algorithms, password):
    """Processes a private key file.

    Args:
        file_path (str): The path to the private key file.
        digest_algorithms (list): The list of digest algorithms to use.
        password (str): The password for the private key.

    """
    private_key_attributes = {}

    logger.info("Processing private key file: %s", file_path)

    private_key_bytes = read_file_as_bytes(file_path)

    if private_key_bytes:
        private_key_attributes['File'] = {
            'Path': file_path, 
            'Size': len(private_key_bytes)
        }

        private_key_attributes['File Thumbprint'] = get_byte_digests(
            private_key_bytes, digest_algorithms)

        parsed_attributes = parse_private_key(private_key_bytes, digest_algorithms, password)

        private_key_attributes.update({
            'Key Type': parsed_attributes['Key Type'],
            'Key Size': parsed_attributes['Key Size'],
            'SPKI Thumbprint': parsed_attributes['SPKI Thumbprint']
        })

    return private_key_attributes


def process_signing_request(file_path, digest_algorithms):
    """Processes a signing request file.

    Args:
        file_path (str): The path to the signing request file.
        digest_algorithms (list): The list of digest algorithms to use.

    """
    signing_request_attributes = {}

    logger.info("Processing signing request file: %s", file_path)

    signing_request_bytes = read_file_as_bytes(file_path)

    if signing_request_bytes:
        signing_request_attributes['File'] = {
            'Path': file_path, 
            'Size': len(signing_request_bytes)
        }
        signing_request_attributes['File Thumbprint'] = get_byte_digests(
            signing_request_bytes, digest_algorithms)

        parsed_attributes = parse_signing_request(signing_request_bytes, digest_algorithms)

        signing_request_attributes.update({
            'Key Type': parsed_attributes['Key Type'],
            'Key Size': parsed_attributes['Key Size'],
            'Subject': parsed_attributes['Subject'],
            'SPKI Thumbprint': parsed_attributes['SPKI Thumbprint']

        })
    
    return signing_request_attributes


def process_signed_public_key(file_path, digest_algorithms):
    """Processes a signed public key file.
    
    Args:
        file_path (str): The path to the signed public key file.
        digest_algorithms (list): The list of digest algorithms to use.


    """
    signed_public_key_attributes = {}

    logger.info("Processing signed public key file: %s", file_path)

    signed_public_key_bytes = read_file_as_bytes(file_path)

    if signed_public_key_bytes:
        signed_public_key_attributes['File'] = {
            'Path': file_path, 
            'Size': len(signed_public_key_bytes)
        }

        signed_public_key_attributes['File Thumbprint'] = get_byte_digests(
            signed_public_key_bytes, digest_algorithms)
        
        parsed_attributes = parse_signed_public_key(signed_public_key_bytes, digest_algorithms)

        signed_public_key_attributes.update({
            'Key Type': parsed_attributes['Key Type'],
            'Key Size': parsed_attributes['Key Size'],
            'Subject': parsed_attributes['Subject'],
            'Serial Number': parsed_attributes['Serial Number'],
            'Issuer': parsed_attributes['Issuer'],
            'Validity Period': parsed_attributes['Validity Period'],
            'SPKI Thumbprint': parsed_attributes['SPKI Thumbprint']
        })

    return signed_public_key_attributes

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted!")