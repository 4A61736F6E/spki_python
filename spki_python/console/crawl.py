# coding: utf-8
"""Console module which runs the spki_python package.
"""


import argparse
import json
import logging
from pathlib import Path
import os
import sys


from spki_python.dns import resolve_domain_addresses

from spki_python.network import is_ipv4_available
from spki_python.network import is_ipv6_available
from spki_python.network import get_domain_certificates
from spki_python.network import parse_certificate


from spki_python.utilities import logger
from spki_python.utilities import save_certificate
from spki_python.utilities import save_text_file
from spki_python.utilities import read_websites_from_file



def collect_certificates(websites:dict):
    """_summary_

    Args:
        websites (dict): _description_

    Returns:
        _type_: _description_
    """
    session_details = []

    ip_stack_available = {
        "A": is_ipv4_available(),
        "AAAA": is_ipv6_available()
    }

    for website in websites:
        logger.info("Accessing online website: %s:%d", website['Domain'], website['Port'])
        for dns_record in website["DNS Records"]:
            record_type = list(dns_record.keys())[0]
            if ip_stack_available[record_type] and dns_record[record_type]:
                results = get_domain_certificates(
                    website['Domain'],
                    dns_record[record_type],
                    website['Port']
                    )
                session_details += results

    return session_details


def export_certificate(folder:str, session_record:dict):
    """_summary_

    Args:
        certificate (dict): _description_
    """

    if not session_record["Certificate"]["PEM"]:
        return False

    for suffix in [".pem", ".der"]:
        sni_use = "sni_true" if session_record['SNI'] else "sni_false"
        filename = f"{session_record['Domain']}_{session_record['Address']}_"
        filename += f"{session_record['Port']}_{sni_use}{suffix}"
        filepath = Path(f"{folder}/{filename}")
        save_certificate(filepath, session_record['Certificate']['PEM'])

    return True



def main():
    """_summary_
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Verbose output (-v is info, -vv is debug)"
    )

    parser.add_argument(
        '-n', '--nameserver',
        action='store',
        dest='nameserver',
        help='IP address of the name server to use for DNS resolution.'
    )

    required_arguments = parser.add_argument_group('required arguments')

    required_arguments.add_argument(
        '-iL',
        required=True,
        action='store',
        dest='input_file',
        help='Input file containing list of sites to assess.'
    )

    required_arguments.add_argument(
        '-d', '--dump',
        required=True,
        action='store',
        dest='dump_folder',
        help='Base folder to dump all artifacts to.'
    )

    args = parser.parse_args()

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
        logger.debug("Arguments: %s", vars(args))

    if not args.input_file and not args.input_folder:
        logger.error("Nothing to do.  Must specify at least one input.")
        return

    if args.nameserver:
        nameserver = args.nameserver
    else:
        nameserver = None

    # Create folders if none exist.
    os.makedirs(Path(args.dump_folder), exist_ok=True)
    os.makedirs(Path(f"{args.dump_folder}/certs"), exist_ok=True)

    # Resolve website/domain IPv4 and IPv6 addresses.
    website_filename = Path(args.input_file)
    websites = read_websites_from_file(website_filename)
    resolve_domain_addresses(websites, nameserver=nameserver)
    website_export_filename = Path(f"{args.dump_folder}/websites.json")
    save_text_file(website_export_filename, websites)

    certificates = collect_certificates(websites)
    if certificates:
        for certificate in certificates:
            parse_certificate(certificate['Certificate'])
            export_certificate(Path(f"{args.dump_folder}/certs"), certificate)
        all_certificates_filename = Path(f"{args.dump_folder}/certificates.json")
        save_text_file(all_certificates_filename, certificates)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted!")
