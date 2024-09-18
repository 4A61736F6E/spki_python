# coding: utf-8

import json
import logging
import os
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization


logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s")



def read_websites_from_file(filename):
    """Reads list of web sites (one per line) from text file.

    Args:
        filename (str): Path and name of file to read.

    Returns:
        list: List of web sites (str).  None on failure.
    """
    results = [] # Consists of a list of web sites ["domain:port",...]
    logger.debug("Reading websites from file, '%s'.", filename)
    try:
        if not os.path.exists(filename):
            log_msg = f"File '{filename}' not found."
            logger.error(log_msg)
            raise FileNotFoundError(log_msg)

        with open(filename, 'r', encoding="UTF-8") as file:
            for line in file:

                line = line.strip()
                if line:
                    # Prepend a default scheme (https://) if the line does not have a scheme
                    # Yes, a lame hack.
                    if not line.startswith(('http://', 'https://')):
                        line = 'https://' + line

                    # Use urlparse to parse the URL
                    url = urlparse(line)
                    domain = url.hostname
                    port = int(url.port) if url.port else int(443)  # Assume port 443 if not specified

                    website = {
                        "Domain": domain,
                        "Port": port,
                    }

                    results.append(website)
    
    except (FileNotFoundError, PermissionError) as ex:
        print(f"Error: {ex}")
        return None

    logger.info("Found %d websites.", len(results))
    return results


def save_certificate(filename: str, certificate: str):
    """ Save a certificate to a file with the appropriate format 
    (PEM or DER) based on the filename's extension.

    Args:
        filename (str): Path and name of file to write to disk.
        certificate (str): Certificate data to save to disk.

    Returns:
        bool: True upon succes. False otherwise.
    """
    file_extension = Path(filename).suffix
    file_format = file_extension.lower()

    if file_format not in ('.pem', '.der'):
        logger.warning("Invalid file extension (%s). Use '.pem' or '.der'.", filename)
        return False

    try:
        if file_format == '.pem':
            # Ensure the certificate is in PEM format
            certificate_bytes = certificate.encode('utf-8')
        else:  # assumes file_format == '.der'
            # Load the certificate in PEM format and convert it to DER
            certificate_bytes = x509.load_pem_x509_certificate(
                certificate.encode('utf-8')).public_bytes(
                serialization.Encoding.DER
            )
        with open(filename, 'wb') as cert_file:
            logger.debug("Saving certificate data: `%s`.", filename)
            cert_file.write(certificate_bytes)

        return True
    except Exception as e:
        logger.warning("Error saving certificate to '%s': %s", filename, e)
        return False


def save_text_file(filename:str, data):
    """_summary_

    Args:
        filename (str): _description_
        data (_type_): _description_
    """
    bytes_written = 0
    filename = Path(filename).expanduser()
    logger.info("Writing data to disk: '%s'.", filename)

    with open (filename, 'w', encoding='utf-8') as fp:
        if isinstance(data, (dict,list)):
            json.dump(data, fp)
            # this is a guess between 'json.dump' vs 'json.dumps'
            bytes_written = len(json.dumps(data)) 
        elif isinstance(data, str):
            bytes_written = fp.write(data)
    logger.debug("Wrote %d bytes to file '%s'.", bytes_written, filename)
    return bytes_written
