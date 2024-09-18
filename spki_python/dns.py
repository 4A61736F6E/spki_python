# coding: utf-8

import json
import os
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.resolver
import dns.exception

from spki_python.utilities import logger


def get_name_service_records(domain:str, record_type:str, name_server:str=None, match=False):
    """Retrieves a specific DNS record.

    Args:
        domain (str):                The domain to query.
        record_type (str):           Type of DNS record to query (e.g. SOA, NS, CAA, AAAA, A)
        name_server (str, optional): IP address of name server to query. Defaults to None or 
                                      system default. 
        match (bool, optional): Only return matching records of 'record_type'. Defaults to False.

    Returns:
        list: list of records.  [] if not match, None if failure.
    """
    timeout = 5
    rdatatype_exists = False
    matching_records = []

    rdatatype = dns.rdatatype.from_text(record_type)

    try:
        if name_server:
            log_msg = f"Querying name server {name_server} about {domain} for '{record_type}' records."
            qname = dns.name.from_text(domain)
            query = dns.message.make_query(qname, rdatatype)
            result = dns.query.udp(query, name_server, timeout=timeout)
        else:
            log_msg = f"Querying system default name server about {domain} for '{record_type}' records."
            result = dns.resolver.resolve(domain, record_type).response

        logger.debug(log_msg)

        for record in result.answer:
            if match:
                if record.rdtype == rdatatype.value:
                    matching_records.append(record)
            else:
                if (not rdatatype_exists) and (record.rdtype == rdatatype.value):
                    rdatatype_exists = True

    except dns.exception.Timeout:
        log_msg = f"Timeout occured after {timeout} seconds: querying {name_server} about {domain} for '{record_type}' records."
        logger.warning(log_msg)
        return [] #eww, I know.
    except dns.resolver.NoAnswer:
        log_msg = f"No answer provided for '{record_type}' record type of domain '{domain}'."
        logger.debug(log_msg)
        return [] #I know, eww.
    except Exception as ex:
        logger.warning(f"Exception {type(ex).__name__}: {ex}")
        return [] #more eww.

    logger.info("DNS records found for domain '%s'", domain)
    if match:
        return matching_records
    else:
        return result.answer


def resolve_domain_addresses(domains:list, nameserver=None):
    """Resolves the IP addresses for a list of domains.

    Args:
        domains (list): List of dictionaries containing domain names.
        nameserver (str, optional): IP address of the name server to use for DNS resolution.
                                    Defaults to None.

    Returns:
        bool: True upon success. False otherwise.
    """
    logger.info("Correlating IP addresses for %d websites.", len(domains))

    for domain in domains:
        domain['DNS Records'] = []
        for rtype in ["A", "AAAA"]:
            addresses = {
                rtype: []
            }
            dns_records = get_name_service_records(
                domain['Domain'], rtype, name_server=nameserver, match=True)
            for record_rrset in dns_records:
                while record_rrset:
                    rrset_item = record_rrset.pop()
                    address = rrset_item.address
                    record_type = dns.rdatatype.RdataType.to_text(rrset_item.rdtype)
                    addresses[record_type].append(address)
            domain['DNS Records'].append(addresses)
            logger.debug("Found %d '%s' record types for %s.", 
                         len(addresses[rtype]), rtype, domain['Domain'])
    return True
