# coding: utf-8
"""Unit Test of DNS Module.
"""

import json
import logging
import unittest

import dns.rdatatype

from spki_python.utilities import logger
from spki_python.dns import get_name_service_records
from spki_python.dns import resolve_domain_addresses


DEFAULT_LOGGING_LEVEL = logging.DEBUG
#DEFAULT_LOGGING_LEVEL = logging.WARNING


class TestNameDNS(unittest.TestCase):
    """Class Summary
    """

    def setUp(self) -> None:
        """_summary_
        """
        logging.basicConfig(
            format='%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        logger.setLevel(DEFAULT_LOGGING_LEVEL)


    def test_get_name_service_records_using_system(self):
        """UnitTest: Get Name Service Records
        """

        # This assumes a CNAME then A record set.
        # $ dig +noall +answer www.microsoft.com A
        # www.microsoft.com.	2109	IN	CNAME	www.microsoft.com-c-3.edgekey.net.
        # www.microsoft.com-c-3.edgekey.net. 333 IN CNAME	www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.
        # www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net. 333 IN CNAME e13678.dscb.akamaiedge.net.
        # e13678.dscb.akamaiedge.net. 12	IN	A	23.203.117.159
        #
        # Testing for multiple record response.
        result = get_name_service_records("www.microsoft.com", "A")

        self.assertTrue(result)
        self.assertEqual(len(result), 4)

        type_name = dns.rdatatype.RdataType.to_text(result[0].rdtype)
        self.assertEqual(type_name, "CNAME")

        type_name = dns.rdatatype.RdataType.to_text(result[-1].rdtype)
        self.assertEqual(type_name, "A")

        # Testing for specific record response.
        result = get_name_service_records("www.microsoft.com", "A", match=True)
        self.assertTrue(result)
        self.assertEqual(len(result), 1)

        type_name = dns.rdatatype.RdataType.to_text(result[0].rdtype)
        self.assertEqual(type_name, "A")
        

        # $ dig +noall +answer docs.python.org SOA
        # docs.python.org.	84440	IN	CNAME	dualstack.python.map.fastly.net.
        #
        # Testing for empty list set response.
        result = get_name_service_records("docs.python.org", "SOA", match=True)
        self.assertFalse(result)
        self.assertEqual(len(result), 0)
        

        # $ dig +noall +answer www.google.com NS
        #
        # Testing variations of no response of any kind.
        result = get_name_service_records("www.google.com", "NS")
        self.assertFalse(result)
        self.assertEqual(len(result), 0)

        result = get_name_service_records("www.google.com", "NS", match=True)
        self.assertFalse(result)
        self.assertEqual(len(result), 0)




    def test_get_name_service_records_using_google(self):
        """UnitTest: Get Name Service Records
        """

        # This assumes a CNAME then A record set.
        # $ dig +noall +answer @8.8.8.8 www.microsoft.com A
        # www.microsoft.com.	2109	IN	CNAME	www.microsoft.com-c-3.edgekey.net.
        # www.microsoft.com-c-3.edgekey.net. 333 IN CNAME	www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.
        # www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net. 333 IN CNAME e13678.dscb.akamaiedge.net.
        # e13678.dscb.akamaiedge.net. 12	IN	A	23.203.117.159
        #
        # Testing for multiple record response.
        result = get_name_service_records("www.microsoft.com", "A", "8.8.8.8")

        self.assertTrue(result)
        self.assertEqual(len(result), 4)

        type_name = dns.rdatatype.RdataType.to_text(result[0].rdtype)
        self.assertEqual(type_name, "CNAME")

        type_name = dns.rdatatype.RdataType.to_text(result[-1].rdtype)
        self.assertEqual(type_name, "A")

        # Testing for specific record response.
        result = get_name_service_records("www.microsoft.com", "A", "8.8.8.8", match=True)
        self.assertTrue(result)
        self.assertEqual(len(result), 1)

        type_name = dns.rdatatype.RdataType.to_text(result[0].rdtype)
        self.assertEqual(type_name, "A")
        

        # $ dig +noall +answer @8.8.8.8 docs.python.org SOA
        # docs.python.org.	84440	IN	CNAME	dualstack.python.map.fastly.net.
        #
        # Testing for empty list set response.
        result = get_name_service_records("docs.python.org", "SOA", "8.8.8.8", match=True)
        self.assertFalse(result)
        self.assertEqual(len(result), 0)
        

        # $ dig +noall +answer @8.8.8.8 www.google.com NS
        #
        # Testing variations of no response of any kind.
        result = get_name_service_records("www.google.com", "NS", "8.8.8.8")
        self.assertFalse(result)
        self.assertEqual(len(result), 0)

        result = get_name_service_records("www.google.com", "NS", "8.8.8.8", match=True)
        self.assertFalse(result)
        self.assertEqual(len(result), 0)


    def test_resole_domain_addresses(self):
        """UnitTest Resolve Website Addresses
        """

        test_sites = [
            {
            "Domain": "www.microsoft.com",
            "Port": 443
            },
            {
            "Domain": "netflix.com",
            "Port": 443
            }
        ]

        print(f"test_sites before:\n{json.dumps(test_sites, indent=2)}")

        result = resolve_domain_addresses(test_sites)

        self.assertTrue(result)

        print(f"test_sites after:\n{json.dumps(test_sites, indent=2)}")
