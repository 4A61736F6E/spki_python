# coding: utf-8
"""Unit Test of Networking Module.
"""

import json
import logging
import unittest

from spki_python.utilities import logger
from spki_python.network import get_certificate
from spki_python.network import is_ipv4_available
from spki_python.network import is_ipv6_available
from spki_python.network import get_cipher_suite_auth_value
from spki_python.network import get_cipher_suites_by_suite_auth
from spki_python.network import get_inverse_cipher_suites



# Querying for AAAA records...
# Command: dig +noall +answer @8.8.8.8 www.gmail.com AAAA
# www.gmail.com.		300	IN	AAAA	2607:f8b0:4009:80b::2005
# 
# Querying for A records...
# Command: dig +noall +answer @8.8.8.8 www.gmail.com A
# www.gmail.com.		300	IN	A	142.250.190.101


DEFAULT_LOGGING_LEVEL = logging.DEBUG
#DEFAULT_LOGGING_LEVEL = logging.WARNING


DEFAULT_CIPHER_SUITES = [
    {
        "id": 50336513,
        "name": "TLS_AES_128_GCM_SHA256",
        "protocol": "TLSv1.3",
        "description": "TLS_AES_128_GCM_SHA256  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(128) Mac=AEAD",
        "strength_bits": 128,
        "alg_bits": 128,
        "aead": True,
        "symmetric": "aes-128-gcm",
        "digest": None,
        "kea": "kx-any",
        "auth": "auth-any"
    },
    {
        "id": 50380844,
        "name": "ECDHE-ECDSA-AES256-GCM-SHA384",
        "protocol": "TLSv1.2",
        "description": "ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256) Mac=AEAD",
        "strength_bits": 256,
        "alg_bits": 256,
        "aead": True,
        "symmetric": "aes-256-gcm",
        "digest": None,
        "kea": "kx-ecdhe",
        "auth": "auth-ecdsa"
    },
    {
        "id": 50380848,
        "name": "ECDHE-RSA-AES256-GCM-SHA384",
        "protocol": "TLSv1.2",
        "description": "ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(256) Mac=AEAD",
        "strength_bits": 256,
        "alg_bits": 256,
        "aead": True,
        "symmetric": "aes-256-gcm",
        "digest": None,
        "kea": "kx-ecdhe",
        "auth": "auth-rsa"
    }
]


class TestNetworking(unittest.TestCase):
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


    def test_get_certificate_ipv6(self):
        """_summary_
        """
        domain = "www.gmail.com"
        address = "2607:f8b0:4009:80b::2005"
        port = 443

        server_cipher_suites, session_details = get_certificate(
            domain, address, port, cipher_suite=None, sni=False
        )

        self.assertIsInstance(session_details, dict)
        self.assertTrue(session_details["Protocol"])
        self.assertTrue(session_details["Certificate"]["PEM"])

        self.assertIsInstance(server_cipher_suites, list)
        self.assertGreater(len(server_cipher_suites), 0)


    def test_get_certificate_ipv6_offline(self):
        """_summary_
        """
        domain = "www.gmail.com"
        address = "2607:f8b0:4009:80b::2005"
        port = 443

        result = get_certificate(
            domain, address, port, cipher_suite=None, sni=False
        )

        self.assertIsNone(result)


    def test_get_certificate_ipv4(self):
        """_summary_
        """

        domain = "www.gmail.com"
        address = "142.250.190.101"
        port = 443

        server_cipher_suites, session_details = get_certificate(
            domain, address, port, cipher_suite=None, sni=False
        )

        self.assertIsInstance(session_details, dict)
        self.assertTrue(session_details["Protocol"])
        self.assertTrue(session_details["Certificate"]["PEM"])

        self.assertIsInstance(server_cipher_suites, list)
        self.assertGreater(len(server_cipher_suites), 0)


    def test_get_certificate_ipv4_offline(self):
        """_summary_
        """

        domain = "www.gmail.com"
        address = "142.250.190.101"
        port = 443

        result = get_certificate(
            domain, address, port, cipher_suite=None, sni=False
        )

        self.assertIsNone(result)
        #self.assertIsInstance(result, dict)


    def _test_get_certificate_ipv4_timeout(self):
        """_summary_
        """

        domain = "example.net"
        address = "127.0.0.1"
        port = 443

        cipher_suites, session_details = get_certificate(
            domain, address, port, cipher_suite=None, sni=False
        )

        self.assertIsNone(cipher_suites)
        #self.assertIsInstance(result, dict)


    def test_is_ipv4_available(self):
        """UnitTest: is IPv4 available?
        """

        result = is_ipv4_available()

        self.assertTrue(result)
        #self.assertFalse(result)


    def test_is_ipv6_available(self):
        """UnitTest: is IPv6 available?
        """

        result = is_ipv6_available()

        self.assertTrue(result)
        #self.assertFalse(result)


    def test_get_cipher_suite_auth_value(self):
        """UnitTest: get cipher suite auth via suite name
        """

        suite_auth = get_cipher_suite_auth_value("TLS_AES_128_GCM_SHA256",DEFAULT_CIPHER_SUITES)
        self.assertEqual(suite_auth, "auth-any")

        suite_auth = get_cipher_suite_auth_value("ECDHE-ECDSA-AES256-GCM-SHA384",DEFAULT_CIPHER_SUITES)
        self.assertEqual(suite_auth, "auth-ecdsa")

        suite_auth = get_cipher_suite_auth_value("ECDHE-RSA-AES256-GCM-SHA384",DEFAULT_CIPHER_SUITES)
        self.assertEqual(suite_auth, "auth-rsa")

        suite_auth = get_cipher_suite_auth_value("Does-Not-Exist", DEFAULT_CIPHER_SUITES)
        self.assertIsNone(suite_auth)


    def test_get_cipher_suites_by_suite_auth(self):
        """UnitTest: get cipher suites by suite auth
        """

        cipher_suites = get_cipher_suites_by_suite_auth("RSA", DEFAULT_CIPHER_SUITES)
        self.assertIn("ECDHE-RSA-AES256-GCM-SHA384", cipher_suites)

        cipher_suites = get_cipher_suites_by_suite_auth("auth-rsa", DEFAULT_CIPHER_SUITES)
        self.assertIn("ECDHE-RSA-AES256-GCM-SHA384", cipher_suites)

        cipher_suites = get_cipher_suites_by_suite_auth("ECDSA", DEFAULT_CIPHER_SUITES)
        self.assertIn("ECDHE-ECDSA-AES256-GCM-SHA384", cipher_suites)

        cipher_suites = get_cipher_suites_by_suite_auth("auth-ecdsa", DEFAULT_CIPHER_SUITES)
        self.assertIn("ECDHE-ECDSA-AES256-GCM-SHA384", cipher_suites)

        cipher_suites = get_cipher_suites_by_suite_auth("auth-any", DEFAULT_CIPHER_SUITES)
        self.assertIn("TLS_AES_128_GCM_SHA256", cipher_suites)


    def test_get_inverse_cipher_suites(self):
        """UnitTest: get inverse cipher suites
        """
        inverse_cipher_suites = get_inverse_cipher_suites('rsa', DEFAULT_CIPHER_SUITES)
        self.assertIsInstance(inverse_cipher_suites, list)
        self.assertIn("ECDHE-ECDSA-AES256-GCM-SHA384", inverse_cipher_suites)

        inverse_cipher_suites = get_inverse_cipher_suites('auth-rsa', DEFAULT_CIPHER_SUITES)
        self.assertIsInstance(inverse_cipher_suites, list)
        self.assertIn("ECDHE-ECDSA-AES256-GCM-SHA384", inverse_cipher_suites)

        inverse_cipher_suites = get_inverse_cipher_suites('ecdsa', DEFAULT_CIPHER_SUITES)
        self.assertIsInstance(inverse_cipher_suites, list)
        self.assertIn("ECDHE-RSA-AES256-GCM-SHA384", inverse_cipher_suites)

        inverse_cipher_suites = get_inverse_cipher_suites('auth-ecdsa', DEFAULT_CIPHER_SUITES)
        self.assertIsInstance(inverse_cipher_suites, list)
        self.assertIn("ECDHE-RSA-AES256-GCM-SHA384", inverse_cipher_suites)


