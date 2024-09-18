# coding: utf-8
"""Unit Test of Utilities Module.
"""

import logging
import os
from pathlib import Path
import unittest

# from spki_python.utilities import logger
from spki_python.utilities import read_websites_from_file
from spki_python.utilities import save_certificate
from spki_python.utilities import save_text_file

DEFAULT_WEBSITE_FILE = "tests/data/badssl/targets.txt"


logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s")

DEFAULT_LOGGING_LEVEL = logging.DEBUG
#DEFAULT_LOGGING_LEVEL = logging.WARNING



class TestUtilities(unittest.TestCase):
    """Class Summary
    """

    def setUp(self) -> None:
        """_summary_
        """
        logger.setLevel(DEFAULT_LOGGING_LEVEL)


    def test_logger(self):
        """UnitTest: Logger / Logging
        """
        logging.basicConfig(
            #format="%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s"
            #format='%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s: %(message)s',
            #  datefmt='%Y-%m-%d %H:%M:%S'
        )

        log_level_names = {
            0:"NOTSET",
            10:"DEBUG",
            20:"INFO",
            30:"WARNING",
            40:"ERROR",
            50:"CRITICAL"
        }

        logger.setLevel(DEFAULT_LOGGING_LEVEL)

        print(f"\nLogging Level: {log_level_names[logger.level]} ({logger.level})")
        logger.debug("Messege Level: DEBUG")
        logger.info("Message Level: INFO")
        logger.warning("Message Level: WARNING")
        logger.error("Message Level: ERROR")
        logger.critical("Message Level: CRITICAL")


    def test_read_websites_from_file_failure(self):
        """UnitTest: Read Websites from File (Failure)
        """
        logger.info("Testing read_websites_from_file() with a missing file.")
        websites = read_websites_from_file("tests/data/badssl/missing.txt")
        self.assertIsNone(websites)


    def test_read_websites_from_file(self):
        """UnitTest: Read Websites from File
        """
        websites = read_websites_from_file(DEFAULT_WEBSITE_FILE)

        self.assertTrue(websites)
        self.assertGreater(len(websites),50)
        self.assertIsInstance(websites, list)
        self.assertIsInstance(websites[0], dict)
        self.assertIsInstance(websites[0]['Domain'], str)
        self.assertIsInstance(websites[0]['Port'], int)


    def test_save_text_file(self):
        """UnitTest: Save a Text File to Disk
        """
        output_str = "Hello, Python."
        output_dict = {'Msg':output_str}

        str_filename = f"{Path.cwd()}/tests/data/utilities_test_output.txt"
        json_filename = f"{Path.cwd()}/tests/data/utilities_test_output.json"

        bytes_written = save_text_file(str_filename, output_str)
        self.assertGreater(bytes_written, 0)

        bytes_written = save_text_file(json_filename, output_dict)
        self.assertGreater(bytes_written, 0)
