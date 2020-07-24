import argparse
import unittest
import os
import pytest

from cve_updater import JsonFileType


class ArgParseJsonFileTypeTestCase(unittest.TestCase):

    def test_parse_json_file(self):

        args = os.path.join(os.path.dirname(__file__), 'networks/network.json')
        parsed_file = JsonFileType('r')(args)

        print(parsed_file)

        assert parsed_file

    def test_parse_not_json_file(self):

        args = os.path.join(os.path.dirname(__file__), 'networks/network.txt')

        with pytest.raises(argparse.ArgumentTypeError) as execinfo:
            JsonFileType('r')(args)

            assert 'Not a JSON file' in str(execinfo.value)
