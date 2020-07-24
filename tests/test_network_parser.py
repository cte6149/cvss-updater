import unittest

from util.network_parser import valid_network
from util import exceptions


class NetworkValidatorTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_validate_network_with_no_nodes(self):
        json_network = {
            'nodes': []
        }

        with self.assertRaises(exceptions.EmptyNetworkException) as context:
            valid_network(json_network)

        self.assertIn("You must have a least 2 nodes in the network", str(context.exception))

    def test_validate_network_with_missing_internet_nodes(self):
        json_network = {
            'nodes': [
                {
                    'id': 1,
                    'type': 'MACHINE'
                },
                {
                    'id': 2,
                    'type': 'MACHINE'
                }
            ]
        }

        with self.assertRaises(exceptions.MissingInternetNodeException) as context:
            valid_network(json_network)

        self.assertIn("You must have at least 1 Node of Type Internet Node", str(context.exception))

    def test_validate_network_with_missing_cve(self):
        json_network = {
            'nodes': [
                {
                    'id': 1,
                    'type': 'INTERNET'
                },
                {
                    'id': 2,
                    'type': 'MACHINE'
                }
            ]
        }

        with self.assertRaises(exceptions.MissingCveException) as context:
            valid_network(json_network)

        self.assertIn("You must have at least 1 CVE in the network", str(context.exception))

    def test_validate_proper_network(self):
        json_network = {
            'nodes': [
                {
                    'id': 1,
                    'type': 'INTERNET'
                },
                {
                    'id': 2,
                    'type': 'MACHINE',
                    'cve': {}
                }
            ]
        }

        self.assertTrue(valid_network(json_network))
