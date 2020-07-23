import unittest

import networkx as nx

from cve_updater.network_parsers.json_parser import parse_network, _parse_questionnaire, _parse_cve, _parse_cvss
from cve_updater.models import Questionnaire, Answer, CVE, CVSS


class JsonParserTestCases(unittest.TestCase):

    def test_parser_returns_graph_digraph_tuple(self):
        data = {}

        connectivity_graph, communication_graph = parse_network(data)

        assert isinstance(connectivity_graph, nx.Graph)
        assert isinstance(communication_graph, nx.DiGraph)

    def test_parser_parses_graph_attributes_from_top_level_json_keys(self):

        data = {
            'key': 'value'
        }

        connectivity_graph, communication_graph = parse_network(data)

        assert connectivity_graph.graph.get('key', None)
        assert communication_graph.graph.get('key', None)

    def test_parser_parses_nodes_from_nodes_list(self):

        data = {
            'nodes': [
                {'id': 'A'},
                {'id': 'B'},
                {'id': 'C'},
            ]
        }

        connectivity_graph, communication_graph = parse_network(data)

        expected_nodes = ['A', 'B', 'C']

        assert all((node in expected_nodes for node in connectivity_graph.nodes))
        assert all((node in expected_nodes for node in communication_graph.nodes))

    def test_parser_parses_node_data(self):

        data = {
            'nodes': [
                {
                    'id': 'A',
                    'key': 'value'
                },
            ]
        }

        connectivity_graph, communication_graph = parse_network(data)

        assert connectivity_graph.nodes(data=True)['A'].get('key', None)
        assert communication_graph.nodes(data=True)['A'].get('key', None)

    def test_parser_parses_connectivity_edge(self):
        data = {
            'nodes': [
                {
                    'id': 'A',
                    'connected_to': ['B']
                }
            ]
        }

        connectivity_graph, _ = parse_network(data)

        assert 'B' in connectivity_graph['A']

    def test_parser_parses_communication_edge_with_data(self):
        data = {
            'nodes': [
                {
                    'id': 'A',
                    'communicates_to': [{
                        'id': 'B',
                        'key': 'value'
                    }]
                }
            ]
        }

        _, communication_graph = parse_network(data)

        assert 'B' in communication_graph['A']
        assert 'A' not in communication_graph['B']
        assert communication_graph['A']['B'].get('key', None)


class QuestionnaireParserTestCases(unittest.TestCase):

    def test_parsing_returns_questionnaire_type(self):

        questionnaire = _parse_questionnaire({})

        assert isinstance(questionnaire, Questionnaire)

    def test_parsing_converts_answers_to_enum(self):

        questionnaire = _parse_questionnaire({1: 'YES'})

        assert questionnaire.answers[1] == Answer.YES


class CveParserTestCases(unittest.TestCase):

    def test_parsing_cve_returns_cve_type(self):

        cve = _parse_cve({'name': 'test'})

        assert isinstance(cve, CVE)

    def test_parses_cvss(self):

        cve = _parse_cve({'name': 'test', 'cvss': {}})

        assert cve.cvss
        assert isinstance(cve.cvss, CVSS)


class CvssPaserTestCases(unittest.TestCase):

    def test_parsing_cvss_returns_cvss_type(self):

        cvss = _parse_cvss({})

        assert isinstance(cvss, CVSS)
