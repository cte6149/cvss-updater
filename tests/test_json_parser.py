import unittest

import networkx as nx

import util

from util.network_parsers.json_parser import (
    parse_network,
    _parse_questionnaire,
    _parse_cve,
    _parse_cvss,
    _parse_communication_node,
    _convert_readable_value_to_enum_name
)
from util.models import Questionnaire, Answer, CVE, CVSS
from util.cvss_calculator import AttackComplexity, Impact, PrivilegeRequired


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

    def test_converts_attack_vector(self):
        cvss = _parse_cvss({
            'attack_vector': 'Adjacent_Network'
        })

        assert isinstance(cvss.attack_vector, util.AttackVector)
        assert cvss.attack_vector == util.AttackVector.ADJACENT_NETWORK

    def test_converts_attack_complexity(self):
        cvss = _parse_cvss({
            'attack_complexity': 'High'
        })

        assert isinstance(cvss.attack_complexity, util.AttackComplexity)
        assert cvss.attack_complexity == util.AttackComplexity.HIGH

    def test_converts_privilege_required(self):
        cvss = _parse_cvss({
            'privileges_required': 'Low'
        })

        assert isinstance(cvss.privileges_required, util.PrivilegeRequired)
        assert cvss.privileges_required == util.PrivilegeRequired.LOW

    def test_converts_user_interaction(self):
        cvss = _parse_cvss({
            'user_interaction': 'Required'
        })

        assert isinstance(cvss.user_interaction, util.UserInteraction)
        assert cvss.user_interaction == util.UserInteraction.REQUIRED

    def test_converts_scope(self):
        cvss = _parse_cvss({
            'scope': 'Unchanged'
        })

        assert isinstance(cvss.scope, util.Scope)
        assert cvss.scope == util.Scope.UNCHANGED

    def test_converts_exploit_code_maturity(self):
        cvss = _parse_cvss({
            'exploit_code_maturity': 'Functional'
        })

        assert isinstance(cvss.exploit_code_maturity, util.ExploitCodeMaturity)
        assert cvss.exploit_code_maturity == util.ExploitCodeMaturity.FUNCTIONAL

    def test_converts_remediation_level(self):
        cvss = _parse_cvss({
            'remediation_level': 'Workaround'
        })

        assert isinstance(cvss.remediation_level, util.RemediationLevel)
        assert cvss.remediation_level == util.RemediationLevel.WORKAROUND

    def test_converts_report_confidence(self):
        cvss = _parse_cvss({
            'report_confidence': 'Reasonable'
        })

        assert isinstance(cvss.report_confidence, util.ReportConfidence)
        assert cvss.report_confidence == util.ReportConfidence.REASONABLE

    def test_converts_confidentiality(self):
        cvss = _parse_cvss({
            'confidentiality': 'Low'
        })

        assert isinstance(cvss.confidentiality, Impact)
        assert cvss.confidentiality == Impact.LOW

    def test_converts_integrity(self):
        cvss = _parse_cvss({
            'integrity': 'Low'
        })

        assert isinstance(cvss.integrity, Impact)
        assert cvss.integrity == Impact.LOW

    def test_converts_availability(self):
        cvss = _parse_cvss({
            'availability': 'Low'
        })

        assert isinstance(cvss.availability, Impact)
        assert cvss.availability == Impact.LOW


class CommunicationNodeParserTestCases(unittest.TestCase):

    def test_parsing_empty_details_returns_defaults(self):
        data = {
            'id': 1,
        }

        metadata = _parse_communication_node(data)

        expected_data = {
            'v_of_edge': 1,
            'complexity': AttackComplexity.LOW,
            'privilege_needed': "None",
        }
        assert metadata == expected_data

    def test_parsing_complexity_metadata_yields_attack_complexity_enum(self):
        data = {
            'id': 1,
            'complexity': 'High'
        }

        metadata = _parse_communication_node(data)

        expected_data = {
            'v_of_edge': 1,
            'complexity': AttackComplexity.HIGH,
            'privilege_needed': "None",
        }
        assert metadata == expected_data


def test_convert_readable_value_to_enum_name():
    name = 'Not Proven'
    expected = 'NOT_PROVEN'
    assert _convert_readable_value_to_enum_name(name) == expected
