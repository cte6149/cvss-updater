import networkx as nx

import util

from util.models import Questionnaire, Answer, CVE, CVSS
from util.cvss_calculator import AttackComplexity


def parse_network(network_data):
    """Convert network data into networkx graphs"""

    node_data = network_data.pop('nodes', [])
    connectivity_graph = nx.Graph(**network_data)
    communication_graph = nx.DiGraph(**network_data)

    for node in node_data:
        node_id = node.pop('id')

        connectivity_edges = node.pop('connected_to', [])
        for connected_node in connectivity_edges:
            connectivity_graph.add_edge(node_id, connected_node)

        communication_edges = node.pop('communicates_to', [])
        for communication_node in communication_edges:
            parsed_node = _parse_communication_node(communication_node)
            communication_graph.add_edge(node_id, **parsed_node)

        cve_data = node.pop('cve', None)
        if cve_data:
            cve = _parse_cve(cve_data)
            node['cve'] = cve
        print(node)
        connectivity_graph.add_node(node_id, **node)
        communication_graph.add_node(node_id, **node)

    return connectivity_graph, communication_graph


def _parse_communication_node(node):
    return {
        'v_of_edge': node.pop('id'),
        'complexity': AttackComplexity[node.pop('complexity', 'low').upper()],
        'privilege_needed': 'None',
        **node,
    }


def _parse_questionnaire(questionnaire_data):
    converted_answers = {key: Answer[value] for key, value in questionnaire_data.items()}
    return Questionnaire(converted_answers)


def _parse_cve(cve_data):
    cvss_data = cve_data.pop('cvss', {})
    return CVE(cvss=_parse_cvss(cvss_data), **cve_data)


def _parse_cvss(cvss_data):
    cvss_data['attack_vector'] = util.AttackVector[_convert_readable_value_to_enum_name(
        cvss_data.get('attack_vector', 'Network')
    )]
    cvss_data['attack_complexity'] = util.AttackComplexity[_convert_readable_value_to_enum_name(
        cvss_data.get('attack_complexity', 'Low')
    )]
    cvss_data['privileges_required'] = util.PrivilegeRequired[_convert_readable_value_to_enum_name(
        cvss_data.get('privileges_required', 'None')
    )]
    cvss_data['user_interaction'] = util.UserInteraction[_convert_readable_value_to_enum_name(
        cvss_data.get('user_interaction', 'None')
    )]
    cvss_data['scope'] = util.Scope[_convert_readable_value_to_enum_name(
        cvss_data.get('scope', 'Changed')
    )]
    cvss_data['exploit_code_maturity'] = util.ExploitCodeMaturity[_convert_readable_value_to_enum_name(
        cvss_data.get('exploit_code_maturity', 'High')
    )]
    cvss_data['remediation_level'] = util.RemediationLevel[_convert_readable_value_to_enum_name(
        cvss_data.get('remediation_level', 'Unavailable')
    )]
    cvss_data['report_confidence'] = util.ReportConfidence[_convert_readable_value_to_enum_name(
        cvss_data.get('report_confidence', 'Confirmed')
    )]
    cvss_data['confidentiality'] = util.Impact[_convert_readable_value_to_enum_name(
        cvss_data.get('confidentiality', 'High')
    )]
    cvss_data['integrity'] = util.Impact[_convert_readable_value_to_enum_name(
        cvss_data.get('integrity', 'High')
    )]
    cvss_data['availability'] = util.Impact[_convert_readable_value_to_enum_name(
        cvss_data.get('availability', 'High')
    )]
    cvss = CVSS(**cvss_data)
    return cvss


def _convert_readable_value_to_enum_name(name):
    return name.replace(' ', '_').upper()
