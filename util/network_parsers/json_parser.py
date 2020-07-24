import networkx as nx

from util.models import Questionnaire, Answer, CVE, CVSS


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
            communication_graph.add_edge(node_id, communication_node.pop('id'), **communication_node)

        connectivity_graph.add_node(node_id, **node)
        communication_graph.add_node(node_id, **node)

    return connectivity_graph, communication_graph


def _parse_questionnaire(questionnaire_data):
    converted_answers = {key: Answer[value] for key, value in questionnaire_data.items()}
    return Questionnaire(converted_answers)


def _parse_cve(cve_data):
    cvss_data = cve_data.pop('cvss', {})
    return CVE(cvss=_parse_cvss(cvss_data), **cve_data)


def _parse_cvss(cvss_data):
    return CVSS(**cvss_data)
