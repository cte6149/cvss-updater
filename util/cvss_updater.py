import logging

from collections import defaultdict

import networkx as nx

import util

from .exceptions import MissingCveException
from .models import NodeType
from .cvss_calculator import AttackVector, AttackComplexity, Impact


_LOGGER = logging.getLogger(__name__)


def get_internet_nodes(G):
    return (node[0] for node in G.nodes(data=True) if node[1]['type'] == NodeType.INTERNET)


def _calculate_modified_attack_vector(connectivity_network: nx.Graph, node):

    mav_accepted = False
    try:
        modified_attack_vector = connectivity_network.nodes(data=True)[node]['cve'].cvss.attack_vector
    except KeyError:
        raise MissingCveException("Can't process node without a CVE")

    while not mav_accepted:
        if modified_attack_vector == AttackVector.LOCAL or modified_attack_vector == AttackVector.PHYSICAL:
            mav_accepted = True
        elif modified_attack_vector == AttackVector.ADJACENT_NETWORK:
            if not next(connectivity_network.neighbors(node), None):
                modified_attack_vector = AttackVector.LOCAL
            else:
                mav_accepted = True
        elif modified_attack_vector == AttackVector.NETWORK:
            for internet_source in get_internet_nodes(connectivity_network):
                if nx.has_path(connectivity_network, internet_source, node):
                    mav_accepted = True
                    break
            else:
                modified_attack_vector = AttackVector.ADJACENT_NETWORK

    return modified_attack_vector


# traverse the network to find a path with the lowest privilege
def _calculate_modified_attack_complexity(communication_network: nx.DiGraph, node):

    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_complexity_neighbors = set()

            for neighbor in communication_network.neighbors(device):
                relationship = communication_network.edges[device, neighbor]
                if relationship['complexity'] == AttackComplexity.LOW:
                    if communication_network.nodes[neighbor]['type'] == NodeType.INTERNET:
                        return AttackComplexity.LOW
                    low_complexity_neighbors.add(neighbor)

            queue.extend(low_complexity_neighbors - visited)
    return AttackComplexity.HIGH


def _path_with_no_privileges_to_internet(communication_network: nx.DiGraph, node):
    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            no_privileges = set()

            for neighbor in communication_network.neighbors(device):
                relationship = communication_network.edges[device, neighbor]
                if relationship['privilege_needed'] == 'None':
                    if communication_network.nodes[neighbor]['type'] == NodeType.INTERNET:
                        return True
                    no_privileges.add(neighbor)

            queue.extend(no_privileges - visited)
    return False


def _path_with_low_or_no_privileges_to_internet(communication_network: nx.DiGraph, node):
    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_or_no_privleges_neighbors = set()

            for neighbor in communication_network.neighbors(device):
                relationship = communication_network.edges[device, neighbor]
                if relationship['privilege_needed'] != 'High':
                    if communication_network.nodes[neighbor]['type'] == NodeType.INTERNET:
                        return True
                    low_or_no_privleges_neighbors.add(neighbor)

            queue.extend(low_or_no_privleges_neighbors - visited)
    return False


def _calculate_modified_privileges_required(communication_network: nx.DiGraph, node):
    if _path_with_no_privileges_to_internet(communication_network, node):
        return util.PrivilegeRequired.NONE
    elif _path_with_low_or_no_privileges_to_internet(communication_network, node):
        return util.PrivilegeRequired.LOW
    return util.PrivilegeRequired.HIGH


def _calculate_modified_user_interaction(network: nx.Graph, node):
    return network.nodes[node]['cve'].cvss.user_interaction


def _calculate_modified_scope(network: nx.Graph, node):
    return network.nodes[node]['cve'].cvss.scope


def internetless_subgraph(G):
    internet_nodes = get_internet_nodes(G)
    return nx.subgraph_view(G, lambda node: node not in internet_nodes)


def _calculate_modified_confidentiality(communication_network, node):
    # subnet = internetless_subgraph(communication_network)
    # score = nx.eigenvector_centrality(subnet, weight='confidentiality_weight')[node]
    score = nx.eigenvector_centrality(communication_network, weight='confidentiality_weight')[node]

    if score < 1/3:
        return Impact.NONE
    elif (1/3) <= score < (2/3):
        return Impact.LOW
    else:
        return Impact.HIGH


def _calculate_modified_integrity(communication_network, node):
    # subnet = internetless_subgraph(communication_network)
    # score = nx.eigenvector_centrality(subnet, weight='integrity_weight')[node]
    score = nx.eigenvector_centrality(communication_network, weight='integrity_weight')[node]

    if score < 1/3:
        return Impact.NONE
    elif (1/3) <= score < (2/3):
        return Impact.LOW
    else:
        return Impact.HIGH


def _calculate_modified_availability(connectivity_network: nx.Graph, node):
    score = nx.betweenness_centrality(connectivity_network, normalized=True)[node]

    if score < 1/3:
        return util.Impact.NONE
    elif (1/3) <= score < (2/3):
        return util.Impact.LOW
    else:
        return util.Impact.HIGH


def update_cvss(connectivity_network: nx.Graph, communication_network: nx.DiGraph):
    cves = dict()
    for node in nx.get_node_attributes(connectivity_network, 'cve'):
        cve = connectivity_network.nodes[node]['cve']
        cve.cvss.modified_attack_vector = _calculate_modified_attack_vector(connectivity_network, node)
        cve.cvss.modified_attack_complexity = _calculate_modified_attack_complexity(communication_network, node)
        cve.cvss.modified_privileges_required = _calculate_modified_privileges_required(communication_network, node)
        cve.cvss.modified_user_interaction = _calculate_modified_user_interaction(communication_network, node)
        cve.cvss.modified_scope = _calculate_modified_scope(communication_network, node)
        cve.cvss.modified_confidentiality = _calculate_modified_confidentiality(communication_network, node)
        cve.cvss.modified_integrity = _calculate_modified_integrity(communication_network, node)
        cve.cvss.modified_availability = _calculate_modified_availability(connectivity_network, node)

        cves[node] = cve

    return cves
