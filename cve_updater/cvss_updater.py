import cve_updater
import networkx as nx


def _calculate_modified_attack_vector(connectivity_network: nx.Graph, node):

    mav_accepted = False
    modified_attack_vector = connectivity_network.nodes[node]['cve']['cvss']['attack_vector']

    while not mav_accepted:
        if modified_attack_vector.lower() == "local" or modified_attack_vector.lower == "physical":
            mav_accepted = True
        elif modified_attack_vector.lower() == "adjacent network":
            if len(connectivity_network.neighbors(node)) == 0:
                modified_attack_vector = "Local"
            else:
                mav_accepted = True
        elif modified_attack_vector.lower() == "network":
            for internet_source in cve_updater.get_internet_nodes(connectivity_network):
                if nx.has_path(connectivity_network, internet_source, node):
                    mav_accepted = True
                else:
                    modified_attack_vector = "Adjacent Network"

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
                if relationship['complexity'] == 'Low':
                    if communication_network.nodes[neighbor]['type'] == 'INTERNET':
                        return 'Low'
                    low_complexity_neighbors.add(neighbor)

            queue.extend(low_complexity_neighbors - visited)
    return 'High'


def _path_with_no_privileges_to_internet(communication_network: nx.DiGraph, node):
    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_privileges = set()

            for neighbor in communication_network.neighbors(device):
                relationship = communication_network.edges[device, neighbor]
                if relationship['privilege_needed'] == 'None':
                    if communication_network.nodes[neighbor]['type'] == 'INTERNET':
                        return True
                    low_privileges.add(neighbor)

            queue.extend(low_privileges - visited)
    return False


def _path_with_low_or_no_privileges_to_internet(communication_network: nx.DiGraph, node):
    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_complexity_neighbors = set()

            for neighbor in communication_network.neighbors(device):
                relationship = communication_network.edges[device, neighbor]
                if relationship['privilege_needed'] in ['None', 'Low']:
                    if neighbor.type == 'INTERNET':
                        return True
                    low_complexity_neighbors.add(neighbor)

            queue.extend(low_complexity_neighbors - visited)
    return False


def _calculate_modified_privileges_required(communication_network: nx.DiGraph, node):
    if _path_with_no_privileges_to_internet(communication_network, node):
        return "None"
    elif _path_with_low_or_no_privileges_to_internet(communication_network, node):
        return "Low"
    return 'High'


def _calculate_modified_user_interaction(network: nx.Graph, node):
    return network.nodes[node]['cve']['cvss']['user_interaction']


def _calculate_modified_scope(network: nx.Graph, node):
    return network.nodes[node]['cve']['cvss']['scope']


def _calculate_modified_confidentiality(communication_network, node):
    subnet = list(set(communication_network) - set(cve_updater.get_internet_nodes(communication_network)))
    score = nx.eigenvector_centrality(communication_network.subgraph(subnet), weight='confidentiality_weight')[node]

    if score < 1/3:
        return 'None'
    elif (1/3) <= score < (2/3):
        return 'Low'
    else:
        return 'High'


def _calculate_modified_integrity(communication_network, node):
    subnet = list(set(communication_network) - set(cve_updater.get_internet_nodes(communication_network)))
    score = nx.eigenvector_centrality(communication_network.subgraph(subnet), weight='integrity_weight')[node]

    if score < 1/3:
        return 'None'
    elif (1/3) <= score < (2/3):
        return 'Low'
    else:
        return 'High'


def _calculate_modified_availability(connectivity_network: nx.Graph, node):
    score = nx.betweenness_centrality(connectivity_network, normalized=True)[node]

    if score < 1/3:
        return 'None'
    elif (1/3) <= score < (2/3):
        return 'Low'
    else:
        return 'High'


def update_cvss(connectivity_network: nx.Graph, communication_network: nx.DiGraph):
    cves = dict()
    for node in nx.get_node_attributes(connectivity_network, 'cve'):
        cve = connectivity_network.nodes[node]['cve']
        cve['cvss']['modified_attack_vector'] = _calculate_modified_attack_vector(connectivity_network, node)
        cve['cvss']['modified_attack_complexity'] = _calculate_modified_attack_complexity(communication_network, node)
        cve['cvss']['modified_privileges_required'] = _calculate_modified_privileges_required(communication_network, node)
        cve['cvss']['modified_user_interaction'] = _calculate_modified_user_interaction(communication_network, node)
        cve['cvss']['modified_scope'] = _calculate_modified_scope(communication_network, node)
        cve['cvss']['modified_confidentiality'] = _calculate_modified_confidentiality(communication_network, node)
        cve['cvss']['modified_integrity'] = _calculate_modified_integrity(communication_network, node)
        cve['cvss']['modified_availability'] = _calculate_modified_availability(connectivity_network, node)

        cves[node] = cve

    return cves
