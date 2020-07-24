import json
import networkx as nx

from .networkx_controller import create_networks
from .exceptions import EmptyNetworkException, MissingInternetNodeException, MissingCveException


def import_network(f):
    contents = json.load(f)

    if contents != [] and valid_network(contents):
        return create_networks(contents)


def valid_network(network_json):

    if not nodes_exist(network_json):
        raise EmptyNetworkException("You must have a least 2 nodes in the network")

    cve_exists = False
    internet_exists = False

    for node in network_json["nodes"]:

        if internet_exists and cve_exists:
            break

        if not internet_exists:
            internet_exists = node_is_internet(node)
        if not cve_exists:
            cve_exists = node_has_cve(node)

    if not internet_exists:
        raise MissingInternetNodeException("You must have at least 1 Node of Type Internet Node")
    elif not cve_exists:
        raise MissingCveException("You must have at least 1 CVE in the network")

    if meta_name_exists(network_json):
        print("Successfully loaded network: " + network_json["meta"]["name"])
    else:
        print("Successfully loaded network")
    return True


def meta_name_exists(network_json):
    return "meta" in network_json and network_json["meta"]is not {} and "name" in network_json["meta"]


def nodes_exist(network_json):
    return "nodes" in network_json and len(network_json["nodes"]) >= 2


def node_is_internet(node):
    return "type" in node and node["type"].lower() == "internet"


def node_has_cve(node):
    return "cve" in node


def main():
    connectivity, communication = import_network("../networks/network.json")

    print("Connectivity:")
    for node in connectivity.nodes:
        print(node, "-", *connectivity.neighbors(node))

    print("Communication:")
    for node in communication.nodes:
        for neighbor in communication.neighbors(node):
            print(node, "-", neighbor, communication.edges[node, neighbor])

    print("CVEs:")
    for node in nx.get_node_attributes(connectivity, 'cve'):
        print(node)


if __name__ == "__main__":
    main()
