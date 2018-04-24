import json
import cve_updater


def import_network(file_path):
    contents = read_json(file_path)

    if valid_network(contents):
        return create_network(contents)


def read_json(file_path):
    file_contents = dict()

    try:
        with open(file_path) as f:
            file_contents = json.load(f)
    except FileNotFoundError as e:
        print("File " + e.filename + " Not Found!")

    return file_contents


def valid_network(network_json):

    if not nodes_exist(network_json):
        print("You must have a least 2 nodes in the network")
        return False

    cve_exists = False
    internet_exists = False

    for node in network_json["nodes"]:

        if internet_exists and cve_exists:
            break

        if not internet_exists:
            internet_exists = node_is_internet(node)
        if not cve_exists:
            cve_exists = node_has_cve(node)

    if not cve_exists:
        print("You must have at least 1 CVE in the network")
        return False
    elif not internet_exists:
        print("You must have at least 1 Node of Type Internet Node")
        return False

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


def create_network(network_json):
    nodes = dict()
    network_connected_to = dict()
    network_communicates_to = dict()

    for json_node in network_json["nodes"]:
        node_id = json_node["id"]
        node = parse_node(json_node)
        node.save()

        nodes[node_id] = node
        network_connected_to[node_id] = json_node["connected_to"]
        network_communicates_to[node_id] = json_node["communicates_to"]

    for node_id, node in nodes.items():
        for connected_node in network_connected_to[node_id]:
            node.connected_devices.connect(nodes[connected_node])

        for communicates_to_connection in network_communicates_to[node_id]:
            node.communicates_to.connect(nodes[communicates_to_connection["id"]], {
                "complexity": communicates_to_connection["complexity"],
                "privilege_needed": communicates_to_connection["privilege_needed"]
            })

    return nodes


def parse_node(json_node):
    node = cve_updater.Node()
    node.name = json_node["name"]

    if "cve" in json_node:
        json_cve = json_node["cve"]
        cve = cve_updater.CVE()
        cve.name = json_cve["name"]

        json_cvss = json_cve["cvss"]
        cvss = cve_updater.CVSS()
        cvss.attack_vector = json_cvss["attack_vector"]
        cvss.attack_complexity = json_cvss["attack_complexity"]
        cvss.privileges_required = json_cvss["privileges_required"]
        cvss.user_interaction = json_cvss["user_interaction"]
        cvss.scope = json_cvss["scope"]
        cvss.confidentiality = json_cvss["confidentiality"]
        cvss.integrity = json_cvss["integrity"]
        cvss.availability = json_cvss["availability"]
        cvss.exploit_code_maturity = json_cvss["exploit_code_maturity"]
        cvss.remediation_level = json_cvss["remediation_level"]
        cvss.report_confidence = json_cvss["report_confidence"]

        cve.cvss = cvss
        node.cve = cve

    return node


def main():
    print(import_network("../networks/network.json"))


if __name__ == "__main__":
    main()
