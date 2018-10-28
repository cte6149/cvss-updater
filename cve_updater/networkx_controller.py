import networkx as nx
import cve_updater


def create_networks(network_json):
    connectivity_network = nx.Graph(**network_json['meta'])
    communication_network = nx.DiGraph(**network_json['meta'])

    for json_node in network_json['nodes']:

        node_id = json_node['id']

        node_attributes = dict()
        node_attributes['name'] = json_node['name']
        node_attributes['type'] = json_node['type'].upper()

        if "cve" in json_node:
            node_attributes['cve'] = json_node['cve']
            node_attributes['cve']['cvss']['confidentiality_requirement'] = network_json['meta']['confidentiality_requirement']
            node_attributes['cve']['cvss']['integrity_requirement'] = network_json['meta']['integrity_requirement']
            node_attributes['cve']['cvss']['availability_requirement'] = network_json['meta']['availability_requirement']

        connectivity_network.add_node(node_id, **node_attributes)
        for neighbor_id in json_node["connected_to"]:
            connectivity_network.add_edge(node_id, neighbor_id)

        communication_network.add_node(node_id, **node_attributes)
        confidentiality_weight, integrity_weight = determine_weights(json_node.get('questionnaire_responses', []))
        for neighbor in json_node["communicates_to"]:
            edges = list()

            communication_network.add_edge(node_id, neighbor['id'],
                                           **{'complexity': neighbor['complexity'],
                                              'privilege_needed': neighbor['privilege_needed'],
                                              'confidentiality': confidentiality_weight,
                                              'integrity_weight': integrity_weight
                                              }
                                           )

    return connectivity_network, communication_network


def determine_weights(questionnaire_answers):
    confidentiality_questions = [1, 2, 4, 5, 6, 7, 9]
    integrity_questions = [1, 2, 3, 4, 6, 8]

    confidentiality_weight = 1
    integrity_weight = 1

    for answer in questionnaire_answers:
        score = 1
        if answer["answer"].lower() == "no":
            score = 1
        elif answer["answer"].lower() == "maybe":
            score = 2
        elif answer["answer"].lower() == "yes":
            score = 3

        if answer["question_id"] in confidentiality_questions:
            if score > confidentiality_weight:
                confidentiality_weight = score
        elif answer["question_id"] in integrity_questions:
            if score > integrity_weight:
                integrity_weight = score

    return confidentiality_weight, integrity_weight


def get_internet_nodes(network):
    return filter(lambda x: network.nodes[x]['type'] == 'INTERNET', network.nodes)
