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


if __name__ == "__main__":
    print("Testing Connection")

    internet = cve_updater.Node()
    internet.name = "The Internet"
    internet.type = "INTERNET"
    internet.weight = 10
    internet.save()

    device1 = cve_updater.Node()
    device1.name = "Test Device 1"
    device1.weight = 1
    device1.save()

    device2 = cve_updater.Node()
    device2.name = "Test Device 2"
    device2.weight = 1
    device2.save()

    device3 = cve_updater.Node()
    device3.name = "Test Device 3"
    device3.weight = 10
    device3.save()

    device4 = cve_updater.Node()
    device4.name = "Test Device 4"
    device4.weight = 1
    device4.save()

    device5 = cve_updater.Node()
    device5.name = "Test Device 5"
    device5.weight = 1
    device5.save()

    device6 = cve_updater.Node()
    device6.name = "Test Device 6"
    device6.weight = 10
    cve = cve_updater.CVE()
    cve.name = "Some CVE"
    cvss = cve_updater.CVSS()
    cvss.attack_vector = "Network"
    cve.cvss = cvss
    device6.cve = cve
    device6.save()

    # Relationships
    device1.connected_devices.connect(internet)
    device1.connected_devices.connect(device2)
    device1.connected_devices.connect(device3)
    device1.connected_devices.connect(device4)
    device1.connected_devices.connect(device5)
    device1.connected_devices.connect(device6)

    device1.communicates_to.connect(internet, {'complexity': 'Low', 'privilege_needed': 'None'})
    device2.communicates_to.connect(device1, {'complexity': 'Low', 'privilege_needed': 'None'})
    device3.communicates_to.connect(device2, {'complexity': 'Low', 'privilege_needed': 'None'})
    device4.communicates_to.connect(device3, {'complexity': 'Low', 'privilege_needed': 'None'})
    device5.communicates_to.connect(device4, {'complexity': 'Low', 'privilege_needed': 'None'})
    device6.communicates_to.connect(device5, {'complexity': 'Low', 'privilege_needed': 'None'})

    internet.communicates_to.connect(device1, {'complexity': 'Low', 'privilege_needed': 'None'})
    device1.communicates_to.connect(device2, {'complexity': 'Low', 'privilege_needed': 'None'})
    device2.communicates_to.connect(device3, {'complexity': 'Low', 'privilege_needed': 'None'})
    device3.communicates_to.connect(device4, {'complexity': 'Low', 'privilege_needed': 'None'})
    device4.communicates_to.connect(device5, {'complexity': 'Low', 'privilege_needed': 'None'})
    device5.communicates_to.connect(device6, {'complexity': 'Low', 'privilege_needed': 'None'})

    device6.refresh()
    device6 = cve_updater.update_cvss(device6)
    print(device6.cve.cvss.__dict__)
    print(device6.cve.cvss.base_score)
    print(device6.cve.cvss.environmental_score)

    #internet.delete()
    #device1.delete()
    #device2.delete()
    #device3.delete()
    #device4.delete()
    #device5.delete()
    #device6.delete()
