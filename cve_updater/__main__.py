import json
import networkx as nx
import matplotlib.pyplot as plt

from cve_updater import import_network, update_cvss, base_score, environmental_score


def get_user_file():

    while True:
        print("Supported File Types: .json")
        file_path = input("Input network file to load: ")
        formatted_path = file_path.split(".")

        if len(formatted_path) == 2 and formatted_path[1] == "json":
            return file_path
        else:
            print("Unsupported File Type!\n")


def main():

    while True:
        file_path = get_user_file()
        connectivity_network, communication_network = import_network(file_path)

        if connectivity_network is not None and communication_network is not None:
            break

    cves = update_cvss(connectivity_network, communication_network)

    for node_id, cve in cves.items():
        print("Updated CVSS for Node: " + str(node_id))
        print('Base Score:', base_score(cve['cvss']))
        print('Environmental Score:', environmental_score(cve['cvss']))

        print(json.dumps(communication_network.nodes[node_id], sort_keys=False, indent=2))

    color_map = ['blue'] * len(connectivity_network)
    for node in nx.get_node_attributes(connectivity_network, 'cve'):
        print(f'Node: {node}')
        color_map[node-1] = 'red'

    print(color_map)

    nx.draw(connectivity_network, node_color=color_map, with_labels=True, font_weight='bold')
    plt.show()

    nx.draw(communication_network, node_color=color_map, with_labels=True, font_weight='bold')
    plt.show()


if __name__ == "__main__":
    main()
