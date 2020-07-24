import argparse
import json
import networkx as nx
import matplotlib.pyplot as plt
import sys

from util.cvss_calculator import base_score, environmental_score
from util.cvss_updater import update_cvss
from util.network_parser import import_network


class JsonFileType(argparse.FileType):
    def __call__(self, filename):
        if not filename.endswith('.json'):
            raise argparse.ArgumentTypeError(
                'Not a JSON file'
            )
        return super().__call__(filename)


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('file_name', type=JsonFileType('r'))

    parsed_args = parser.parse_args(args)

    return parsed_args


def main():

    args = parse_args(sys.argv[1:])

    file = args.file_name

    connectivity_network, communication_network = import_network(file)

    if connectivity_network is None and communication_network is None:
        return

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
