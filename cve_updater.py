#! venv/bin/python3

import argparse
import networkx as nx
import matplotlib.pyplot as plt
import sys

from util.cvss_updater import update_cvss
from util.network_parser import import_network
from util.models import NodeType


class JsonFileType(argparse.FileType):
    def __call__(self, filename):
        if not filename.endswith('.json'):
            raise argparse.ArgumentTypeError(
                'Not a JSON file'
            )
        return super().__call__(filename)


def single_run(args):
    file = args.file_name

    connectivity_network, communication_network = import_network(file)

    if connectivity_network is None and communication_network is None:
        exit(0)

    cves = update_cvss(connectivity_network, communication_network)

    for node_id, cve in cves.items():
        print("Updated CVSS for Node: " + str(node_id))
        print(repr(cve.cvss))
        print('Base Score:', cve.cvss.base_score)
        print('Environmental Score:', cve.cvss.environmental_score)
        print(f'==Full Diff==\n{cve.cvss.full_diff()}')

        print(f'++Diff++\n{cve.cvss.diff()}')

    color_map = ['blue'] * len(connectivity_network)
    for node in communication_network.nodes(data=True):
        ID = 0
        DATA = 1
        node_id = node[ID]
        if 'cve' in node[DATA]:
            print("CVE NODE == ", node_id)
            color_map[node_id - 1] = 'red'
        elif node[DATA]['type'] == NodeType.INTERNET:
            color_map[node_id - 1] = 'white'
        # elif node[DATA]['type'] == NodeType.ROUTER:
        #     color_map[node_id - 1] = 'green'
        # elif node[DATA]['type'] == NodeType.SWITCH:
        #     color_map[node_id - 1] = 'yellow'
        else:
            continue

    nx.draw(connectivity_network, node_color=color_map, with_labels=True, font_weight='bold')
    plt.show()

    # nx.draw(communication_network, node_color=color_map, with_labels=True, font_weight='bold')
    # plt.show()


def random_cve(args):
    print(args)


def random_communications(args):
    print(args)


def add_single_run_command(subparser):
    """Create single run command and add to parser"""
    single_run_cmd = subparser.add_parser(name='single_run', description='Run the CVE updater against a single network')
    single_run_cmd.add_argument('file_name', type=JsonFileType('r'))
    single_run_cmd.set_defaults(func=single_run)


def add_random_cve_command(subparser):
    """Create random cve command"""
    random_cve_cmd = subparser.add_parser(name='random_cve', description='Run CVE Calculator on Randomized Location')
    random_cve_cmd.add_argument('template_filename', type=JsonFileType('r'), help='The template file to generate runs off of')
    random_cve_cmd.add_argument('cve_filename', type=JsonFileType('r'), help='The description of the CVE')
    random_cve_cmd.add_argument('--num_runs', type=int, default=1, help='The number of runs to create')
    random_cve_cmd.add_argument('--seed', type=str, default=1, help='The seed used for randomization')
    random_cve_cmd.set_defaults(func=random_cve)


def add_random_communications_command(subparser):
    """Create random cve command"""
    random_communications_cmd = subparser.add_parser(name='random_communications', description='Run CVE Calculator on a network with randomized communications')
    random_communications_cmd.add_argument('network_filename', type=JsonFileType('r'), help='The network file to generate runs off of')
    random_communications_cmd.add_argument('--num_runs', type=int, default=1, help='The number of runs to create')
    random_communications_cmd.add_argument('--seed', type=str, default=1, help='The seed used for randomization')
    random_communications_cmd.set_defaults(func=random_communications)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(required=True)

    add_single_run_command(subparser)
    add_random_cve_command(subparser)
    add_random_communications_command(subparser)

    try:
        args = parser.parse_args(sys.argv[1:])
        args.func(args)
    except Exception:
        parser.print_usage()
