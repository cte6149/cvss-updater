#! venv/bin/python3

import json
import argparse
import random
import networkx as nx
import matplotlib.pyplot as plt
import sys
import copy
import pprint

from networkx.generators import random_graphs

from util.cvss_updater import update_cvss
from util.network_parser import import_network, json_parser
from util.models import NodeType
from util.cvss_updater import AttackComplexity


class JsonFileType(argparse.FileType):
    def __call__(self, filename):
        if not filename.endswith('.json'):
            raise argparse.ArgumentTypeError(
                'Not a JSON file'
            )
        return super().__call__(filename)


def print_cve_data_for_node(node_id, cve):
    print("Updated CVSS for Node: " + str(node_id))
    print('Base Score:', cve.cvss.base_score)
    print('Environmental Score:', cve.cvss.environmental_score, '\n')
    print(f'==Full Diff==\n{cve.cvss.full_diff()}')

    print(f'++Diff++\n{cve.cvss.diff()}')


def print_graph_relationships(graph: nx.Graph):
    for node, adjacency in graph.adjacency():
        # print(node, ": ", adjacency)
        print(f'Node {node} Neighbors')
        pprint.pprint(adjacency, indent=4)
        print()


def generate_graph_view(connectivity_network, communication_network):
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


def single_run(args):
    file = args.file_name

    connectivity_network, communication_network = import_network(file)

    if connectivity_network is None and communication_network is None:
        exit(0)

    cves = update_cvss(connectivity_network, communication_network)

    for node_id, cve in cves.items():
        print_cve_data_for_node(node_id, cve)

    generate_graph_view(connectivity_network, communication_network)


def random_cve(args):

    connectivity_network, communication_network = import_network(args.template_filename, ignore_cve=True)

    number_of_nodes = connectivity_network.number_of_nodes() - 1 # subtract internet node since cve cannot exist there
    if args.num_runs >= number_of_nodes:
        raise Exception("Number of runs exceeds number of nodes")


    print('Connectivity Graph:')
    print_graph_relationships(connectivity_network)
    print("=====\n")
    print('Communication Gragh:')
    print_graph_relationships(communication_network)

    cve_json = json.load(args.cve_filename)
    template_cve = json_parser._parse_cve(cve_json['cve'])

    visited_nodes = set()
    cve_results = dict()

    for run in range(0, args.num_runs):
        node_id = random.randint(2, number_of_nodes) # internet node is id 1
        while node_id in visited_nodes:
            print("Run already completed for node: ", node_id)
            node_id = random.randint(1, number_of_nodes)

        visited_nodes.add(node_id)

        print("Placing CVE on node ", node_id)
        cve = copy.deepcopy(template_cve)
        connectivity_network.nodes[node_id]['cve'] = cve
        communication_network.nodes[node_id]['cve'] = cve

        cves = update_cvss(connectivity_network, communication_network)

        cve_results.update(cves)
        del connectivity_network.nodes[node_id]['cve']
        del communication_network.nodes[node_id]['cve']

    print(template_cve)
    print('=====')
    for node_id, cve in cve_results.items():
        print_cve_data_for_node(node_id, cve)
        print('=====\n')

#    generate_graph_view(connectivity_network, communication_network)


def generate_random_communication_network(n, p):
    # Generate random graph
    G = random_graphs.erdos_renyi_graph(n, p)
    # Increase Node Ids by 1
    G = nx.relabel_nodes(G, lambda x: x + 1)

    # Generate random attributes for each attribute
    attrs = {
        (edge[0], edge[1]): {
            "complexity": random.choice(list(AttackComplexity)),
            "privilege_needed": random.choice(("None", "Low", "High")),
        }
        for edge in G.edges
    }
    nx.set_edge_attributes(G, attrs)

    return G


def random_communications(args):
    connectivity_network, _ = import_network(args.network_filename)

    print('Connectivity Graph:')
    print_graph_relationships(connectivity_network)
    print('=====')

    for run in range(0, args.num_runs):

        print(f'--- RUN #{run+1}---')

        edge_probability = random.randint(0, 100) / 100
        print(f'Edge Probability: {edge_probability}')

        # randomly generate communications network
        communication_network = generate_random_communication_network(
            connectivity_network.number_of_nodes(),
            edge_probability
        )

        nx.set_node_attributes(communication_network, {
            node: node_attrs for node, node_attrs in connectivity_network.nodes.items()
        })

        # run cve updater on network
        cves = update_cvss(connectivity_network, communication_network)

        print("=====\n")
        print('Communication Gragh:')
        print_graph_relationships(communication_network)

        print('\n=====')
        for node_id, cve in cves.items():
            print_cve_data_for_node(node_id, cve)
            print('=====\n')

        print('-----')

#    generate_graph_view(connectivity_network, communication_network


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
    random_cve_cmd.add_argument('--seed', type=str, default=str(random.randrange(sys.maxsize)), help='The seed used for randomization')
    random_cve_cmd.set_defaults(func=random_cve)


def add_random_communications_command(subparser):
    """Create random cve command"""
    random_communications_cmd = subparser.add_parser(name='random_communications', description='Run CVE Calculator on a network with randomized communications')
    random_communications_cmd.add_argument('network_filename', type=JsonFileType('r'), help='The network file to generate runs off of')
    random_communications_cmd.add_argument('--num_runs', type=int, default=1, help='The number of runs to create')
    random_communications_cmd.add_argument('--seed', type=str, default=str(random.randrange(sys.maxsize)), help='The seed used for randomization')
    random_communications_cmd.set_defaults(func=random_communications)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(required=True)

    add_single_run_command(subparser)
    add_random_cve_command(subparser)
    add_random_communications_command(subparser)

    try:
        args = parser.parse_args(sys.argv[1:])
        print(f'=== Seed: {args.seed} ===')
        random.seed(args.seed)
        args.func(args)
    except argparse.ArgumentError:
        parser.print_usage()
