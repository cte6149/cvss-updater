import unittest

import networkx as nx

from cve_updater.cvss_updater import (
    _calculate_modified_attack_vector,
    _calculate_modified_attack_complexity,
    _calculate_modified_user_interaction,
    _calculate_modified_scope,
    internetless_subgraph,
)

from cve_updater.models import NodeType
from cve_updater.exceptions import MissingCveException
from cve_updater.cvss_calculator import AttackVector


class ModifiedAttackVectorTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.connectivity_graph = nx.Graph()
        self.connectivity_graph.add_node(0, type=NodeType.INTERNET)
        self.connectivity_graph.add_node(1, type=NodeType.MACHINE)
        self.connectivity_graph.add_node(2, type=NodeType.MACHINE, cve={'cvss': {'attack_vector': AttackVector.PHYSICAL}})

        self.connectivity_graph.add_edge(0, 1)
        self.connectivity_graph.add_edge(1, 2)

    def test_cant_calculate_mav_if_node_doesnt_contain_cve(self):
        """Test that the calculation fails if the passed in node does not have a CVE"""
        with self.assertRaises(MissingCveException) as context:
            _calculate_modified_attack_vector(self.connectivity_graph, 1)

        assert "Can't process node without a CVE" in str(context.exception)

    def test_physical_attack_vector_yields_physical_mav(self):
        """Test that the calculation does not change the cvss mav value if the initial value is physical"""
        mav = _calculate_modified_attack_vector(self.connectivity_graph, 2)
        assert mav == AttackVector.PHYSICAL

    def test_local_attack_vector_yields_local_mav(self):
        """Test that the calculation does not change the cvss mav value if the initial value is local"""
        self.connectivity_graph.nodes(data=True)[2]['cve']['cvss']['attack_vector'] = AttackVector.LOCAL

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 2)
        assert mav == AttackVector.LOCAL

    def test_adjacent_network_av_with_no_neighbors_yields_local_mav(self):
        """Test that the calculation changes adjacent network to local if the node does not have neighbors"""
        self.connectivity_graph.nodes(data=True)[2]['cve']['cvss']['attack_vector'] = AttackVector.ADJACENT_NETWORK
        self.connectivity_graph.remove_edge(1, 2)

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 2)
        assert mav == AttackVector.LOCAL

    def test_adjacent_network_av_with_neighbors_yields_adjacent_network_mav(self):
        """Test that the algorithm does not change the attack vector if the node has neighbors"""
        self.connectivity_graph.nodes(data=True)[2]['cve']['cvss']['attack_vector'] = AttackVector.ADJACENT_NETWORK

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 2)
        assert mav == AttackVector.ADJACENT_NETWORK

    def test_network_av_does_not_change_with_connection_to_internet(self):
        """Test that the algorithm does not change the attack vector if the node has a connection to the internet"""
        self.connectivity_graph.nodes(data=True)[2]['cve']['cvss']['attack_vector'] = AttackVector.NETWORK

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 2)
        assert mav == AttackVector.NETWORK

    def test_network_av_downgrades_with_no_connection_to_internet(self):
        """Test that the algorithm does not change the attack vector if the node has neighbors"""
        self.connectivity_graph.nodes(data=True)[2]['cve']['cvss']['attack_vector'] = AttackVector.NETWORK

        self.connectivity_graph.remove_edge(0, 1)
        mav = _calculate_modified_attack_vector(self.connectivity_graph, 2)
        assert mav == AttackVector.ADJACENT_NETWORK


class ModifiedAttackComplexityTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.communication_graph = nx.DiGraph()
        self.communication_graph.add_node(0, type=NodeType.INTERNET)
        self.communication_graph.add_node(1, type=NodeType.MACHINE, cve={'cvss': {}})

    def test_node_not_attached_to_internet_high_complexity(self):
        mac = _calculate_modified_attack_complexity(self.communication_graph, 1)
        assert mac == 'High'

    def test_node_attached_to_internet_with_high_complexity(self):
        self.communication_graph.add_edge(1, 0, complexity='High')
        mac = _calculate_modified_attack_complexity(self.communication_graph, 1)

        assert mac == 'High'

    def test_node_attached_to_internet_with_low_complexity(self):
        self.communication_graph.add_edge(1, 0, complexity='Low')
        mac = _calculate_modified_attack_complexity(self.communication_graph, 1)

        assert mac == 'Low'

    def test_node_multiple_paths_to_internet_with_high_complexity(self):
        self.communication_graph.add_node(2, type=NodeType.MACHINE)
        self.communication_graph.add_edge(1, 0, complexity='High')
        self.communication_graph.add_edge(2, 0, complexity='High')
        self.communication_graph.add_edge(1, 2, complexity='High')

        mac = _calculate_modified_attack_complexity(self.communication_graph, 1)

        assert mac == 'High'

    def test_node_multiple_paths_to_internet_with_low_complexity_longest_path(self):
        self.communication_graph.add_node(2, type=NodeType.MACHINE)
        self.communication_graph.add_edge(1, 0, complexity='High')
        self.communication_graph.add_edge(2, 0, complexity='Low')
        self.communication_graph.add_edge(1, 2, complexity='Low')

        mac = _calculate_modified_attack_complexity(self.communication_graph, 1)

        assert mac == 'Low'


class ModifiedPrivilegesTestCases(unittest.TestCase):
    pass


class ModifiedUserInteractionTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.connectivity_graph = nx.Graph()
        self.connectivity_graph.add_node(0, type=NodeType.MACHINE, cve={'cvss': {'user_interaction': 'None'}})

    def test_user_interaction_unchanged(self):
        assert _calculate_modified_user_interaction(self.connectivity_graph, 0) == 'None'


class ModifiedScopeTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.connectivity_graph = nx.Graph()
        self.connectivity_graph.add_node(0, type=NodeType.MACHINE, cve={'cvss': {'scope': 'Unchanged'}})

    def test_user_interaction_unchanged(self):
        assert _calculate_modified_scope(self.connectivity_graph, 0) == 'Unchanged'


def test_retrieve_subgraph_with_no_internet_nodes():
    G = nx.Graph()
    G.add_node(0, type=NodeType.INTERNET)
    G.add_node(1, type=NodeType.MACHINE)
    G.add_node(2, type=NodeType.MACHINE)
    G.add_node(3, type=NodeType.MACHINE)
    G.add_node(4, type=NodeType.MACHINE)

    subgraph = internetless_subgraph(G)

    assert 0 not in subgraph
    assert all(node in G for node in subgraph)
