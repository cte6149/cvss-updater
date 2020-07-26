import unittest

import networkx as nx

from unittest import mock

from util.cvss_updater import (
    _calculate_modified_attack_vector,
    _calculate_modified_attack_complexity,
    _calculate_modified_privileges_required,
    _calculate_modified_user_interaction,
    _calculate_modified_scope,
    _calculate_modified_confidentiality,
    _calculate_modified_integrity,
    internetless_subgraph,
    _path_with_no_privileges_to_internet,
    _path_with_low_or_no_privileges_to_internet,
)
from util.models import NodeType, CVE, CVSS
from util.exceptions import MissingCveException
from util.cvss_calculator import AttackVector, AttackComplexity, UserInteraction, Impact


class ModifiedAttackVectorTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.connectivity_graph = nx.Graph()
        self.connectivity_graph.add_node('A', type=NodeType.INTERNET)
        self.connectivity_graph.add_node('B', type=NodeType.MACHINE)
        self.connectivity_graph.add_node('C', type=NodeType.MACHINE, cve=CVE(name='test',
                                                                             cvss=CVSS(attack_vector=AttackVector.PHYSICAL)))

        self.connectivity_graph.add_edge('A', 'B')
        self.connectivity_graph.add_edge('B', 'C')

    def test_cant_calculate_mav_if_node_doesnt_contain_cve(self):
        """Test that the calculation fails if the passed in node does not have a CVE"""
        with self.assertRaises(MissingCveException) as context:
            _calculate_modified_attack_vector(self.connectivity_graph, 'B')

        assert "Can't process node without a CVE" in str(context.exception)

    def test_physical_attack_vector_yields_physical_mav(self):
        """Test that the calculation does not change the cvss mav value if the initial value is physical"""
        mav = _calculate_modified_attack_vector(self.connectivity_graph, 'C')
        assert mav == AttackVector.PHYSICAL

    def test_local_attack_vector_yields_local_mav(self):
        """Test that the calculation does not change the cvss mav value if the initial value is local"""
        self.connectivity_graph.nodes(data=True)['C']['cve'].cvss.attack_vector = AttackVector.LOCAL

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 'C')
        assert mav == AttackVector.LOCAL

    def test_adjacent_network_av_with_no_neighbors_yields_local_mav(self):
        """Test that the calculation changes adjacent network to local if the node does not have neighbors"""
        self.connectivity_graph.nodes(data=True)['C']['cve'].cvss.attack_vector = AttackVector.ADJACENT_NETWORK
        self.connectivity_graph.remove_edge('B', 'C')

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 'C')
        assert mav == AttackVector.LOCAL

    def test_adjacent_network_av_with_neighbors_yields_adjacent_network_mav(self):
        """Test that the algorithm does not change the attack vector if the node has neighbors"""
        self.connectivity_graph.nodes(data=True)['C']['cve'].cvss.attack_vector = AttackVector.ADJACENT_NETWORK

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 'C')
        assert mav == AttackVector.ADJACENT_NETWORK

    def test_network_av_does_not_change_with_connection_to_internet(self):
        """Test that the algorithm does not change the attack vector if the node has a connection to the internet"""
        self.connectivity_graph.nodes(data=True)['C']['cve'].cvss.attack_vector = AttackVector.NETWORK

        mav = _calculate_modified_attack_vector(self.connectivity_graph, 'C')
        assert mav == AttackVector.NETWORK

    def test_network_av_downgrades_with_no_connection_to_internet(self):
        """Test that the algorithm does not change the attack vector if the node has neighbors"""
        self.connectivity_graph.nodes(data=True)['C']['cve'].cvss.attack_vector = AttackVector.NETWORK

        self.connectivity_graph.remove_edge('A', 'B')
        mav = _calculate_modified_attack_vector(self.connectivity_graph, 'C')
        assert mav == AttackVector.ADJACENT_NETWORK


class ModifiedAttackComplexityTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.communication_graph = nx.DiGraph()
        self.communication_graph.add_node('A', type=NodeType.INTERNET)
        self.communication_graph.add_node('B', type=NodeType.MACHINE, cve=CVE(name='test'))

    def test_node_not_attached_to_internet_high_complexity(self):
        mac = _calculate_modified_attack_complexity(self.communication_graph, 'B')
        assert mac == AttackComplexity.HIGH

    def test_node_attached_to_internet_with_high_complexity(self):
        self.communication_graph.add_edge('B', 'A', complexity=AttackComplexity.HIGH)
        mac = _calculate_modified_attack_complexity(self.communication_graph, 'B')

        assert mac == AttackComplexity.HIGH

    def test_node_attached_to_internet_with_low_complexity(self):
        self.communication_graph.add_edge('B', 'A', complexity=AttackComplexity.LOW)
        mac = _calculate_modified_attack_complexity(self.communication_graph, 'B')

        assert mac == AttackComplexity.LOW

    def test_node_multiple_paths_to_internet_with_high_complexity(self):
        self.communication_graph.add_node('C', type=NodeType.MACHINE)
        self.communication_graph.add_edge('B', 'A', complexity=AttackComplexity.HIGH)
        self.communication_graph.add_edge('C', 'A', complexity=AttackComplexity.HIGH)
        self.communication_graph.add_edge('B', 'C', complexity=AttackComplexity.HIGH)

        mac = _calculate_modified_attack_complexity(self.communication_graph, 'B')

        assert mac == AttackComplexity.HIGH

    def test_node_multiple_paths_to_internet_with_low_complexity_longest_path(self):
        self.communication_graph.add_node('C', type=NodeType.MACHINE)
        self.communication_graph.add_edge('B', 'A', complexity=AttackComplexity.HIGH)
        self.communication_graph.add_edge('C', 'A', complexity=AttackComplexity.LOW)
        self.communication_graph.add_edge('B', 'C', complexity=AttackComplexity.LOW)

        mac = _calculate_modified_attack_complexity(self.communication_graph, 'B')

        assert mac == AttackComplexity.LOW


class ModifiedPrivilegesTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.communication_graph = nx.DiGraph()
        self.communication_graph.add_node('A', type=NodeType.INTERNET)
        self.communication_graph.add_node('B', type=NodeType.MACHINE)
        self.communication_graph.add_node('C', type=NodeType.MACHINE, cve={'cvss': {}})

    def test_path_to_internet_with_none_privileges_returns_none(self):
        with mock.patch('util.cvss_updater._path_with_no_privileges_to_internet') as mock_no_priv_test:
            mock_no_priv_test.return_value = True
            assert _calculate_modified_privileges_required(self.communication_graph, 'C') == 'None'

    def test_path_to_internet_with_low_or_none_privileges_returns_low(self):
        with mock.patch('util.cvss_updater._path_with_no_privileges_to_internet') as mock_no_priv_test, \
                mock.patch('util.cvss_updater._path_with_low_or_no_privileges_to_internet') as mock_no_low_priv_test:
            mock_no_priv_test.return_value = False
            mock_no_low_priv_test.return_value = True
            assert _calculate_modified_privileges_required(self.communication_graph, 'C') == 'Low'

    def test_no_path_to_internet_with_none_or_low_privileges_returns_high(self):
        with mock.patch('util.cvss_updater._path_with_no_privileges_to_internet') as mock_no_priv_test, \
                mock.patch('util.cvss_updater._path_with_low_or_no_privileges_to_internet') as mock_no_low_priv_test:
            mock_no_priv_test.return_value = False
            mock_no_low_priv_test.return_value = False
            assert _calculate_modified_privileges_required(self.communication_graph, 'C') == 'High'


class PathToInternetNonePrivilegesTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.communication_graph = nx.DiGraph()
        self.communication_graph.add_node('A', type=NodeType.INTERNET)
        self.communication_graph.add_node('B', type=NodeType.MACHINE)
        self.communication_graph.add_node('C', type=NodeType.MACHINE, cve={'cvss': {}})

    def test_no_path_with_none_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='High')
        self.communication_graph.add_edge('C', 'B', privilege_needed='Low')

        assert not _path_with_no_privileges_to_internet(self.communication_graph, 'C')

    def test_direct_path_with_none_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='High')
        self.communication_graph.add_edge('C', 'A', privilege_needed='None')

        assert _path_with_no_privileges_to_internet(self.communication_graph, 'C')

    def test_indirect_path_with_none_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='None')
        self.communication_graph.add_edge('C', 'B', privilege_needed='None')
        self.communication_graph.add_edge('C', 'A', privilege_needed='High')

        assert _path_with_no_privileges_to_internet(self.communication_graph, 'C')


class PathToInternetNoneOrLowPrivilegesTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.communication_graph = nx.DiGraph()
        self.communication_graph.add_node('A', type=NodeType.INTERNET)
        self.communication_graph.add_node('B', type=NodeType.MACHINE)
        self.communication_graph.add_node('C', type=NodeType.MACHINE, cve={'cvss': {}})

    def test_no_path_to_internet(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='High')
        self.communication_graph.add_edge('C', 'B', privilege_needed='High')

        assert not _path_with_low_or_no_privileges_to_internet(self.communication_graph, 'C')

    def test_direct_path_with_none_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='High')
        self.communication_graph.add_edge('C', 'A', privilege_needed='None')

        assert _path_with_low_or_no_privileges_to_internet(self.communication_graph, 'C')

    def test_direct_path_with_low_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='High')
        self.communication_graph.add_edge('C', 'A', privilege_needed='Low')

        assert _path_with_low_or_no_privileges_to_internet(self.communication_graph, 'C')

    def test_indirect_path_with_none_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='None')
        self.communication_graph.add_edge('C', 'B', privilege_needed='None')
        self.communication_graph.add_edge('C', 'A', privilege_needed='High')

        assert _path_with_low_or_no_privileges_to_internet(self.communication_graph, 'C')

    def test_indirect_path_with_low_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='Low')
        self.communication_graph.add_edge('C', 'B', privilege_needed='Low')
        self.communication_graph.add_edge('C', 'A', privilege_needed='High')

        assert _path_with_low_or_no_privileges_to_internet(self.communication_graph, 'C')

    def test_indirect_path_with_mixed_privileges(self):

        self.communication_graph.add_edge('B', 'A', privilege_needed='None')
        self.communication_graph.add_edge('C', 'B', privilege_needed='Low')
        self.communication_graph.add_edge('C', 'A', privilege_needed='High')

        assert _path_with_low_or_no_privileges_to_internet(self.communication_graph, 'C')


class ModifiedUserInteractionTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.connectivity_graph = nx.Graph()
        self.connectivity_graph.add_node('A', type=NodeType.MACHINE, cve=CVE(name='test', cvss=CVSS(user_interaction=UserInteraction.NONE)))

    def test_user_interaction_unchanged(self):
        assert _calculate_modified_user_interaction(self.connectivity_graph, 'A') == UserInteraction.NONE


class ModifiedScopeTestCases(unittest.TestCase):

    def setUp(self) -> None:
        self.connectivity_graph = nx.Graph()
        self.connectivity_graph.add_node('A', type=NodeType.MACHINE, cve=CVE(name='test', cvss=CVSS(scope='Unchanged')))

    def test_user_interaction_unchanged(self):
        assert _calculate_modified_scope(self.connectivity_graph, 'A') == 'Unchanged'


class ModifiedConfidentialityTestCases(unittest.TestCase):

    def test_return_none_if_eigenvector_lt_one_third(self):
        G = nx.Graph()
        G.add_node('A', type=NodeType.MACHINE)

        with mock.patch('util.cvss_updater.nx.eigenvector_centrality') as mock_eigenvector:
            mock_eigenvector.return_value = {'A': 0}
            assert _calculate_modified_confidentiality(G, 'A') == Impact.NONE
            assert mock_eigenvector.called

    def test_return_none_if_eigenvector_gte_one_third_lt_two_third(self):
        G = nx.Graph()
        G.add_node('A', type=NodeType.MACHINE)

        with mock.patch('util.cvss_updater.nx.eigenvector_centrality') as mock_eigenvector:
            mock_eigenvector.return_value = {'A': 1/3}
            assert _calculate_modified_confidentiality(G, 'A') == Impact.LOW
            assert mock_eigenvector.called

    def test_return_none_if_eigenvector_gte_two_third(self):
        G = nx.Graph()
        G.add_node('A', type=NodeType.MACHINE)

        with mock.patch('util.cvss_updater.nx.eigenvector_centrality') as mock_eigenvector:
            mock_eigenvector.return_value = {'A': 2/3}
            assert _calculate_modified_confidentiality(G, 'A') == Impact.HIGH
            assert mock_eigenvector.called


class ModifiedIntegrityTestCases(unittest.TestCase):

    def test_return_none_if_eigenvector_lt_one_third(self):
        G = nx.Graph()
        G.add_node('A', type=NodeType.MACHINE)

        with mock.patch('util.cvss_updater.nx.eigenvector_centrality') as mock_eigenvector:
            mock_eigenvector.return_value = {'A': 0}
            assert _calculate_modified_integrity(G, 'A') == Impact.NONE
            assert mock_eigenvector.called

    def test_return_none_if_eigenvector_gte_one_third_lt_two_third(self):
        G = nx.Graph()
        G.add_node('A', type=NodeType.MACHINE)

        with mock.patch('util.cvss_updater.nx.eigenvector_centrality') as mock_eigenvector:
            mock_eigenvector.return_value = {'A': 1/3}
            assert _calculate_modified_integrity(G, 'A') == Impact.LOW
            assert mock_eigenvector.called

    def test_return_none_if_eigenvector_gte_two_third(self):
        G = nx.Graph()
        G.add_node('A', type=NodeType.MACHINE)

        with mock.patch('util.cvss_updater.nx.eigenvector_centrality') as mock_eigenvector:
            mock_eigenvector.return_value = {'A': 2/3}
            assert _calculate_modified_integrity(G, 'A') == Impact.HIGH
            assert mock_eigenvector.called


def test_retrieve_subgraph_with_no_internet_nodes():
    G = nx.Graph()
    G.add_node('A', type=NodeType.INTERNET)
    G.add_node('B', type=NodeType.MACHINE)
    G.add_node('C', type=NodeType.MACHINE)
    G.add_node('D', type=NodeType.MACHINE)
    G.add_node('E', type=NodeType.MACHINE)

    subgraph = internetless_subgraph(G)

    assert 'A' not in subgraph
    assert all(node in G for node in subgraph)
