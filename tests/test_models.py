import unittest

from unittest import mock

from cve_updater.models import Node, NodeType, CVE, CVSS


class NodeTestCase(unittest.TestCase):

    def test_repr(self):
        node = Node(node_id=1, name='Test Machine')
        expected = "<Node: id=1, type=NodeType.MACHINE, name='Test Machine'>"

        assert repr(node) == expected

    def test_str(self):
        node = Node(node_id=1, name='Test Machine')
        expected = "ID: 1; Test Machine"

        assert str(node) == expected

    def test_default_type_is_machine(self):
        node = Node(node_id=1)

        assert node.type == NodeType.MACHINE


class CveTestCase(unittest.TestCase):

    def test_repr(self):
        cve = CVE(name='1')
        expected = "<CVE: name='1', base_score='N/A', environmental_score='N/A'>"

        assert repr(cve) == expected

    # def test_str(self):
    #     node = Node(node_id=1, name='Test Machine')
    #     expected = "ID: 1; Test Machine"
    #
    #     assert str(node) == expected


class CvssTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.cvss = CVSS()

    def test_repr(self):
        expected = "<CVSS: base_score=0, environmental_score=0>"

        assert repr(self.cvss) == expected

    def test_base_score_returns_zero_if_subscore_less_than_zero(self):
        with mock.patch('cve_updater.models.CVSS.impact_subscore',
                        new_callable=mock.PropertyMock) as mock_impact_subscore:

            mock_impact_subscore.return_value = 0
            assert self.cvss.base_score == 0
            mock_impact_subscore.assert_called_once()

    def test_base_score_uses_calculation_when_impact_subscore_gt_zero_and_scope_unchanged(self):
        with mock.patch('cve_updater.models.CVSS.impact_subscore',
                        new_callable=mock.PropertyMock) as mock_impact_subscore:

            mock_impact_subscore.return_value = 1
            self.cvss.scope = 'unchanged'
            assert self.cvss.base_score == 2.0
            assert mock_impact_subscore.called
            assert mock_impact_subscore.call_count == 2

    def test_base_score_uses_calculation_when_impact_subscore_gt_zero_and_scope_changed(self):
        with mock.patch('cve_updater.models.CVSS.impact_subscore',
                        new_callable=mock.PropertyMock) as mock_impact_subscore:

            mock_impact_subscore.return_value = 1
            self.cvss.scope = 'changed'
            assert self.cvss.base_score == 2.1
            assert mock_impact_subscore.called
            assert mock_impact_subscore.call_count == 2

    def test_impact_subscore_uses_calculation_when_scope_unchanged(self):
        with mock.patch('cve_updater.models.CVSS.impact_base',
                        new_callable=mock.PropertyMock) as mock_impact_base:

            mock_impact_base.return_value = 1
            self.cvss.scope = 'unchanged'
            assert self.cvss.impact_subscore == 6.42
            mock_impact_base.assert_called_once()

    def test_impact_subscore_uses_calculation_when_scope_changed(self):
        with mock.patch('cve_updater.models.CVSS.impact_base',
                        new_callable=mock.PropertyMock) as mock_impact_base:

            mock_impact_base.return_value = 1
            self.cvss.scope = 'changed'
            assert round(self.cvss.impact_subscore, 2) == 4.90
            assert mock_impact_base.called
            assert mock_impact_base.call_count == 2

    def test_impact_base_calculation(self):
        test_cases = [
            ('None', 'None', 'None', 0),
            ('Low', 'Low', 'Low', 0.53),
            ('High', 'High', 'High', 0.91),
            ('Low', 'None', 'None', 0.22),
            ('High', 'None', 'None', 0.56),
            ('None', 'Low', 'None', 0.22),
            ('None', 'High', 'None', 0.56),
            ('None', 'None', 'Low', 0.22),
            ('None', 'None', 'High', 0.56),
            ('Low', 'Low', 'None', 0.39),
            ('High', 'High', 'None', 0.81),
            ('Low', 'None', 'Low', 0.39),
            ('High', 'None', 'High', 0.81),
        ]

        for case in test_cases:
            self.cvss.confidentiality = case[0]
            self.cvss.integrity = case[1]
            self.cvss.availability = case[2]

            assert round(self.cvss.impact_base, 2) == case[3]