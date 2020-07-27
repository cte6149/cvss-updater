import unittest
import re

from unittest import mock

from util.models import NodeType, CVE, CVSS, Questionnaire, Answer
from util.cvss_calculator import Impact, Scope


class CveTestCase(unittest.TestCase):

    def test_repr(self):
        cve = CVE(name='1')
        expected = "<CVE: name='1', base_score='N/A', environmental_score='N/A'>"

        assert repr(cve) == expected


class CvssTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.cvss = CVSS()

    def test_str(self):
        expected = r'CVSS: base_score=[0-9]*.?[0-9]*, environmental_score=[0-9]*.?[0-9]*'

        assert re.match(expected, str(self.cvss))

    def test_base_score_returns_zero_if_subscore_less_than_zero(self):
        with mock.patch('util.models.CVSS.impact_subscore',
                        new_callable=mock.PropertyMock) as mock_impact_subscore:

            mock_impact_subscore.return_value = 0
            assert self.cvss.base_score == 0
            mock_impact_subscore.assert_called_once()

    def test_base_score_uses_calculation_when_impact_subscore_gt_zero_and_scope_unchanged(self):
        with mock.patch('util.models.CVSS.impact_subscore',
                        new_callable=mock.PropertyMock) as mock_impact_subscore:

            mock_impact_subscore.return_value = 1
            self.cvss.scope = Scope.UNCHANGED
            assert self.cvss.base_score == 2.0
            assert mock_impact_subscore.called
            assert mock_impact_subscore.call_count == 2

    def test_base_score_uses_calculation_when_impact_subscore_gt_zero_and_scope_changed(self):
        with mock.patch('util.models.CVSS.impact_subscore',
                        new_callable=mock.PropertyMock) as mock_impact_subscore:

            mock_impact_subscore.return_value = 1
            self.cvss.scope = Scope.CHANGED
            assert self.cvss.base_score == 2.1
            assert mock_impact_subscore.called
            assert mock_impact_subscore.call_count == 2

    def test_impact_subscore_uses_calculation_when_scope_unchanged(self):
        with mock.patch('util.models.CVSS.impact_base',
                        new_callable=mock.PropertyMock) as mock_impact_base:

            mock_impact_base.return_value = 1
            self.cvss.scope = Scope.UNCHANGED
            assert self.cvss.impact_subscore == 6.42
            mock_impact_base.assert_called_once()

    def test_impact_subscore_uses_calculation_when_scope_changed(self):
        with mock.patch('util.models.CVSS.impact_base',
                        new_callable=mock.PropertyMock) as mock_impact_base:

            mock_impact_base.return_value = 1
            self.cvss.scope = Scope.CHANGED
            assert round(self.cvss.impact_subscore, 2) == 4.90
            assert mock_impact_base.called
            assert mock_impact_base.call_count == 2

    def test_impact_base_calculation(self):
        test_cases = [
            (Impact.NONE, Impact.NONE, Impact.NONE, 0),
            (Impact.LOW, Impact.LOW, Impact.LOW, 0.53),
            (Impact.HIGH, Impact.HIGH, Impact.HIGH, 0.91),
            (Impact.LOW, Impact.NONE, Impact.NONE, 0.22),
            (Impact.HIGH, Impact.NONE, Impact.NONE, 0.56),
            (Impact.NONE, Impact.LOW, Impact.NONE, 0.22),
            (Impact.NONE, Impact.HIGH, Impact.NONE, 0.56),
            (Impact.NONE, Impact.NONE, Impact.LOW, 0.22),
            (Impact.NONE, Impact.NONE, Impact.HIGH, 0.56),
            (Impact.LOW, Impact.LOW, Impact.NONE, 0.39),
            (Impact.HIGH, Impact.HIGH, Impact.NONE, 0.81),
            (Impact.LOW, Impact.NONE, Impact.LOW, 0.39),
            (Impact.HIGH, Impact.NONE, Impact.HIGH, 0.81),
        ]

        for case in test_cases:
            self.cvss.confidentiality = case[0]
            self.cvss.integrity = case[1]
            self.cvss.availability = case[2]

            assert round(self.cvss.impact_base, 2) == case[3]


class QuestionnaireTestCases(unittest.TestCase):

    def test_creation_with_no_data_yields_NO_answers(self):

        questionnaire = Questionnaire()

        assert all(answer == Answer.NO for answer in questionnaire.answers.values())

    def test_creation_with_answers_updates_default_questionnaire_results(self):

        questionnaire = Questionnaire(answers={1: Answer.YES})

        assert any(answer == Answer.YES for answer in questionnaire.answers.values())

    def test_questionnaire_defines_get_item(self):

        questionnaire = Questionnaire()

        assert questionnaire[1] == Answer.NO
