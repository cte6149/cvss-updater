import math, enum
import util

from collections import abc


class NodeType(enum.Enum):
    INTERNET = 'Internet'
    MACHINE = 'Machine'
    SERVER = 'Server'
    SWITCH = 'Switch'
    ROUTER = 'Router'


class CVE:

    def __init__(self, name, cvss=None):
        self.name = name
        self._cvss = cvss

    def __repr__(self):
        return (f"<CVE: name='{self.name}'"
                f", base_score='{self.cvss.base_score if self._cvss else 'N/A'}'"
                f", environmental_score='{self.cvss.environmental_score if self._cvss else 'N/A'}'"
                ">")

    @property
    def cvss(self):
        return self._cvss

    @cvss.setter
    def cvss(self, cvss):
        self._cvss = cvss


class CVSS:

    def __init__(self, **kwargs):
        self.attack_vector = kwargs.get('attack_vector', util.AttackVector.PHYSICAL)
        self.attack_complexity = kwargs.get('attack_complexity', util.AttackComplexity.LOW)
        self.privileges_required = kwargs.get('privileges_required', util.PrivilegeRequired.NONE)
        self.user_interaction = kwargs.get('user_interaction', util.UserInteraction.NONE)
        self.scope = kwargs.get('scope', util.Scope.CHANGED)
        self.confidentiality = kwargs.get('confidentiality', util.Impact.NONE)
        self.integrity = kwargs.get('integrity', util.Impact.NONE)
        self.availability = kwargs.get('availability', util.Impact.NONE)

        self.exploit_code_maturity = kwargs.get('exploit_code_maturity', util.ExploitCodeMaturity.NOT_DEFINED)
        self.remediation_level = kwargs.get('remediation_level', util.RemediationLevel.NOT_DEFINED)
        self.report_confidence = kwargs.get('report_confidence', util.ReportConfidence.NOT_DEFINED)

        self.modified_attack_vector = kwargs.get('modified_attack_vector', util.AttackVector.NOT_DEFINED)
        self.modified_attack_complexity = kwargs.get('modified_attack_complexity', util.AttackComplexity.NOT_DEFINED)
        self.modified_privileges_required = kwargs.get('modified_privileges_required', util.PrivilegeRequired.NOT_DEFINED)
        self.modified_user_interaction = kwargs.get('modified_user_interaction', util.UserInteraction.NOT_DEFINED)
        self.modified_scope = kwargs.get('modified_scope', self.scope)

        self.confidentiality_requirement = kwargs.get('confidentiality_requirement', util.SecurityRequirement.NOT_DEFINED)
        self.integrity_requirement = kwargs.get('integrity_requirement', util.SecurityRequirement.NOT_DEFINED)
        self.availability_requirement = kwargs.get('availability_requirement', util.SecurityRequirement.NOT_DEFINED)

        self.modified_confidentiality = kwargs.get('modified_confidentiality', util.Impact.NOT_DEFINED)
        self.modified_integrity = kwargs.get('modified_integrity', util.Impact.NOT_DEFINED)
        self.modified_availability = kwargs.get('modified_availability', util.Impact.NOT_DEFINED)

    def __str__(self):
        return f'CVSS: base_score={self.base_score}, environmental_score={self.environmental_score}'

    def __repr__(self):
        return (f'CVSS('
                f'attack_vector={self.attack_vector}'
                f', attack_complexity={self.attack_complexity}'
                f', privileges_required={self.privileges_required}'
                f', user_interaction={self.user_interaction}'
                f', scope={self.scope}'
                f', confidentiality={self.confidentiality}'
                f', integrity={self.integrity}'
                f', availability={self.availability}'
                f', exploit_code_maturity={self.exploit_code_maturity}'
                f', remediation_level={self.remediation_level}'
                f', report_confidence={self.report_confidence}'
                f', modified_attack_vector={self.modified_attack_vector}'
                f', modified_attack_complexity={self.modified_attack_complexity}'
                f', modified_privileges_required={self.modified_privileges_required}'
                f', modified_user_interaction={self.modified_user_interaction}'
                f', modified_scope={self.modified_scope}'
                f', modified_confidentiality={self.modified_confidentiality}'
                f', modified_integrity={self.modified_integrity}'
                f', modified_availability={self.modified_availability}'
                f', confidentiality_requirement={self.confidentiality_requirement}'
                f', integrity_requirement={self.integrity_requirement}'
                f', availability_requirement={self.availability_requirement}'
                f')')

    def full_diff(self):
        return (
            f'attack_vector\t\t|\t{self.attack_vector} -> {self.modified_attack_vector}\n'
            f'attack_complexity\t|\t{self.attack_complexity} -> {self.modified_attack_complexity}\n'
            f'privileges_required\t|\t{self.privileges_required} -> {self.modified_privileges_required}\n'
            f'user_interaction\t|\t{self.user_interaction} -> {self.modified_user_interaction}\n'
            f'scope\t\t\t|\t{self.scope} -> {self.modified_scope}\n'
            f'confidentiality\t\t|\t{self.confidentiality} -> {self.modified_confidentiality}\n'
            f'integrity\t\t|\t{self.integrity} -> {self.modified_integrity}\n'
            f'availability\t\t|\t{self.availability} -> {self.modified_availability}\n'
        )

    def diff(self):
        results = ''
        results += f'attack_vector\t\t|\t{self.attack_vector} -> {self.modified_attack_vector}\n' if self.attack_vector != self.modified_attack_vector else ''
        results += f'attack_complexity\t|\t{self.attack_complexity} -> {self.modified_attack_complexity}\n' if self.attack_complexity != self.modified_attack_complexity else ''
        results += f'privileges_required\t|\t{self.privileges_required} -> {self.modified_privileges_required}\n' if self.privileges_required != self.modified_privileges_required else ''
        results += f'user_interaction\t|\t{self.user_interaction} -> {self.modified_user_interaction}\n' if self.user_interaction != self.modified_user_interaction else ''
        results += f'scope\t\t\t|\t{self.scope} -> {self.modified_scope}\n' if self.scope != self.modified_scope else ''
        results += f'confidentiality\t\t|\t{self.confidentiality} -> {self.modified_confidentiality}\n' if self.confidentiality != self.modified_confidentiality else ''
        results += f'integrity\t\t|\t{self.integrity} -> {self.modified_integrity}\n' if self.integrity != self.modified_integrity else ''
        results += f'availability\t\t|\t{self.availability} -> {self.modified_availability}\n' if self.availability != self.modified_availability else ''
        return results

    @property
    def base_score(self):

        base_score = 0
        if self.impact_subscore <= 0:
            base_score = 0
        elif self.scope == util.Scope.UNCHANGED:
            unrounded_base_score = min((self.impact_subscore + self.exploitability_base), 10)
            base_score = math.ceil(unrounded_base_score * 10) / 10
        else:
            unrounded_base_score = min(1.08 * (self.impact_subscore + self.exploitability_base), 10)
            base_score = math.ceil(unrounded_base_score * 10) / 10

        return base_score

    @property
    def impact_subscore(self):

        score = 0
        if self.scope == util.Scope.UNCHANGED:
            score = 6.42 * self.impact_base
        else:
            score = 7.52 * (self.impact_base - 0.029) - 3.25 * math.pow((self.impact_base - 0.02), 15)

        return score

    @property
    def impact_base(self):

        impact_conf = self.confidentiality.value
        impact_integ = self.integrity.value
        impact_avail = self.availability.value

        return 1 - ((1 - impact_conf) * (1 - impact_integ) * (1 - impact_avail))

    @property
    def exploitability_base(self):

        attack_vector = self.attack_vector.value
        attack_complexity = self.attack_complexity.value
        privilege_required = util.get_privilege_required_value(self.privileges_required, self.scope)
        user_interaction = self.user_interaction.value

        return 8.22 * attack_vector * attack_complexity * privilege_required * user_interaction

    @property
    def temporal_score(self):
        return None

    @property
    def environmental_score(self):
        environmental_score = 0

        exploit_code_maturity = self.exploit_code_maturity.value
        remediation_level = self.remediation_level.value
        report_confidence = self.report_confidence.value

        if self.modified_impact_subscore <= 0:
            environmental_score = 0
        elif self.modified_scope == util.Scope.UNCHANGED:
            unrounded_modified_score = min((self.modified_impact_subscore + self.modified_exploitability), 10)
            modified_score = math.ceil(unrounded_modified_score * 10) / 10

            unrounded_environmental_score = modified_score * exploit_code_maturity * remediation_level * report_confidence
            environmental_score = math.ceil(unrounded_environmental_score * 10) / 10
        else:
            unrounded_modified_score = min(1.08 * (self.modified_impact_subscore + self.modified_exploitability), 10)
            modified_score = math.ceil(unrounded_modified_score * 10) / 10

            unrounded_environmental_score = modified_score * exploit_code_maturity * remediation_level * report_confidence
            environmental_score = math.ceil(unrounded_environmental_score * 10) / 10
        return environmental_score

    @property
    def modified_impact_subscore(self):
        score = 0
        if self.scope == util.Scope.UNCHANGED:
            score = 6.42 * self.modified_impact_score
        else:
            score = 7.52 * (self.modified_impact_score-0.029) - 3.25 * math.pow((self.modified_impact_score - 0.02), 15)

        return score

    @property
    def modified_impact_score(self):

        confidentiality_requirement = self.confidentiality_requirement.value
        integrity_requirement = self.integrity_requirement.value
        availability_requirement = self.availability_requirement.value

        modified_impact_conf = self.modified_confidentiality.value
        modified_impact_integ = self.modified_integrity.value
        modified_impact_avail = self.modified_availability.value

        return min(1 - (
        (1 - modified_impact_conf * confidentiality_requirement) * (1 - modified_impact_integ * integrity_requirement) * (
        1 - modified_impact_avail * availability_requirement)), 0.915)

    @property
    def modified_exploitability(self):

        modified_attack_vector = self.modified_attack_vector.value
        modified_attack_complexity = self.modified_attack_complexity.value
        modified_privilege_required = util.get_privilege_required_value(self.modified_privileges_required, self.modified_scope)
        modified_user_interaction = self.modified_user_interaction.value

        return round(
            10000000 * 8.22 * modified_attack_vector * modified_attack_complexity * modified_privilege_required * modified_user_interaction) / 10000000


class Answer(enum.Enum):
    NO = 1
    MAYBE = 2
    YES = 3


class Questionnaire(abc.MutableMapping):

    CONFIDENTIALITY_QUESTIONS = [1, 2, 4, 5, 6, 7, 8, 9]
    INTEGRITY_QUESTIONS = [1, 2, 3, 4, 5, 6, 8, 10]

    def __init__(self, answers=()):
        self.answers = {
            1: Answer.NO,
            2: Answer.NO,
            3: Answer.NO,
            4: Answer.NO,
            5: Answer.NO,
            6: Answer.NO,
            7: Answer.NO,
            8: Answer.NO,
            9: Answer.NO,
            10: Answer.NO,
        }
        self.answers.update(answers)

    def __setitem__(self, k, v):
        self.answers[k] = v

    def __delitem__(self, v):
        del self.answers[v]

    def __getitem__(self, k):
        return self.answers[k]

    def __len__(self):
        return len(self.answers)

    def __iter__(self):
        return iter(self.answers.items())

    @property
    def confidentiality_weight(self):
        return max(answer.value for question_id, answer in self if question_id in self.CONFIDENTIALITY_QUESTIONS)

    @property
    def integrity_weight(self):
        return max(answer.value for question_id, answer in self if question_id in self.INTEGRITY_QUESTIONS)

    def __str__(self):
        return f'confidentiality_weight: {self.confidentiality_weight} -- integrity_weight: {self.integrity_weight}'

    def __repr__(self):
        return str(self)