import math, enum
import util

from collections import abc


class NodeType(enum.Enum):
    INTERNET = 'Internet'
    MACHINE = 'Machine'
    SERVER = 'Server'
    SWITCH = 'Switch'
    ROUTER = 'Router'


class Node:

    def __init__(self, node_id, name="", node_type=NodeType.MACHINE):
        self.id = node_id
        self.type = node_type
        self.name = name

    def __repr__(self):
        return f"<Node: id={self.id}, type={self.type}, name='{self.name}'>"

    def __str__(self):
        return f'ID: {self.id}; {self.name}'


class OldCommunicationRelationship():
    complexity = None
    privilege_needed = None


class OldNode:
    TYPE = (
        ('MACHINE', 'Machine'),
        ('SERVER', 'Server'),
        ('SWITCH', 'Switch'),
        ('ROUTER', 'Router'),
        ('INTERNET', 'Internet')
    )

    # name = neomodel.StringProperty()
    # type = neomodel.StringProperty(choices=TYPE, default='SERVER')
    # confidentiality_weight = neomodel.FloatProperty(default=3.0)
    # integrity_weight = neomodel.FloatProperty(default=3.0)
    #
    # confidentiality_ev_score = neomodel.FloatProperty()
    # integrity_ev_score = neomodel.FloatProperty()
    # availability_ev_score = neomodel.FloatProperty()
    #
    # connected_devices = neomodel.Relationship("Node", "CONNECTED_TO")
    # communicates_to = neomodel.RelationshipTo("Node", "CAN_COMMUNICATE_TO", model=CommunicationRelationship)
    # receives_communications_from = neomodel.RelationshipFrom("Node", "CAN_COMMUNICATE_TO", model=CommunicationRelationship)
    #
    # cve_ = neomodel.JSONProperty(db_property="cve", required=False)

    @property
    def cve(self):
        return CVE.from_dict(self.cve_) if self.cve_ else None

    @cve.setter
    def cve(self, cve):
        self.cve_ = cve.__dict__

    def __hash__(self):
        return hash(self.id)

    def is_connected_to_internet(self, visited=None):
        visited, queue = set(), [self]
        while queue:
            device = queue.pop(0)

            if device.type == "INTERNET":
                return True
            if device not in visited:
                visited.add(device)
                queue.extend(set(device.connected_devices.all()) - visited)
        return False
        # if visited is None:
        #     visited = []
        #
        # visited.append(self)
        # print(visited)
        #
        # if len(self.internet.all()) > 0:
        #     return True
        #
        # for neighbor in self.devices.all():
        #     if neighbor not in visited and neighbor.is_connected_to_internet(visited):
        #         return True
        # return False

    # def get_confidentiality_questionnaire_result(self):
    #     confidentiality_questions = [0, 1, 2, 3, 5, 7]
    #
    #     confidentiality_result = 'none'
    #
    #     for x in range(0, len(confidentiality_questions)):
    #         answer = convert_answer(self.questionnaire_responses)
    #         if(answer == 'high'):
    #             pass
    #
    #
    # def convert_answer(answer):
    #     value = 'high'
    #     if answer == 'no':
    #         value = 'none'
    #     elif answer == 'not sure':
    #         value = 'low'
    #
    #     return value
    #
    # def get_integrity_questionnaire_result(self):
    #     pass

class CVE:

    def __init__(self, name, cvss=None):
        self.name = name
        self._cvss = cvss

    def __repr__(self):
        return (f"<CVE: name='{self.name}'"
                f", base_score='{self.cvss.base_score if self._cvss else 'N/A'}'"
                f", environmental_score='{self.cvss.environmental_score if self._cvss else 'N/A'}'"
                ">")

    @classmethod
    def from_dict(cls, values):
        cve = cls()
        cve.__dict__ = {**cve.__dict__, **values}
        return cve

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
        self.scope = kwargs.get('scope', 'unchanged')
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
        self.modified_scope = 'None'
        self.confidentiality_requirement = kwargs.get('confidentiality_requirement', util.SecurityRequirement.NOT_DEFINED)
        self.integrity_requirement = kwargs.get('integrity_requirement', util.SecurityRequirement.NOT_DEFINED)
        self.availability_requirement = kwargs.get('availability_requirement', util.SecurityRequirement.NOT_DEFINED)
        self.modified_confidentiality = kwargs.get('modified_confidentiality', util.Impact.NOT_DEFINED)
        self.modified_integrity = kwargs.get('modified_integrity', util.Impact.NOT_DEFINED)
        self.modified_availability = kwargs.get('modified_availability', util.Impact.NOT_DEFINED)

    def __str__(self):
        return f'CVSS: base_score={self.base_score}, environmental_score={self.environmental_score}'

    @property
    def base_score(self):

        base_score = 0
        if self.impact_subscore <= 0:
            base_score = 0
        elif self.scope == 'unchanged':
            unrounded_base_score = min((self.impact_subscore + self.exploitability_base), 10)
            base_score = math.ceil(unrounded_base_score * 10) / 10
        else:
            unrounded_base_score = min(1.08 * (self.impact_subscore + self.exploitability_base), 10)
            base_score = math.ceil(unrounded_base_score * 10) / 10

        return base_score

    @property
    def impact_subscore(self):

        score = 0
        if self.scope == 'unchanged':
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
        elif self.modified_scope == 'unchanged':
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
        if self.scope == 'unchanged':
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

    @classmethod
    def from_dict(cls, values):
        cvss = cls()
        for key, value in values.items():
            setattr(cvss, key, value)
        return cvss


class Answer(enum.Enum):
    NO = 1
    MAYBE = 2
    YES = 3


class Questionnaire(abc.MutableMapping):

    CONFIDENTIALITY_QUESTIONS = [1, 2, 4, 5, 6, 7, 9]
    INTEGRITY_QUESTIONS = [1, 2, 3, 4, 6, 8]

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
