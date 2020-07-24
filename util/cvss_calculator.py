import math
import enum


class AttackVector(enum.Enum):
    NETWORK = 0.85
    ADJACENT_NETWORK = 0.62
    LOCAL = 0.55
    PHYSICAL = 0.2

    @classmethod
    def get_value(cls, name):
        pass

def get_attack_vector_value(name):
    return {
        'network': 0.85,
        'adjacent network': 0.62,
        'local': 0.55,
        'physical': 0.2,
    }[name.lower()]


class Impact(enum.Enum):
    HIGH = 0.56
    LOW = 0.22
    NONE = 0

def get_impact_value(name):
    return {
        'high': 0.56,
        'low': 0.22,
        'none': 0
    }[name.lower()]


class AttackComplexity(enum.Enum):
    HIGH = 0.44
    LOW = 0.77

def get_attack_complexity_value(name):
    return {
        'high': 0.44,
        'low': 0.77
    }[name.lower()]


class PrivilegeRequired(enum.Enum):
    pass

def get_privilege_required_value(name, scope):
    values = {'none': 0.85}
    if scope.lower() == "unchanged":
        values['low'] = 0.62
        values['high'] = 0.27
    else:
        values['low'] = 0.68
        values['high'] = 0.50

    return values[name.lower()]


class UserInteration(enum.Enum):
    REQUIRED = 0.62
    NONE = 0.85

def get_user_interaction_value(name):
    return {
        'required': 0.62,
        'none': 0.85
    }[name.lower()]


class ExploitCodeMaturity(enum.Enum):
    NOT_DEFINED = 1
    HIGH = 1
    FUNCTIONAL = 0.97
    PROOF_OF_CONCEPT = 0.94
    UNPROVEN = 0.91

def get_exploit_code_maturity_value(name):
    return {
        'not defined': 1,
        'high': 1,
        'functional': 0.97,
        'proof of concept': 0.94,
        'unproven':0.91
    }[name.lower()]


class REMEDIATION_LEVEL(enum.Enum):
    NOT_DEFINED = 1
    UNAVAILABLE = 1
    WORKAROUND = 0.97
    TEMPORARY_FIX = 0.96
    OFFICIAL_FIX = 0.95

def get_remediation_level_value(name):
    return {
        'not defined': 1,
        'unavailable': 1,
        'workaround': 0.97,
        'temporary fix': 0.96,
        'official fix':0.95
    }[name.lower()]


class ReportConfidence(enum.Enum):
    NOT_DEFINED = 1
    CONFIRMED = 1
    REASONABLE = 0.96
    UNKNOWN = 0.92

def get_report_confidence_value(name):
    return {
        'not defined': 1,
        'confirmed': 1,
        'reasonable': 0.96,
        'unknown': 0.92
    }[name.lower()]


class SecurityRequirement(enum.Enum):
    NOT_DEFINED = 1
    HIGH = 1.5
    MEDIUM = 1
    LOW = 0.5

def get_security_requirement_value(name):
    return {
        'not defined': 1,
        'high': 1.5,
        'medium': 1,
        'low': 0.5
    }[name.lower()]


class ModifiedPrivilegeRequired(enum.Enum):
    pass 
def get_modified_privilege_required_value(name, modified_scope):
    values = {'none': 0.85}

    if modified_scope.lower() == "unchanged":
        values['low'] = 0.62
        values['high'] = 0.27
    else:
        values['low'] = 0.68
        values['high'] = 0.50

    return values[name.lower()]


def base_score(cvss):

    base_score = 0
    if impact_subscore(cvss) <= 0:
        base_score = 0
    elif cvss['scope'] == 'unchanged':
        unrounded_base_score = min((impact_subscore(cvss) + exploitability_base(cvss)), 10)
        base_score = math.ceil(unrounded_base_score * 10) / 10
    else:
        unrounded_base_score = min(1.08 * (impact_subscore(cvss) + exploitability_base(cvss)), 10)
        base_score = math.ceil(unrounded_base_score * 10) / 10

    return base_score


def impact_subscore(cvss):

    score = 0
    if cvss['scope'] == 'unchanged':
        score = 6.42 * impact_base(cvss)
    else:
        score = 7.52 * (impact_base(cvss) - 0.029) - 3.25 * math.pow((impact_base(cvss) - 0.02), 15)

    return score


def impact_base(cvss):

    impact_conf = get_impact_value(cvss['confidentiality'])
    impact_integ = get_impact_value(cvss['integrity'])
    impact_avail = get_impact_value(cvss['availability'])

    return 1 - ((1 - impact_conf) * (1 - impact_integ) * (1 - impact_avail))


def exploitability_base(cvss):

    attack_vector = get_attack_vector_value(cvss['attack_vector'])
    attack_complexity = get_attack_complexity_value(cvss['attack_complexity'])
    privilege_required = get_privilege_required_value(cvss['privileges_required'], cvss['scope'])
    user_interaction = get_user_interaction_value(cvss['user_interaction'])

    return 8.22 * attack_vector * attack_complexity * privilege_required * user_interaction


def temporal_score(self):
    return None


def environmental_score(cvss):
    environmental_score = 0

    exploit_code_maturity = get_exploit_code_maturity_value(cvss['exploit_code_maturity'])
    remediation_level = get_remediation_level_value(cvss['remediation_level'])
    report_confidence = get_report_confidence_value(cvss['report_confidence'])

    if modified_impact_subscore(cvss) <= 0:
        environmental_score = 0
    elif cvss['modified_scope'] == 'unchanged':
        unrounded_modified_score = min((modified_impact_subscore(cvss) + modified_exploitability(cvss)), 10)
        modified_score = math.ceil(unrounded_modified_score * 10) / 10

        unrounded_environmental_score = modified_score * exploit_code_maturity * remediation_level * report_confidence
        environmental_score = math.ceil(unrounded_environmental_score * 10) / 10
    else:
        unrounded_modified_score = min(1.08 * (modified_impact_subscore(cvss) + modified_exploitability(cvss)), 10)
        modified_score = math.ceil(unrounded_modified_score * 10) / 10

        unrounded_environmental_score = modified_score * exploit_code_maturity * remediation_level * report_confidence
        environmental_score = math.ceil(unrounded_environmental_score * 10) / 10
    return environmental_score


def modified_impact_subscore(cvss):
    score = 0
    if cvss['modified_scope'] == 'unchanged':
        score = 6.42 * modified_impact_score(cvss)
    else:
        score = 7.52 * (modified_impact_score(cvss)-0.029) - 3.25 * math.pow((modified_impact_score(cvss) - 0.02), 15)

    return score


def modified_impact_score(cvss):

    confidentiality_requirement = get_security_requirement_value(cvss['confidentiality_requirement'])
    integrity_requirement = get_security_requirement_value(cvss['integrity_requirement'])
    availability_requirement = get_security_requirement_value(cvss['availability_requirement'])

    modified_impact_conf = get_impact_value(cvss['modified_confidentiality'])
    modified_impact_integ = get_impact_value(cvss['modified_integrity'])
    modified_impact_avail = get_impact_value(cvss['modified_availability'])

    return min(1 - (
    (1 - modified_impact_conf * confidentiality_requirement) * (1 - modified_impact_integ * integrity_requirement) * (
    1 - modified_impact_avail * availability_requirement)), 0.915)


def modified_exploitability(cvss):

    modified_attack_vector = get_attack_vector_value(cvss['modified_attack_vector'])
    modified_attack_complexity = get_attack_complexity_value(cvss['modified_attack_complexity'])
    modified_privilege_required = get_privilege_required_value(cvss['modified_privileges_required'], cvss['modified_scope'])
    modified_user_interaction = get_user_interaction_value(cvss['modified_user_interaction'])

    return round(
        10000000 * 8.22 * modified_attack_vector * modified_attack_complexity * modified_privilege_required * modified_user_interaction) / 10000000