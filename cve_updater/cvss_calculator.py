import math


def get_attack_vector_value(name):
    return {
        'network': 0.85,
        'adjacent network': 0.62,
        'local': 0.55,
        'physical': 0.2,
    }[name.lower()]


def get_impact_value(name):
    return {
        'high': 0.56,
        'low': 0.22,
        'none': 0
    }[name.lower()]


def get_attack_complexity_value(name):
    return {
        'high': 0.44,
        'low': 0.77
    }[name.lower()]


def get_privilege_required_value(name, scope):
    values = {'none': 0.85}
    if scope.lower() == "unchanged":
        values['low'] = 0.62
        values['high'] = 0.27
    else:
        values['low'] = 0.68
        values['high'] = 0.50

    return values[name.lower()]


def get_user_interaction_value(name):
    return {
        'required': 0.62,
        'none': 0.85
    }[name.lower()]


def get_exploit_code_maturity_value(name):
    return {
        'not defined': 1,
        'high': 1,
        'functional': 0.97,
        'proof of concept': 0.94,
        'unproven':0.91
    }[name.lower()]


def get_remediation_level_value(name):
    return {
        'not defined': 1,
        'unavailable': 1,
        'workaround': 0.97,
        'temporary fix': 0.96,
        'official fix':0.95
    }[name.lower()]


def get_report_confidence_value(name):
    return {
        'not defined': 1,
        'confirmed': 1,
        'reasonable': 0.96,
        'unknown': 0.92
    }[name.lower()]


def get_security_requirement_value(name):
    return {
        'not defined': 1,
        'high': 1.5,
        'medium': 1,
        'low': 0.5
    }[name.lower()]


def get_modified_privilege_required_value(name, modified_scope):
    values = {'none': 0.85}

    if modified_scope.lower() == "unchanged":
        values['low'] = 0.62
        values['high'] = 0.27
    else:
        values['low'] = 0.68
        values['high'] = 0.50

    return values[name.lower()]
