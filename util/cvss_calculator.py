import math
import enum


class AttackVector(enum.Enum):
    NETWORK = 0.85
    ADJACENT_NETWORK = 0.62
    LOCAL = 0.55
    PHYSICAL = 0.2
    NOT_DEFINED = 0.85


class AttackComplexity(enum.Enum):
    NOT_DEFINED = 0.77
    HIGH = 0.44
    LOW = 0.77


class PrivilegeRequired(enum.Enum):
    NONE = 'None'
    LOW = 'Low'
    HIGH = 'High'
    NOT_DEFINED = 'Not Defined'

    def get_value(self, scope):
        pass

def get_privilege_required_value(name, scope):
    values = {
        PrivilegeRequired.NONE: 0.85,
        PrivilegeRequired.NOT_DEFINED: 0.85,
    }
    if scope == Scope.UNCHANGED:
        values[PrivilegeRequired.LOW] = 0.62
        values[PrivilegeRequired.HIGH] = 0.27
    else:
        values[PrivilegeRequired.LOW] = 0.68
        values[PrivilegeRequired.HIGH] = 0.50

    return values[name]


class UserInteraction(enum.Enum):
    REQUIRED = 0.62
    NONE = 0.85
    NOT_DEFINED = 0.85


class Scope(enum.Enum):
    NOT_DEFINED = 'Not Defined'
    UNCHANGED = 'Unchanged'
    CHANGED = 'Changed'


class Impact(enum.Enum):
    HIGH = 0.56
    LOW = 0.22
    NONE = 0
    NOT_DEFINED = 0.56


class ExploitCodeMaturity(enum.Enum):
    NOT_DEFINED = 1
    HIGH = 1
    FUNCTIONAL = 0.97
    PROOF_OF_CONCEPT = 0.94
    UNPROVEN = 0.91


class RemediationLevel(enum.Enum):
    NOT_DEFINED = 1
    UNAVAILABLE = 1
    WORKAROUND = 0.97
    TEMPORARY_FIX = 0.96
    OFFICIAL_FIX = 0.95


class ReportConfidence(enum.Enum):
    NOT_DEFINED = 1
    CONFIRMED = 1
    REASONABLE = 0.96
    UNKNOWN = 0.92


class SecurityRequirement(enum.Enum):
    NOT_DEFINED = 1
    HIGH = 1.5
    MEDIUM = 1
    LOW = 0.5


def get_modified_privilege_required_value(name, modified_scope):
    return get_privilege_required_value(name, modified_scope)
