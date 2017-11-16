import json
from enum import Enum

import neomodel

neomodel.config.DATABASE_URL = 'bolt://neo4j:admin@localhost:7687'


class CommunicationRelationship(neomodel.StructuredRel):
    complexity = neomodel.StringProperty()
    privilege_needed = neomodel.StringProperty()


class Node(neomodel.StructuredNode):
    TYPE = (
        ('MACHINE', 'Machine'),
        ('SERVER', 'Server'),
        ('SWITCH', 'Switch'),
        ('ROUTER', 'Router'),
        ('INTERNET', 'Internet')
    )

    name = neomodel.StringProperty()
    type = neomodel.StringProperty(choices=TYPE, default='SERVER')

    connected_devices = neomodel.Relationship("Node", "CONNECTED_TO")
    communicates_to = neomodel.RelationshipTo("Node", "CAN_COMMUNICATE_TO", model=CommunicationRelationship)
    receives_communications_from = neomodel.RelationshipFrom("Node", "CAN_COMMUNICATE_TO", model=CommunicationRelationship)

    cve_ = neomodel.JSONProperty(db_property="cve", required=False)

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


class CVE:
    name = ""

    def __init__(self):
        self.name = ""
        self._cvss = None

    @classmethod
    def from_dict(cls, values):
        cve = cls()
        cve.__dict__ = {**cve.__dict__, **values}
        return cve

    @property
    def cvss(self):
        return CVSS.from_dict(self._cvss) if self._cvss else None

    @cvss.setter
    def cvss(self, cvss):
        self._cvss = cvss.__dict__


class CVSS:

    def __init__(self):
        self.attack_vector = 'Network'
        self.attack_complexity = 'High'
        self.privileges_required = 'None'
        self.user_interaction = 'None'
        self.scope = 'Changed'
        self.confidentiality = 'High'
        self.impact = 'High'
        self.availability = 'High'
        self.modified_attack_vector = 'None'
        self.modified_attack_complexity = 'None'
        self.modified_privileges_required = 'None'
        self.modified_user_interaction = 'None'
        self.modified_scope = 'None'
        self.modified_confidentiality = 'None'
        self.modified_impact = 'None'
        self.modified_availability = 'None'

    @classmethod
    def from_dict(cls, values):
        cvss = cls()
        for key, value in values.items():
            setattr(cvss, key, value)
        return cvss
