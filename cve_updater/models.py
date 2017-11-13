import json
from enum import Enum

import neomodel

neomodel.config.DATABASE_URL = 'bolt://neo4j:admin@localhost:7687'


class Internet(neomodel.StructuredNode):
    name = neomodel.StringProperty(unique_index=True)
    devices = neomodel.Relationship("Device", "CONNECTED_TO", cardinality=neomodel.ZeroOrMore)


class Device(neomodel.StructuredNode):
    TYPE = (
        ('MACHINE', 'Machine'),
        ('SERVER', 'Server'),
        ('SWITCH', 'Switch'),
        ('ROUTER', 'Router')
    )

    name = neomodel.StringProperty()
    type = neomodel.StringProperty(choices=TYPE, default='SERVER')

    internet = neomodel.Relationship("Internet", "CONNECTED_TO", cardinality=neomodel.ZeroOrOne)
    devices = neomodel.Relationship("Device", "CONNECTED_TO")

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
            vertex = queue.pop(0)

            if len(vertex.internet.all()) > 0:
                return True
            if vertex not in visited:
                visited.add(vertex)
                queue.extend(set(vertex.devices.all()) - visited)
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


class CVE():
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
        self.attack_vector = "Local"
        self.attack_complexity = ""
        self.privileges_required = ""
        self.user_interaction = ""
        self.scope = ""
        self.confidentiality = ""
        self.impact = ""
        self.availability = ""
        self.modified_attack_vector = ""
        self.modified_attack_complexity = ""
        self.modified_privileges_required = ""
        self.modified_user_interaction = ""
        self.modified_scope = ""
        self.modified_confidentiality = ""
        self.modified_impact = ""
        self.modified_availability = ""

    def __str__(self):
        return "Attack Vector=" + self.attack_vector + " Mod. Attack Vector=" + self.modified_attack_vector

    @classmethod
    def from_dict(cls, values):
        cvss = cls()
        cvss.__dict__ = {**cvss.__dict__, **values}
        return cvss
