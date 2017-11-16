import json

from neo4j.v1 import GraphDatabase, basic_auth

import cve_updater

#driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "admin"))

centralities = {}


def find_cves():
    pass


if __name__ == "__main__":
    print("Testing Connection")

    internet = cve_updater.Node()
    internet.name = "The Internet"
    internet.type = "INTERNET"
    internet.save()

    device1 = cve_updater.Node()
    device1.name = "Test Device 1"
    device1.save()

    device2 = cve_updater.Node()
    device2.name = "Test Device 2"
    device2.save()

    device3 = cve_updater.Node()
    device3.name = "Test Device 3"
    device3.save()

    device4 = cve_updater.Node()
    device4.name = "Test Device 4"
    device4.save()

    device5 = cve_updater.Node()
    device5.name = "Test Device 5"
    device5.save()

    device6 = cve_updater.Node()
    device6.name = "Test Device 6"
    cve = cve_updater.CVE()
    cve.name = "Some CVE"
    cvss = cve_updater.CVSS()
    cvss.attack_vector = "Network"
    cve.cvss = cvss
    device6.cve = cve
    device6.save()

    # Relationships
    device1.connected_devices.connect(internet)
    device1.connected_devices.connect(device2)
    device1.connected_devices.connect(device3)
    device1.connected_devices.connect(device4)
    device1.connected_devices.connect(device5)
    device1.connected_devices.connect(device6)

    device1.communicates_to.connect(internet, {'complexity': 'Low', 'privilege_needed': 'None'})
    device2.communicates_to.connect(device1, {'complexity': 'Low', 'privilege_needed': 'None'})
    device3.communicates_to.connect(device2, {'complexity': 'Low', 'privilege_needed': 'None'})
    device4.communicates_to.connect(device3, {'complexity': 'Low', 'privilege_needed': 'None'})
    device5.communicates_to.connect(device4, {'complexity': 'Low', 'privilege_needed': 'None'})
    device6.communicates_to.connect(device5, {'complexity': 'Low', 'privilege_needed': 'None'})

    internet.communicates_to.connect(device1, {'complexity': 'Low', 'privilege_needed': 'None'})
    device1.communicates_to.connect(device2, {'complexity': 'Low', 'privilege_needed': 'High'})
    device2.communicates_to.connect(device3, {'complexity': 'Low', 'privilege_needed': 'None'})
    device3.communicates_to.connect(device4, {'complexity': 'Low', 'privilege_needed': 'Low'})
    device4.communicates_to.connect(device5, {'complexity': 'Low', 'privilege_needed': 'None'})
    device5.communicates_to.connect(device6, {'complexity': 'Low', 'privilege_needed': 'None'})

    device6 = cve_updater.update_cvss(device6)
    print(device6.cve.cvss.__dict__)

    internet.delete()
    device1.delete()
    device2.delete()
    device3.delete()
    device4.delete()
    device5.delete()
    device6.delete()
