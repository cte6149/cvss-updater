import json

from neo4j.v1 import GraphDatabase, basic_auth

import cve_updater

#driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "admin"))

centralities = {}


def find_cves():
    pass


if __name__ == "__main__":
    print("Testing Connection")

    internet = cve_updater.Internet()
    internet.name = "The Internet"

    internet.save()

    device1 = cve_updater.Device()
    device1.name = "Test Device 1"
    device1.save()

    device1.internet.connect(internet)

    device2 = cve_updater.Device()
    device2.name = "Test Device 2"
    device2.save()

    device3 = cve_updater.Device()
    device3.name = "Test Device 3"
    device3.save()

    device4 = cve_updater.Device()
    device4.name = "Test Device 4"
    device4.save()

    device5 = cve_updater.Device()
    device5.name = "Test Device 5"
    device5.save()

    device6 = cve_updater.Device()
    device6.name = "Test Device 6"
    cve = cve_updater.CVE()
    cve.name = "Some CVE"
    cvss = cve_updater.CVSS()
    cvss.attack_vector = "Network"
    cve.cvss = cvss
    device6.cve = cve
    device6.save()

    test = cve_updater.Device.nodes.get(name="Test Device 6")

    device1.devices.connect(device2)
    device2.devices.connect(device3)
    device2.devices.connect(device4)
    device3.devices.connect(device5)
    device3.devices.connect(device6)
    # device6.devices.connect(device2)

    print(device1.internet.is_connected(internet))

    # Modified attack vector
    modified_attack_vector = cve_updater.calculate_modified_attack_vector(device6)
    cvss = device6.cve.cvss
    cvss.modified_attack_vector = modified_attack_vector

    cve = device6.cve
    cve.cvss = cvss
    device6.cve = cve

    device6.save()
    ###

    internet.delete()
    device1.delete()
    device2.delete()
    device3.delete()
    device4.delete()
    device5.delete()
    device6.delete()
