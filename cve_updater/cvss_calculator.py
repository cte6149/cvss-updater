
def calculate_modified_attack_vector(node):

    cve = node.cve
    cvss = cve.cvss
    mav_accepted = False
    modified_attack_vector = cvss.attack_vector

    while not mav_accepted:
        if modified_attack_vector.lower() == "local" or modified_attack_vector.lower == "physical":
            mav_accepted = True
        elif modified_attack_vector.lower() == "adjacent network":
            if len(node.devices.all()) == 0:
                modified_attack_vector = "Local"
            else:
                mav_accepted = True
        elif modified_attack_vector.lower() == "network":
            if node.is_connected_to_internet():
                mav_accepted = True
            else:
                modified_attack_vector = "Adjacent Network"

    return modified_attack_vector


# traverse the network to find a path with the lowest privilege
def calculate_attack_complexity(network_graph, cve):
    pass


def calculate_privileges_required(network_graph, cve):
    pass


def calculate_user_interaction(network_graph, cve):
    return cve.cvss.user_interaction_base


def calculate_scope(network_graph, cve):
    return cve.cvss.scope_base


def calculate_confidentiality(network_graph, cve):
    pass


def calculate_impact(network_graph, cve):
    pass


def calculate_availability(network_graph, cve):
    pass

