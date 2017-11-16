
def _calculate_modified_attack_vector(node):

    cve = node.cve
    cvss = cve.cvss
    mav_accepted = False
    modified_attack_vector = cvss.attack_vector

    while not mav_accepted:
        if modified_attack_vector.lower() == "local" or modified_attack_vector.lower == "physical":
            mav_accepted = True
        elif modified_attack_vector.lower() == "adjacent network":
            if len(node.connected_devices.all()) == 0:
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
def _calculate_modified_attack_complexity(node):

    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_complexity_neighbors = set()

            for neighbor in device.receives_communications_from.all():
                relationship = device.receives_communications_from.relationship(neighbor)
                if relationship.complexity == 'Low':
                    if neighbor.type == 'INTERNET':
                        return 'Low'
                    low_complexity_neighbors.add(neighbor)

            queue.extend(low_complexity_neighbors - visited)
    return 'High'


def _path_with_no_privileges_to_internet(node):
    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_privileges = set()

            for neighbor in device.receives_communications_from.all():
                relationship = device.receives_communications_from.relationship(neighbor)
                if relationship.privilege_needed == 'None':
                    if neighbor.type == 'INTERNET':
                        return True
                    low_privileges.add(neighbor)

            queue.extend(low_privileges - visited)
    return False


def _path_with_low_or_no_privileges_to_internet(node):
    visited, queue = set(), [node]
    while queue:
        device = queue.pop(0)

        if device not in visited:
            visited.add(device)

            low_complexity_neighbors = set()

            for neighbor in device.receives_communications_from.all():
                relationship = device.receives_communications_from.relationship(neighbor)
                if relationship.privilege_needed in ['None', 'Low']:
                    if neighbor.type == 'INTERNET':
                        return True
                    low_complexity_neighbors.add(neighbor)

            queue.extend(low_complexity_neighbors - visited)
    return False


def _calculate_modified_privileges_required(node):
    if _path_with_no_privileges_to_internet(node):
        return "None"
    elif _path_with_low_or_no_privileges_to_internet(node):
        return "Low"
    return 'High'


def _calculate_modified_user_interaction(node):
    return node.cve.cvss.user_interaction


def _calculate_modified_scope(node):
    return node.cve.cvss.scope


def _calculate_modified_confidentiality(node):
    return node.cve.cvss.confidentiality


def _calculate_modified_impact(node):
    return node.cve.cvss.impact


def _calculate_modified_availability(node):
    return node.cve.cvss.availability


def update_cvss(node):
    print('Updating cvss')
    cve = node.cve
    cvss = cve.cvss

    cvss.modified_attack_vector = _calculate_modified_attack_vector(node)
    cvss.modified_attack_complexity = _calculate_modified_attack_complexity(node)
    cvss.modified_privileges_required = _calculate_modified_privileges_required(node)
    cvss.modified_user_interaction = _calculate_modified_user_interaction(node)
    cvss.modified_scope = _calculate_modified_scope(node)
    cvss.modified_confidentiality = _calculate_modified_confidentiality(node)
    cvss.modified_impact = _calculate_modified_impact(node)
    cvss.modified_availability = _calculate_modified_availability(node)

    cve.cvss = cvss
    node.cve = cve
    node.save()

    return node
