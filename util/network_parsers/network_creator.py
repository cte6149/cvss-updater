from util import import_network


def read_network_template(template_network):
    """Read the provided network template"""
    network_template = None

    with open(template_file, 'r') as f:
        network_template = import_network(f)
    return network_template


def select_random_machine_for_cve():
    """Select a random node to place the cve"""


def save_network():
    """Save network to network destination"""


def generate_random_cve_network(template_file):
    """Generate a network with a randomized CVE"""
    network_template = read_network_template(template_file)

    return network_template


def generate_random_communication_network():
    """Generate a network with a randomized CVE"""


if __name__ == '__main__':

    template_file = 'test/test_template.json'
    network_file = generate_random_cve_network(template_file)

