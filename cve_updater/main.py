import json
import cve_updater


def get_user_file():

    while True:
        print("Supported File Types: .json")
        file_path = input("Input network file to load: ")
        formatted_path = file_path.split(".")

        if len(formatted_path) == 2 and formatted_path[1] == "json":
            return file_path
        else:
            print("Unsupported File Type!\n")


def main():

    while True:
        file_path = get_user_file()
        connectivity_network, communication_network = cve_updater.import_network(file_path)

        if connectivity_network is not None and communication_network is not None:
            break

    cves = cve_updater.update_cvss(connectivity_network, communication_network)

    for node_id, cve in cves.items():
        print("Updated CVSS for Node: " + str(node_id))
        print('Base Score:', cve_updater.base_score(cve['cvss']))
        print('Environmental Score:', cve_updater.environmental_score(cve['cvss']))

        print(json.dumps(communication_network.nodes[node_id], sort_keys=False, indent=2))


if __name__ == "__main__":
    main()
