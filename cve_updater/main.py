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
        network = cve_updater.import_network(file_path)

        if network is not None:
            break

    network = cve_updater.update_cvss(network)

    print(network)
    for node in network:
        if node.cve is not None:
            print(node.cve.cvss.__dict__)
            print(node.cve.cvss.base_score)
            print(node.cve.cvss.environmental_score)


if __name__ == "__main__":
    main()