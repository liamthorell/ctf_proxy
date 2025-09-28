#!/usr/bin/python3

"""
CTF Proxy Setup Script

This script automates the setup and management of CTF services through a reverse proxy.

Usage:
  python proxy_cli.py SETUP [service_dirs...]     - Set up proxy for specified services
  python proxy_cli.py SETUP                       - Interactive setup (scan for services)
  python proxy_cli.py RESTART                     - Restart all configured services
  python proxy_cli.py REMOVE                      - Remove all services and restore backups
  python proxy_cli.py REMOVE_SERVICE <name>       - Remove specific service from proxy
  python proxy_cli.py LIST                        - List all configured services
  python proxy_cli.py TULIP                       - Export services in Tulip format
  python proxy_cli.py HELP                        - Show this help message

Examples:
  python proxy_cli.py SETUP                       # Interactive setup
  python proxy_cli.py SETUP ./service1 ./service2 # Setup specific services
  python proxy_cli.py REMOVE_SERVICE web1         # Remove 'web1' service from proxy
  python proxy_cli.py LIST                        # Show all configured services
"""

import os
import sys
import json
import shutil
import subprocess
import time

from pathlib import Path, PosixPath

import ruamel.yaml  # pip install ruamel.yaml

"""
Why not just use the included yaml package?
Because this one preservs order and comments (and also allows adding them)
"""

blacklist = ["remote_pcap_folder", "caronte", "tulip", "ctf_proxy", "snht"]

yaml = ruamel.yaml.YAML()
yaml.preserve_quotes = True
yaml.indent(sequence=3, offset=1)

dirs: list[PosixPath] = []
services_dict = {}


class WrongArgument(Exception):
    pass


def parse_dirs():
    """
    If the user provided arguments use them as paths to find the services.
    If not, iterate through the directories and ask for confirmation
    """
    global dirs

    # Get arguments after SETUP or RESTART command
    setup_args = []
    if "SETUP" in sys.argv:
        setup_index = sys.argv.index("SETUP")
        setup_args = sys.argv[setup_index + 1 :]
    elif "RESTART" in sys.argv:
        restart_index = sys.argv.index("RESTART")
        setup_args = sys.argv[restart_index + 1 :]

    if setup_args:
        for dir in setup_args:
            d = Path(dir)
            if not d.exists():
                raise WrongArgument(f"The path {dir} doesn't exist")
            if not d.is_dir():
                raise WrongArgument(f"The path {dir} is not a directory")
            dirs.append(d)
    else:
        print(f"No arguments were provided; automatically scanning for services.")
        for file in Path(".").iterdir():
            if file.is_dir() and file.stem[0] != "." and file.stem not in blacklist:
                if "y" in input(f"Is {file.stem} a service? [y/N] "):
                    dirs.append(Path(".", file))


def make_backup():
    global dirs

    for dir in dirs:
        if not Path(dir.name + f"_backup.zip").exists():
            shutil.make_archive(dir.name + f"_backup", "zip", dir)


def parse_services():
    """
    If services.json is present, load it into the global dictionary.
    Otherwise, parse all the docker-compose yamls to build the dictionary and
    then save the result into services.json
    """
    global services_dict, dirs

    if not dirs:
        print("[!] CRITICAL ERROR: No service directories found to parse")
        print("Cannot continue without any services. Exiting...")
        exit(1)

    for service in dirs:
        file = Path(service, "docker-compose.yml")
        if not file.exists():
            file = Path(service, "docker-compose.yaml")

        if not file.exists():
            print(f"[!] Error: No docker-compose file found in {service}")
            continue

        try:
            with open(file, "r") as fs:
                ymlfile = yaml.load(file)
        except Exception as e:
            print(f"[!] Error parsing YAML file {file}: {e}")
            continue

        if not ymlfile or "services" not in ymlfile:
            print(f"[!] Error: No services section found in {file}")
            continue

        # Check if the service has complex network configuration that would conflict
        if "networks" in ymlfile:
            networks = ymlfile["networks"]
            # Allow simple default network renaming, but skip complex configurations
            if (
                len(networks) == 1
                and "default" in networks
                and len(networks["default"]) <= 2
                and all(
                    key in ["name", "external"] for key in networks["default"].keys()
                )
            ):
                print(
                    f"[+] Service {service.stem} has simple default network configuration - will be replaced with ctf_proxy network"
                )
            else:
                print(
                    f"[!] Warning: Service {service.stem} has complex network configuration - skipping import"
                )
                print(
                    "    Services with custom networks may conflict with ctf_proxy setup"
                )
                continue

        services_dict[service.stem] = {"path": str(service.resolve()), "containers": {}}

        for container in ymlfile["services"]:
            try:
                if "ports" not in ymlfile["services"][container]:
                    print(f"{service.stem}_{container} has no ports binding")
                    continue

                ports_string = ymlfile["services"][container]["ports"]

                # Handle both list and string formats
                if isinstance(ports_string, list):
                    ports_list = []
                    for p in ports_string:
                        if isinstance(p, str) and ":" in p:
                            ports_list.append(p.split(":"))
                        else:
                            print(
                                f"[!] Warning: Invalid port format in {service.stem}_{container}: {p}"
                            )
                            continue
                else:
                    print(
                        f"[!] Error: Ports should be a list in {service.stem}_{container}"
                    )
                    continue

                if not ports_list:
                    print(f"{service.stem}_{container} has no valid port bindings")
                    continue

                http = []
                for port in ports_list:
                    if len(port) < 2:
                        print(
                            f"[!] Warning: Invalid port mapping {port} in {service.stem}"
                        )
                        continue
                    http.append(
                        True
                        if "y"
                        in input(
                            f"Is the service {service.stem}:{port[-2]} http? [y/N] "
                        )
                        else False
                    )

                container_dict = {
                    "target_port": [p[-1] for p in ports_list if len(p) >= 2],
                    "listen_port": [p[-2] for p in ports_list if len(p) >= 2],
                    "http": [h for h in http],
                }
                services_dict[service.stem]["containers"][container] = container_dict

            except KeyError as e:
                print(f"{service.stem}_{container} configuration error: {e}")
            except Exception as e:
                print(f"[!] Error processing {service.stem}_{container}: {e}")
                continue

        with open("services.json", "w") as backupfile:
            json.dump(services_dict, backupfile, indent=2)

    if not services_dict:
        print("[!] CRITICAL ERROR: No valid services were found or parsed")
        print("Cannot proceed without any configured services. Exiting...")
        exit(1)

    print("Found services:")
    for service in services_dict:
        print(f"\t{service}")


def edit_services():
    """
    Prepare the docker-compose for each service; comment out the ports, add hostname, add the external network, add an external volume for data persistence (this alone isn't enough - it' s just for convenience since we are already here)
    """
    global services_dict

    # Only edit the specified service if dirs is set, else all
    services_to_edit = [d.stem for d in dirs] if dirs else list(services_dict.keys())
    for service in services_to_edit:
        file = Path(services_dict[service]["path"], "docker-compose.yml")
        if not file.exists():
            file = Path(services_dict[service]["path"], "docker-compose.yaml")

        # Create backup of docker-compose file before editing
        backup_file = file.with_suffix(file.suffix + ".backup")
        if not backup_file.exists():
            shutil.copy2(file, backup_file)
            print(f"Created backup: {backup_file}")

        with open(file, "r") as fs:
            ymlfile = yaml.load(file)

        for container in services_dict[service]["containers"]:
            try:
                # Add a comment with the ports
                target_ports = services_dict[service]["containers"][container][
                    "target_port"
                ]
                listen_ports = services_dict[service]["containers"][container][
                    "listen_port"
                ]
                ports_string = "ports: "
                for target, listen in zip(target_ports, listen_ports):
                    ports_string += f"- {listen}:{target} "

                ymlfile["services"].yaml_add_eol_comment(ports_string, container)

                # Remove the actual port bindings
                try:
                    ymlfile["services"][container].pop("ports")
                except KeyError:
                    pass  # this means we had already had removed them

                # Add hostname
                hostname = f"{service}_{container}"
                if "hostname" in ymlfile["services"][container]:
                    print(
                        f"[!] Error: service {service}_{container} already has a hostname. Skipping this step, review it manually before restarting."
                    )
                else:
                    ymlfile["services"][container]["hostname"] = hostname

            except Exception as e:
                json.dump(ymlfile, sys.stdout, indent=2)
                print(f"\n{container = }")
                raise e

            # TODO: Add restart: always

            # add external network
            net = {"default": {"name": "ctf_network", "external": True}}
            if "networks" in ymlfile:
                # Check if it's just a simple default network that we can replace
                networks = ymlfile["networks"]
                if (
                    len(networks) == 1
                    and "default" in networks
                    and len(networks["default"]) <= 2
                    and all(
                        key in ["name", "external"]
                        for key in networks["default"].keys()
                    )
                ):
                    print(
                        f"[+] Replacing simple default network configuration in {service}"
                    )
                    ymlfile["networks"] = net
                elif "default" not in ymlfile["networks"]:
                    try:
                        ymlfile["networks"].update(net)
                    except:
                        ymlfile["networks"]["default"] = net["default"]
                else:
                    print(
                        f"[!] Error: service {service} already has a default network. Skipping this step, review it manually before restarting."
                    )
            else:
                ymlfile["networks"] = net

            # write file
            with open(file, "w") as fs:
                yaml.dump(ymlfile, fs)


def configure_proxy():
    """
    Properly configure both the proxy's docker-compose with the listening ports and the config.json with all the services.
    We can't automatically configure ssl for now, so it's better to set https services as not http so they keep working at least. Manually configure the SSL later and turn http back on.
    """
    # Download ctf_proxy
    if not Path("./ctf_proxy").exists():
        print("Cloning ctf_proxy repository...")
        result = os.system("git clone https://github.com/liamthorell/ctf_proxy.git")
        if result != 0:
            print("[!] CRITICAL ERROR: Failed to clone ctf_proxy repository")
            print("Cannot continue without ctf_proxy. Exiting...")
            exit(1)

        for _ in range(50):
            if Path("./ctf_proxy/docker-compose.yml").exists():
                break
            time.sleep(0.2)
        else:
            print("[!] CRITICAL ERROR: ctf_proxy directory did not appear after clone")
            exit(1)

    compose_file = Path("./ctf_proxy/docker-compose.yml")
    if not compose_file.exists():
        print("[!] CRITICAL ERROR: ctf_proxy docker-compose.yml not found after clone")
        print("This indicates a broken ctf_proxy installation. Exiting...")
        exit(1)

    try:
        with open(compose_file, "r") as file:
            ymlfile = yaml.load(file)
    except Exception as e:
        print(f"[!] CRITICAL ERROR: Cannot read ctf_proxy docker-compose.yml: {e}")
        print("This file is essential for the proxy setup. Exiting...")
        exit(1)

    ports = []
    for service in services_dict.keys():
        for container in services_dict[service]["containers"]:
            for port in services_dict[service]["containers"][container]["listen_port"]:
                ports.append(f"{port}:{port}")

    if "services" not in ymlfile or "nginx" not in ymlfile["services"]:
        print("[!] CRITICAL ERROR: Invalid ctf_proxy docker-compose structure")
        print(
            "Missing 'services' section or 'nginx' service. Cannot configure proxy. Exiting..."
        )
        exit(1)

    ymlfile["services"]["nginx"]["ports"] = ports

    try:
        with open(compose_file, "w") as fs:
            yaml.dump(ymlfile, fs)
    except Exception as e:
        print(f"[!] CRITICAL ERROR: Cannot write ctf_proxy docker-compose.yml: {e}")
        print("Cannot save proxy configuration. Exiting...")
        exit(1)

    # Proxy config.json
    print("Remember to manually edit the config for SSL")
    services = []
    for service in services_dict.keys():
        for container in services_dict[service]["containers"]:
            name = f"{service}_{container}"
            target_ports = services_dict[service]["containers"][container][
                "target_port"
            ]
            listen_ports = services_dict[service]["containers"][container][
                "listen_port"
            ]
            http = services_dict[service]["containers"][container]["http"]
            for i, (target, listen) in enumerate(zip(target_ports, listen_ports)):
                try:
                    target_int = int(target)
                    listen_int = int(listen)
                except ValueError:
                    print(
                        f"[!] Warning: Invalid port numbers for {name}: {target}:{listen}"
                    )
                    continue

                services.append(
                    {
                        "name": name + str(i),
                        "target_ip": name,
                        "target_port": target_int,
                        "listen_port": listen_int,
                        "http": http[i] if i < len(http) else False,
                    }
                )

    config_file = Path("./ctf_proxy/proxy/config/config.json")
    if not config_file.exists():
        print("[!] CRITICAL ERROR: ctf_proxy config.json not found")
        print("Cannot configure proxy services without config file. Exiting...")
        exit(1)

    try:
        with open(config_file, "r") as fs:
            proxy_config = json.load(fs)
    except Exception as e:
        print(f"[!] CRITICAL ERROR: Cannot read ctf_proxy config.json: {e}")
        print("Cannot load proxy configuration. Exiting...")
        exit(1)

    proxy_config["services"] = services

    try:
        with open(config_file, "w") as fs:
            json.dump(proxy_config, fs, indent=2)
    except Exception as e:
        print(f"[!] CRITICAL ERROR: Cannot write ctf_proxy config.json: {e}")
        print("Cannot save proxy service configuration. Exiting...")
        exit(1)


def restart_services():
    """
    Make sure every service is off and then start them one by one after the proxy
    """

    # Only restart the specified service if dirs is set, else all
    services_to_restart = [d.stem for d in dirs] if dirs else list(services_dict.keys())

    # Stop all services in parallel
    down_procs = []
    for service in services_to_restart:
        cmd = f"bash -c '!(docker compose --file {services_dict[service]['path']}/docker-compose.yml down) && docker compose --file {services_dict[service]['path']}/docker-compose.yaml down'"
        down_procs.append(subprocess.Popen(cmd, shell=True))
    for proc in down_procs:
        proc.wait()

    # Restart proxy
    os.system(
        f"bash -c 'docker compose --file ctf_proxy/docker-compose.yml restart; docker compose --file ctf_proxy/docker-compose.yml up -d'"
    )

    # Start all services in parallel
    up_procs = []
    for service in services_to_restart:
        cmd = f"bash -c '!(docker compose --file {services_dict[service]['path']}/docker-compose.yml up -d) && docker compose --file {services_dict[service]['path']}/docker-compose.yaml up -d'"
        up_procs.append(subprocess.Popen(cmd, shell=True))
    for proc in up_procs:
        proc.wait()


def remove_all():
    """
    Removes everything
    """

    confirm = input(
        "Are you sure you want to remove all services and restore backups? [y/N] "
    )
    if confirm.lower() != "y":
        print("Aborting removal process.")
        exit(0)

    if not Path("./services.json").exists():
        print("[!] Error: services.json not found. Cannot proceed with removal.")
        exit(1)

    if not Path("./ctf_proxy").exists():
        print(
            "[!] Error: ctf_proxy directory not found. Are you in the correct directory?"
        )
        exit(1)

    with open("./services.json", "r") as fs:
        services = json.load(fs)

    input("Make sure unzip is installed. Press Enter to continue...")

    # Stop ctf_proxy - check for both yml and yaml
    ctf_compose_file = None
    if Path("./ctf_proxy/docker-compose.yml").exists():
        ctf_compose_file = "./ctf_proxy/docker-compose.yml"
    elif Path("./ctf_proxy/docker-compose.yaml").exists():
        ctf_compose_file = "./ctf_proxy/docker-compose.yaml"

    if ctf_compose_file:
        os.system(f"docker compose -f {ctf_compose_file} down")

    # Restore services from backups
    for service_name in services.keys():
        srv = services[service_name]
        path = srv["path"]
        backup_file = path + "_backup.zip"

        if not Path(backup_file).exists():
            print(
                f"[!] Warning: Backup file {backup_file} not found, skipping {service_name}"
            )
            continue

        print(f"Restoring {service_name} from backup...")
        os.system(f"rm -rf {path}")
        os.system(f"mkdir -p {path}")
        os.system(f"unzip {backup_file} -d {path}")

        # Find and start the service - check for both yml and yaml
        service_compose_file = None
        if Path(f"{path}/docker-compose.yml").exists():
            service_compose_file = f"{path}/docker-compose.yml"
        elif Path(f"{path}/docker-compose.yaml").exists():
            service_compose_file = f"{path}/docker-compose.yaml"

        if service_compose_file:
            os.system(f"docker compose -f {service_compose_file} up -d")
        else:
            print(f"[!] Warning: No docker-compose file found for {service_name}")

    print("You can now remove services.json and ./ctf_proxy")
    confirmation = input("Do you want to remove those automatically? (y/N): ")
    if confirmation.lower() == "y":
        os.system("rm -rf ./ctf_proxy")
        os.system("rm -f ./services.json")


def tulip_export():
    """
    Export services in Tulip format
    """
    if not Path("./services.json").exists():
        print("[!] Error: services.json not found. Cannot proceed with Tulip export.")
        exit(1)

    with open("./services.json", "r") as fs:
        services = json.load(fs)

    servs = {}
    for service_name in services.keys():
        srv = services[service_name]
        containers = srv["containers"]

        for container_name in containers.keys():
            container = containers[container_name]
            listen_ports = container["listen_port"]

            # Handle multiple ports per container
            for i, port in enumerate(listen_ports):
                name = f"{service_name}_{container_name}"
                if len(listen_ports) > 1:
                    name += f"_{i}"
                servs[name] = port

    s = """
services = ["""
    for service_name in servs.keys():
        s += f"""
{{"ip": vm_ip, "port": {servs[service_name]}, "name": "{service_name}"}},"""

    s += """
{"ip": vm_ip, "port": -1, "name": "other"}
]
    """
    print(s)


def remove_service(service_name):
    """
    Remove a specific service from the proxy setup with minimal downtime.

    Steps:
    1. Prepare updated ctf_proxy configuration without the service ports
    2. Restore the service's original docker-compose from backup
    3. Restart both proxy and service simultaneously to minimize downtime
    """
    global services_dict

    if not services_dict:
        print(
            "[!] Error: No services configuration found. Please run the script first with SETUP to set up services."
        )
        return False

    if service_name not in services_dict:
        print(f"[!] Error: Service '{service_name}' not found in configuration.")
        print(f"Available services: {list(services_dict.keys())}")
        return False

    service_info = services_dict[service_name]
    service_path = service_info["path"]
    backup_file = service_name + "_backup.zip"

    if not Path(backup_file).exists():
        print(
            f"[!] Error: Backup file '{backup_file}' not found. Cannot restore service."
        )
        return False

    print(f"Removing service: {service_name}")

    # Step 1: Update ctf_proxy configuration to remove service ports
    print("Updating ctf_proxy configuration...")

    # Get ports to remove from this service
    ports_to_remove = []
    for container in service_info["containers"]:
        for port in service_info["containers"][container]["listen_port"]:
            ports_to_remove.append(f"{port}:{port}")

    # Update ctf_proxy docker-compose.yml
    compose_file = Path("./ctf_proxy/docker-compose.yml")
    if not compose_file.exists():
        print("[!] Error: ctf_proxy docker-compose.yml not found")
        return False

    try:
        with open(compose_file, "r") as file:
            ymlfile = yaml.load(file)

        # Remove ports for this service
        current_ports = ymlfile["services"]["nginx"]["ports"]
        updated_ports = [port for port in current_ports if port not in ports_to_remove]
        ymlfile["services"]["nginx"]["ports"] = updated_ports

        with open(compose_file, "w") as fs:
            yaml.dump(ymlfile, fs)

    except Exception as e:
        print(f"[!] Error updating ctf_proxy docker-compose.yml: {e}")
        return False

    # Update ctf_proxy config.json
    config_file = Path("./ctf_proxy/proxy/config/config.json")
    if config_file.exists():
        try:
            with open(config_file, "r") as fs:
                proxy_config = json.load(fs)

            # Remove services belonging to this service
            original_services = proxy_config.get("services", [])
            updated_services = []

            for svc in original_services:
                # Check if this service belongs to the service we're removing
                service_belongs_to_removed = False
                for container in service_info["containers"]:
                    container_name = f"{service_name}_{container}"
                    if svc.get("target_ip", "").startswith(container_name):
                        service_belongs_to_removed = True
                        break

                if not service_belongs_to_removed:
                    updated_services.append(svc)

            proxy_config["services"] = updated_services

            with open(config_file, "w") as fs:
                json.dump(proxy_config, fs, indent=2)

        except Exception as e:
            print(f"[!] Warning: Could not update ctf_proxy config.json: {e}")

    # Step 2: Prepare service restoration
    print(f"Restoring {service_name} from backup...")

    # Step 3: Coordinate restart to minimize downtime
    print("Coordinating restart to minimize downtime...")

    try:
        compose_yml_backup = Path(service_path) / "docker-compose.yml.backup"
        compose_yaml_backup = Path(service_path) / "docker-compose.yaml.backup"
        restored = False
        if compose_yml_backup.exists():
            shutil.copy2(compose_yml_backup, Path(service_path) / "docker-compose.yml")
            compose_yml_backup.unlink(missing_ok=True)
            restored = True
        if compose_yaml_backup.exists():
            shutil.copy2(
                compose_yaml_backup, Path(service_path) / "docker-compose.yaml"
            )
            compose_yaml_backup.unlink(missing_ok=True)
            restored = True
        if not restored:
            print(
                f"[!] Error: No docker-compose backup file found in {service_path} for {service_name}"
            )
            return False

        # Start proxy first, then service synchronously
        os.system(
            "docker compose --file ctf_proxy/docker-compose.yml up -d --force-recreate"
        )

        if Path(f"{service_path}/docker-compose.yml").exists():
            os.system(
                f"docker compose --file {service_path}/docker-compose.yml up -d --force-recreate"
            )
        elif Path(f"{service_path}/docker-compose.yaml").exists():
            os.system(
                f"docker compose --file {service_path}/docker-compose.yaml up -d --force-recreate"
            )

        # Remove service from services_dict and update services.json
        del services_dict[service_name]
        with open("services.json", "w") as backupfile:
            json.dump(services_dict, backupfile, indent=2)

        print(f"Successfully removed service: {service_name}")
        print(f"Service restored to original configuration and restarted")
        return True

    except Exception as e:
        print(f"[!] Error during service removal: {e}")
        return False


def setup_services():
    """
    Main setup functionality - parse directories, services, create backups,
    edit services, configure proxy, and restart everything.
    """
    parse_dirs()
    parse_services()
    make_backup()

    edit_services()
    configure_proxy()
    confirmation = input(
        "You are about to restart the selected services! Make sure that no catastrophic configuration error has occurred.\nPress Enter to continue"
    )
    restart_services()

    tulip = (
        input("Do you want to export the services in Tulip format? [y/N]: ")
        .strip()
        .lower()
    )
    if tulip == "y":
        tulip_export()


def main():
    global services_dict

    if Path(os.getcwd()).name == "ctf_proxy":
        os.chdir("..")

    if Path("./services.json").exists():
        print("Found existing services file")
        with open("./services.json", "r") as fs:
            services_dict = json.load(fs)

    # If no arguments provided, show error and help
    if len(sys.argv) == 1:
        print("[!] Error: No command specified.")
        print("Please specify a command. Available commands:")
        print()
        print(__doc__)
        return

    # Handle SETUP command
    if "SETUP" in sys.argv:
        setup_services()
        return

    if "RESTART" in sys.argv:
        # If a service name or path is provided, only restart that service
        restart_args = []
        restart_index = sys.argv.index("RESTART")
        restart_args = sys.argv[restart_index + 1 :]
        if not services_dict:
            print(
                "[!] Error: Can't restart without first parsing the services. Please run the script at least once with SETUP"
            )
            exit(1)
        if restart_args:
            # Set dirs to the specified service(s) for restart
            global dirs
            dirs = []
            for arg in restart_args:
                d = Path(arg)
                if not d.exists() or not d.is_dir():
                    print(
                        f"[!] Error: Provided path {arg} does not exist or is not a directory."
                    )
                    exit(1)
                dirs.append(d)
        restart_services()
        return

    if "REMOVE" in sys.argv:
        remove_all()
        return

    if "TULIP" in sys.argv:
        tulip_export()
        return

    # Handle REMOVE_SERVICE command
    if "REMOVE_SERVICE" in sys.argv:
        if not services_dict:
            print(
                "[!] Error: No services configuration found. Please run the script first with SETUP to set up services."
            )
            return

        # Find the service name argument
        service_name = None
        for i, arg in enumerate(sys.argv):
            if arg == "REMOVE_SERVICE" and i + 1 < len(sys.argv):
                service_name = sys.argv[i + 1]
                break

        if not service_name:
            print("[!] Error: Please specify a service name after REMOVE_SERVICE")
            print(f"Available services: {list(services_dict.keys())}")
            return

        if remove_service(service_name):
            print(f"Service '{service_name}' successfully removed from proxy setup.")
        else:
            print(f"Failed to remove service '{service_name}'.")
        return

    # Handle LIST command
    if "LIST" in sys.argv:
        if not services_dict:
            print(
                "No services configuration found. Run the script first with SETUP to set up services."
            )
            return

        print("Configured services:")
        for service_name, service_info in services_dict.items():
            print(f"  {service_name}")
            for container_name, container_info in service_info["containers"].items():
                ports = container_info["listen_port"]
                print(f"    └── {container_name}: ports {', '.join(ports)}")
        return

    # If we get here, an unrecognized command was provided
    print(f"[!] Error: Unknown command '{sys.argv[1]}'")
    print("Please use one of the available commands:")
    print()
    print(__doc__)


if __name__ == "__main__":
    # Display help for specific help requests
    if len(sys.argv) > 1:
        first_arg = sys.argv[1].upper()
        if first_arg in ["-H", "--HELP", "HELP"]:
            print(__doc__)
            exit(0)
        elif first_arg == "REMOVE_SERVICE" and len(sys.argv) < 3:
            print("Error: REMOVE_SERVICE requires a service name")
            print("Usage: python proxy_cli.py REMOVE_SERVICE <service_name>")
            print("Use 'python proxy_cli.py LIST' to see available services")
            exit(1)

    main()
