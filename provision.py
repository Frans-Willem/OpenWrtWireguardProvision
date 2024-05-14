import logging
from openwrt.ubus import Ubus
import ipaddress
import re
import subprocess
import os
import pprint
import qrcode

def get_default_gateway():
    import socket, struct
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def get_wan_address(ubus):
    network_interfaces = ubus.api_call("call", "network.interface", "dump", {})
    wan_interfaces = [interface for interface in network_interfaces['interface'] if interface['interface'] == "wan"]
    return wan_interfaces[0]["ipv4-address"][0]['address']

def get_lan_networks(ubus):
    network_interfaces = ubus.api_call("call", "network.interface", "dump", {})
    lan_interfaces = [interface for interface in network_interfaces['interface'] if interface['interface'] == "lan"]
    return [ipaddress.ip_network(address['address'] + "/" + str(address['mask']), strict=False) for lan_interface in lan_interfaces for address in lan_interface["ipv4-address"]]


def get_first_wg_interface(network_config):
    wg_interfaces = [value[".name"] for key, value in network_config.items() if value[".type"] == "interface" and value["proto"] == "wireguard"]
    return wg_interfaces[0]

def collect_wireguard_networks(wireguard_config):
    return [ipaddress.ip_network(address, strict=False) for address in wireguard_config["addresses"]]

def collect_wireguard_used_addresses(wireguard_config, wireguard_peers):
    own_addresses = [ipaddress.ip_network(re.sub("[%/][0-9]+$","",address)) for address in wireguard_config["addresses"]]
    peer_addresses = [ipaddress.ip_network(address) for cfg, peer in wireguard_peers.items() for address in peer["allowed_ips"]]
    return own_addresses + peer_addresses

def is_host_taken(host, taken_addresses):
    for address in taken_addresses:
        if host in address:
            return True
    return False

def first_free_host(all_networks, taken_addresses):
    for network in all_networks:
        for host in network.hosts():
            if not is_host_taken(host, taken_addresses):
                return host
    return None

def is_network_reachable(network, reachable_networks):
    for reachable_network in reachable_networks:
        if network.subnet_of(reachable_network):
            return True
    return False


def wg_genkey():
    return subprocess.run(["wg", "genkey"], check=True, capture_output=True).stdout.decode('utf-8').strip()

def wg_pubkey(privkey):
    return subprocess.run(["wg", "pubkey"], check=True, capture_output=True, input = privkey.encode('utf-8') + b"\n").stdout.decode('utf-8').strip()

def write_config_file(filename, address, private_key, peers):
    with open(filename, "w") as f:
        f.write("[Interface]\n")
        f.write("Address = " + str(ipaddress.ip_network(address)) + "\n")
        f.write("PrivateKey = " + private_key + "\n")
        for peer in peers:
            f.write("\n")
            f.write("[Peer]\n")
            f.write("PublicKey = " + peer["public_key"] + "\n")
            f.write("PresharedKey = " + peer["preshared_key"] + "\n")
            f.write("AllowedIPs = " + ", ".join([str(x) for x in peer["allowed_ips"]]) + "\n")
            f.write("Endpoint = " + ":".join([str(x) for x in peer["endpoint"]]) + "\n")
            f.write("PersistentKeepAlive = " + str(peer["persistent_keepalive"]) + "\n")

def generate_qr(config_filename, qr_filename):
    with open(config_filename, "r") as f:
        data = f.read()
    img = qrcode.make(data)
    img.save(qr_filename)


def main(openwrt = None, username="root", password="", external_address=None, wg_interface=None, description="New peer", conf_filename=None, persistent_keepalive=0, wg_address=None, add_lan_routes=False, add_peer_routes=False, replace=False, dry_run=False):
    # Set up defaults
    if openwrt is None:
        print("No OpenWRT IP specified, attempting to get default gateway")
        openwrt = get_default_gateway()

    ubus_uri = "http://" + openwrt + "/ubus/"
    print("Talking to UBUS:", ubus_uri)
    ubus = Ubus(ubus_uri, username, password)
    ubus.connect()

    if external_address is None:
        external_address = get_wan_address(ubus)
        print("Got external address from WAN interface:", external_address)

    network_config = ubus.api_call("call", "uci", "get", {"config": "network"})
    network_config = network_config["values"]

    if wg_interface is None:
        wg_interface = get_first_wg_interface(network_config)
        print("Got default wireguard interface from config:", wg_interface)

    if conf_filename is None:
        conf_filename = description + ".conf"
        print("Set default configuration filename to:", conf_filename)

    if os.path.exists(conf_filename):
        if replace:
            print("WARNING: Configuration file '" + conf_filename + "' will be overwritten")
        else:
            raise Exception("Configuration file '" + conf_filename + "' already exists, bailing out")

    wireguard_config = network_config[wg_interface]
    wireguard_peers = {key:value for key, value in network_config.items() if value['.type'] == "wireguard_"+wg_interface}
    all_networks = collect_wireguard_networks(wireguard_config)
    peer_allowed_ips = []

    previous_peers = {key: peer for key, peer in wireguard_peers.items() if peer["description"] == description}
    if len(previous_peers) > 0:
        previous_peer_key, previous_peer = list(previous_peers.items())[0]
        if not replace:
            raise Exception("Peer with this description already exists!")
        peer_allowed_ips = [ipaddress.ip_network(allowed_ip) for allowed_ip in previous_peer["allowed_ips"]]
        replace = previous_peer_key
        print("Replacing configuration:", replace)
    else:
        replace = None

    # Figure out which address to give this peer
    if wg_address is None:
        if len(peer_allowed_ips) > 0:
            wg_address = first_free_host(peer_allowed_ips, [])
            if wg_address is None:
                raise Exception('Unable to find a free IP address in peer_allowed_ips')
            print("Set Wireguard address for peer to previous value of:", wg_address)
        else:
            taken_addresses = collect_wireguard_used_addresses(wireguard_config, wireguard_peers)
            wg_address = first_free_host(all_networks, taken_addresses)
            if wg_address is None:
                raise Exception('Unable to find a free IP address in wireguard networks')
            print("Set Wireguard address for peer to default of:", wg_address)
    else:
        wg_address = ipaddress.ip_network(ipaddress.ip_address(wg_address))

    if not any((wg_address in allowed_ip) for allowed_ip in peer_allowed_ips):
        peer_allowed_ips.append(ipaddress.ip_network(wg_address))

    # Add LAN to allowed ips?
    server_allowed_ips = all_networks
    if add_lan_routes:
        server_allowed_ips = server_allowed_ips + get_lan_networks(ubus)

    # Add routes to peer networks
    if add_peer_routes:
        for _, peer in wireguard_peers.items():
            for allowed_ip in peer["allowed_ips"]:
                allowed_ip = ipaddress.ip_network(allowed_ip)
                if not is_network_reachable(allowed_ip, server_allowed_ips):
                    server_allowed_ips.append(allowed_ip)

    # Generate some keys
    private_key = wg_genkey()
    public_key = wg_pubkey(private_key)
    server_private_key = wireguard_config["private_key"]
    server_public_key = wg_pubkey(server_private_key)
    preshared_key = wg_genkey()


    # Write out configuration file
    write_config_file(conf_filename, wg_address, private_key, [{"public_key": server_public_key, "preshared_key": preshared_key, "allowed_ips": server_allowed_ips, "endpoint": [external_address, wireguard_config["listen_port"]], "persistent_keepalive": persistent_keepalive}])

    generate_qr(conf_filename, conf_filename+".png")

    if not dry_run:
        # Add or update section configuration
        section_values = {
            "description": description,
            "allowed_ips": [str(x) for x in peer_allowed_ips],
            "preshared_key": preshared_key,
            "public_key": public_key,
            "route_allowed_ips": "1"
        }
        if replace is None:
            response = ubus.api_call("call", "uci", "add", {"config": "network", "type": "wireguard_" + wg_interface, "values": section_values})
        else:
            response = ubus.api_call("call", "uci", "set", {"config": "network", "section": replace, "values": section_values})
        print("UCI add/set response:", response)

        response=ubus.api_call("call","uci","changes", {})
        print("Changes reponse:")
        pprint.pp(response)

        response = ubus.api_call("call", "uci", "apply", {"config": "network"})
        print("UCI apply response:", response)

        response = ubus.api_call("call", "file", "exec", {"command": "/sbin/ifup", "env": None, "params":[ wg_interface ]})
        print("Ifup response", response)

    return 0


if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description = "Provision new Wireguard Peer on OpenWRT")
    parser.add_argument("--openwrt", help="OpenWRT IP address, will use the default gateway (only works on Linux)")
    parser.add_argument("--username", help="OpenWRT Username", default="root")
    parser.add_argument("--password", help="OpenWRT Password")
    parser.add_argument("--external-address", help="External address to be used for Wireguard config, will use WAN address by default")
    parser.add_argument("--wg-interface", help="Wireguard interface, defaults to first found Wireguard config")
    parser.add_argument("--description", help="Description for new peer", required=True)
    parser.add_argument("--wg-address", help="Wireguard IP address for new peer, defaults to first free address in network")
    parser.add_argument("--persistent-keepalive", help="Persistent keepalive to set on client", default=25)
    parser.add_argument("--add-lan-routes", help="Add LAN networks to allowed_ips on peer", default=False, action='store_true')
    parser.add_argument("--add-peer-routes", help="Add routes to other peer networks to allowed_ips on peer", default=False, action='store_true')
    parser.add_argument("--dry-run", help="Do not write configuration to OpenWRT", default=False, action='store_true')
    parser.add_argument("--replace", help="Replace existing peer with same description, if it exists. IP address will be re-used, if not specified", default=False, action='store_true')
    args = parser.parse_args()
    sys.exit(main(**vars(args)))

sys.exit(1)
