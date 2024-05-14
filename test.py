import logging
from openwrt.ubus import Ubus
import ipaddress
import re
import subprocess
import os
#logging.basicConfig(level=logging.DEBUG)

external_ip = "nope.nope.com"
conf_file = "test.conf"
ubus_uri = "http://192.168.0.1/ubus/"
ubus_username = "root"
ubus_password = "NOPENOPENOPE
wg_interface = "wg0"
requested_name = "Worklaptop"
persistent_keepalive = 25

"""
Calls available:
    luci.wireguard  getPublicAndPrivateKeyFromPrivate {"privkey": "XXX"}
    uci get {"config": "network"}
    uci set {"config": "network", "section": "cfg0c96fc", "values": {}}
    uci add {"config: "network", "type": "wireguard_wg0", "values": {"allowed_ips: [], "description": ..., "persistent_keepalive": 25, "preshared_key": ..., "public_key": .., "route_allowed_ips": "1"}
"""

ubus = Ubus(ubus_uri, ubus_username, ubus_password)
ubus.connect()
network_config = ubus.api_call("call", "uci", "get", {"config": "network"})
wireguard_config = network_config['values'][wg_interface]
peers = {key:value for key, value in network_config['values'].items() if value['.type'] == "wireguard_"+wg_interface}

# First, find an open IP address for the new peer
all_networks = [ipaddress.ip_network(address, strict=False) for address in wireguard_config["addresses"]]
own_addresses = [ipaddress.ip_network(re.sub("[%/][0-9]+$","",address)) for address in wireguard_config["addresses"]]
peer_addresses = [ipaddress.ip_network(address) for cfg, peer in peers.items() for address in peer["allowed_ips"]]
taken_addresses = own_addresses + peer_addresses

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

ip_address = first_free_host(all_networks, taken_addresses)
print("IP address:", ip_address)

private_key = subprocess.run(["wg", "genkey"], check=True, capture_output=True).stdout.decode('utf-8').strip()
preshared_key = subprocess.run(["wg", "genkey"], check=True, capture_output=True).stdout.decode('utf-8').strip()
print("Private key", private_key)
print("Preshared key", preshared_key)

public_key = subprocess.run(["wg", "pubkey"], check=True, capture_output=True, input=private_key.encode('utf-8') + b"\n").stdout.decode('utf-8').strip()
print("Public key", public_key)
server_public_key = subprocess.run(["wg", "pubkey"], check=True, capture_output=True, input=wireguard_config["private_key"].encode('utf-8') + b"\n").stdout.decode('utf-8').strip()
print("Server public key", server_public_key)

if os.path.exists(conf_file):
    raise Exception('Configuration file already exists, bailing out')

# Write out local config file
with open(conf_file, "w") as f:
    f.write("[Interface]\n")
    f.write("Address = " + str(ipaddress.ip_network(ip_address)) + "\n")
    f.write("PrivateKey = " + private_key + "\n")
    f.write("\n")
    f.write("[Peer]\n")
    f.write("PublicKey = " + server_public_key + "\n")
    f.write("PresharedKey = " + preshared_key + "\n")
    f.write("AllowedIPs = " + ", ".join([str(x) for x in all_networks]) + "\n")
    f.write("Endpoint = " + external_ip + ":" + wireguard_config["listen_port"] + "\n")
    f.write("PersistentKeepAlive = " + str(persistent_keepalive) + "\n")

# Write out OpenWRT config
response = ubus.api_call("call", "uci", "add", {"config": "network", "type": "wireguard_" + wg_interface, "values": {"allowed_ips": [str(ipaddress.ip_network(ip_address))], "description": requested_name, "preshared_key": preshared_key, "public_key": public_key, "route_allowed_ips": "1"}})
print("Response add:", response)
response = ubus.api_call("call", "uci", "apply", {"config": "network"})
print("Response apply", response)
response = ubus.api_call("call", "file", "exec", {"command": "/sbin/ifup", "env": None, "params":[ wg_interface ]})
print("Response reload", response)
