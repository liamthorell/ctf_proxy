import json
import os
services = json.load(open("services.json", "r"))

"""     {"ip": vm_ip, "port": 9876, "name": "cc_market"},
    {"ip": vm_ip, "port": 80, "name": "maze"},
    {"ip": vm_ip, "port": 8080, "name": "scadent"},
    {"ip": vm_ip, "port": 5000, "name": "starchaser"},
    {"ip": vm_ip, "port": 1883, "name": "scadnet_bin"}, """

def get_str(servs):

    s = """
    services = ["""

    for s in servs.keys():
        s += """
        {"ip": vm_ip, "port": """ + str(servs[s]) + """, "name": \"""" + s + """\"},"""

    s += """{"ip": vm_ip, "port": -1, "name": "other"}
    ]
    """


servs = {}

for s in services.keys():
    srv = services[s]
    for i in range(srv["containers"].len()):
        sr = srv["containers"][i]
        name = srv["name"] + "_" + str(i)
        port = sr["listen_port"]

        servs[name] = port
    

print(get_str(servs))