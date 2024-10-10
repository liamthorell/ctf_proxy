import json
import os
services = json.load(open("services.json", "r"))

input("Make sure unzip is installed")

os.system("docker compose -f /root/ctf_proxy/docker-compose.* down")

for s in services.keys():
    srv = services[s]
    path = srv["path"]
    os.system(f"rm -rf {path}")
    os.system(f"mkdir {path}")
    os.system(f"unzip {path + "_backup.zip"} -d {path}")
    os.system(f"docker compose up --build -d")
    os.system(f"docker compose -f {path}/docker-compose.* up --build -d")

print("You can now remove services.json and ./ctf_proxy")