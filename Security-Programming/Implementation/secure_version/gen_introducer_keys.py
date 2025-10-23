#!/usr/bin/env python3
"""
gen_introducer_keys.py
----------------------
Generate RSA-4096 keypairs for introducers and write introducers.yaml
compatible with server.py bootstrap flow.

Each introducer entry includes:
  - name
  - host
  - port
  - pubkey (base64url DER, no padding)

Keys are stored under .keys/introducers/ for clarity.

Author: GROUP 12
MEMBERS:  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

"""

import os, yaml
from pathlib import Path
from keys import load_or_create_keys, public_pem_to_der_b64url

# ---------------------------------------------------------------------
# CONFIG: define your introducers here
# ---------------------------------------------------------------------
INTRODUCERS = [
    {"name": "introducer1", "host": "127.0.0.1", "port": 9001},
    {"name": "introducer2", "host": "127.0.0.1", "port": 9002},
    {"name": "introducer3", "host": "127.0.0.1", "port": 9003},
]

KEYDIR = Path(".keys")
YAML_PATH = Path("introducers.yaml")

# ---------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------
def main():
    KEYDIR.mkdir(parents=True, exist_ok=True)
    yaml_entries = []

    for intro in INTRODUCERS:
        name = intro["name"]
        priv_pem, pub_pem = load_or_create_keys(name, keydir=str(KEYDIR))
        pub_b64u = public_pem_to_der_b64url(pub_pem)

        yaml_entries.append({
            "name": name,
            "host": intro["host"],
            "port": intro["port"],
            "pubkey": pub_b64u,
        })
        print(f"✅ Created/loaded introducer {name} at {intro['host']}:{intro['port']}")
        print(f"   → .keys/introducers/{name}.priv.pem / {name}.pub.pem")

    with open(YAML_PATH, "w") as f:
        yaml.safe_dump(yaml_entries, f, sort_keys=False)

    print(f"\n📄 introducers.yaml written successfully ({len(yaml_entries)} entries).")
    print(f"   Path: {YAML_PATH.resolve()}")

# ---------------------------------------------------------------------
if __name__ == "__main__":
    main()
