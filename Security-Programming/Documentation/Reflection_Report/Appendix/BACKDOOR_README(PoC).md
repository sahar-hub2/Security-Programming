# Quarantine: Backdoor PoCs and Instructions

**Repository / Folder:** `quarantine/`

**Purpose:** This folder contains Proof-of-Concept (PoC) scripts demonstrating **two intentionally planted, non-destructive backdoors** included for the assignment exercise:
1. **Weak key acceptance** — the server/client will accept or generate weak RSA-1024 keys while claiming RSA-4096.
2. **Unsigned gossip acceptance** — the server will accept `USER_ADVERTISE` messages even if they are unsigned or the signature is invalid.

> ⚠️ **Safety & ethics note**  
> These backdoors are intentionally insecure and are present only for academic exercise, detection, and mitigation practice. Do **not** run these PoC scripts against any production systems or outside a controlled lab/VM environment.

---

## How to enable the backdoors (local testing only)

**1) Weak keys backdoor**
- This PoC assumes you applied the `keys.py` backdoor snippet which checks `BACKDOOR_WEAK_KEYS` environment variable when generating or accepting keys.
- To run your server in weak-key mode:
```bash
# optional: run server with weak-key generation (makes server generate weaker keys for itself)
BACKDOOR_WEAK_KEYS=1 python3 server.py --name serverA --port 8765

# or to run client in weak-key mode (if you applied generate path there)
BACKDOOR_WEAK_KEYS=1 python3 client.py --user alice --server ws://127.0.0.1:8765
```

**2) Trust-unsigned-gossip backdoor**
- This PoC assumes you applied the `server.py` backdoor snippet which checks `BACKDOOR_TRUST_GOSSIP`.
- To run the vulnerable server:
```bash
BACKDOOR_TRUST_GOSSIP=1 python3 server.py --name serverA --port 8765
```

---

## How to run the PoCs

> Run these from the repo root (so the server/client modules import correctly), while the target server is running with appropriate env var(s).

### 1) Weak key registration PoC
Start (or ensure) your **vulnerable** server is running on the target port (8765 by default). Then:

```bash
python3 quarantine/poc_weak_key_register.py --host 127.0.0.1 --port 8765
```

**Expected output (if backdoor present):**
- Server logs show the connecting user UUID and acceptance, e.g.:
  ```
  [server_id] User poc_weak_key_user (uuid) connected locally.
  [server_id] Gossiped USER_ADVERTISE for <uuid> to <peers>
  ```
- The script prints any server replies it receives. If no reply is printed, check server logs for acceptance.

**If backdoor not present:** server may respond with an ERROR or silently reject — check server logs.

---

### 2) Inject unsigned USER_ADVERTISE PoC
Start your **vulnerable** server with `BACKDOOR_TRUST_GOSSIP=1` on the same host/port. Then:

```bash
python3 quarantine/poc_inject_unsigned_advert.py --host 127.0.0.1 --port 8765
```

**Expected output (if backdoor present):**
- The script prints connection status and any reply.
- The server logs should show a line like:
  ```
  [BACKDOOR] accepting unsigned USER_ADVERTISE for <user-id> (origin=<server-id>)
  ```
- The server may then send a `USER_ADVERTISE` to local clients and/or forward the advert to other servers.

**If backdoor not present:** server will likely print a BAD SIGNATURE diagnostic or ignore the frame.

---

## PoC code location & cleanup

- Files:
  - `quarantine/poc_weak_key_register.py`
  - `quarantine/poc_inject_unsigned_advert.py`
  - `quarantine/BACKDOOR_README.md`

- **Cleanup:** To remove the backdoor exposure:
  1. Remove or revert the backdoor code snippets from `keys.py` and `server.py`.
  2. Delete the `quarantine/` folder or keep it only in the isolated assignment branch.
  3. Do **not** merge the backdoored branch into a public or main branch.

---

## Reflection & detection guidance (for graders / defenders)

- Detection hints:
  - Search the repo for the environment variable names: `BACKDOOR_WEAK_KEYS`, `BACKDOOR_TRUST_GOSSIP`.
  - Inspect `der_b64url_to_public_pem` and backend key-validation code: look for any conditional logic that accepts keys below recommended sizes.
  - Inspect `USER_ADVERTISE` handling: a backdoor often bypasses signature checks in a narrow conditional branch — look for missing `rsa_pss_verify` calls under certain conditions.

- Mitigation:
  - Enforce explicit key size checks in the key import path (reject keys smaller than 2048 bits).
  - Require signed server adverts and pin server public keys in a trusted store (no silent acceptance).
  - Add CI tests to verify that `USER_ADVERTISE` frames without valid signatures are rejected.

---

## Ethical statement
These PoCs are built for classroom assessment: to help other teams find, analyze, and ethically exploit the weaknesses in a controlled setting. They are intentionally limited in scope and non-destructive.


**Author:** GROUP 12

**MEMBERS:**  
  1. Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
  2. Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
  3. Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
  4. Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
  5. Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
  6. Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

