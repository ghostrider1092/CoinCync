"""WP-023 live replay test against the running stratum pool.

Proves the per-canonical-job nonce ledger is SERVER-owned, not per-connection:
- connection A submits nonce N  -> claimed, then fails PoW  -> [23] Low difficulty
- connection B (a SEPARATE login) replays the SAME nonce N   -> [22] Duplicate

If dedup were per-worker (the bug WP-023 fixes), B would be re-credited. The
ledger records the nonce at claim time, before verify(), so an arbitrary nonce
suffices -- no RandomX needed.
"""
import json
import socket
import sys

HOST, PORT = "127.0.0.1", 23333
NONCE = "00000000cafe1234"  # fresh


def rpc(sock, buf, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())
    while b"\n" not in buf[0]:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed")
        buf[0] += chunk
    line, _, buf[0] = buf[0].partition(b"\n")
    return json.loads(line)


def login(sock, buf, who):
    resp = rpc(sock, buf, {"id": 1, "method": "login",
                           "params": {"login": who, "pass": "", "algo": ["cync/rx"]}})
    job = resp["result"]["job"]
    return resp["result"]["id"], job["job_id"]


def submit(sock, buf, sess, job_id, nonce):
    resp = rpc(sock, buf, {"id": 2, "method": "submit",
                           "params": {"id": sess, "job_id": job_id, "nonce": nonce}})
    err = resp.get("error")
    if err is None:
        return "ACCEPTED", resp.get("result")
    # error may be {code,message} or [code,msg,null]
    if isinstance(err, list):
        return f"[{err[0]}] {err[1]}", None
    return f"{{code:{err.get('code')}}} {err.get('message')}", None


def main():
    a = socket.create_connection((HOST, PORT), timeout=15)
    abuf = [b""]
    a_sess, a_job = login(a, abuf, "attacker.A")
    print(f"conn A logged in, canonical job = {a_job}")

    r1 = submit(a, abuf, a_sess, a_job, NONCE)
    print(f"conn A submit nonce {NONCE}: {r1[0]}")

    b = socket.create_connection((HOST, PORT), timeout=15)
    bbuf = [b""]
    b_sess, b_job = login(b, bbuf, "attacker.B")
    print(f"conn B logged in, canonical job = {b_job}")

    if b_job != a_job:
        print("SKIP: canonical job rotated between logins; rerun with the rig stopped")
        sys.exit(2)

    r2 = submit(b, bbuf, b_sess, b_job, NONCE)
    print(f"conn B REPLAY same nonce: {r2[0]}")

    a.close()
    b.close()

    # Verdict: B must be rejected as Duplicate ([22]), not accepted, not merely
    # 'low difficulty' (which would mean the ledger did not catch the replay).
    ok = "duplicate" in r2[0].lower()
    print()
    print("WP-023 REPLAY DEFENSE:", "PASS" if ok else "FAIL")
    if not ok:
        print("  expected conn B to be rejected as Duplicate; got:", r2[0])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
