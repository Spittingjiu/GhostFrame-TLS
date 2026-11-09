import ssl
import json
import socket
import urllib.request
import urllib.parse
import http.client
import time

DEPLOY_RECORD = r"C:\Users\64520\Desktop\GhostFrame_Project\02_Source_Code\deploy_record.json"

def main():
    with open(DEPLOY_RECORD, "r", encoding="utf-8") as f:
        rec = json.load(f)

    ip = rec["ip"]
    port = rec["port"]
    panel_path = rec["panel_path"]
    panel_pass = rec["panel_password"]
    sni = rec["sni"]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = {}

    print("="*60)
    print(" GFT PRO REAL CROSS-BORDER VERIFICATION TEST")
    print("="*60)

    # 1. Probe Fallback Test: GET /
    print("\n[TEST 1] Active Probe on https://{}:{}/".format(ip, port))
    try:
        conn = http.client.HTTPSConnection(ip, port, context=ctx, timeout=8)
        conn.request("GET", "/", headers={"Host": sni, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="ignore")
        server_header = resp.getheader("Server")
        conn.close()

        print("  Status: {}".format(resp.status))
        print("  Server Header: {}".format(server_header))
        print("  Title in Body: {}".format("<title>" in body and body.split("<title>")[1].split("</title>")[0]))
        results["probe"] = {
            "status": resp.status,
            "server_header": server_header,
            "is_blog": "Quiet Compiler" in body or "Compiler" in body
        }
    except Exception as e:
        print("  [FAIL] Probe test exception: {}".format(e))
        results["probe"] = {"error": str(e)}

    # 2. Secret Admin Panel: GET /gft-panel-.../
    print("\n[TEST 2] Secret Admin Panel at {}".format(rec["panel_url"]))
    try:
        conn = http.client.HTTPSConnection(ip, port, context=ctx, timeout=8)
        conn.request("GET", panel_path + "/", headers={"Host": sni})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="ignore")
        conn.close()

        print("  Status: {}".format(resp.status))
        print("  Contains Panel Elements: {}".format("GhostFrame" in body or "panel" in body.lower()))
        results["panel_get"] = {
            "status": resp.status,
            "has_panel": "GhostFrame" in body or "panel" in body.lower()
        }
    except Exception as e:
        print("  [FAIL] Panel get exception: {}".format(e))
        results["panel_get"] = {"error": str(e)}

    # 3. Panel Login Test: POST /api/login
    print("\n[TEST 3] Panel Login Authentication")
    try:
        conn = http.client.HTTPSConnection(ip, port, context=ctx, timeout=8)
        login_body = json.dumps({"password": panel_pass})
        conn.request("POST", panel_path + "/api/login", body=login_body, headers={
            "Host": sni,
            "Content-Type": "application/json"
        })
        resp = conn.getresponse()
        resp_data = json.loads(resp.read().decode("utf-8"))
        cookie = resp.getheader("Set-Cookie")
        conn.close()

        print("  Status: {}".format(resp.status))
        print("  Login OK: {}".format(resp_data.get("ok")))
        print("  Session Cookie Set: {}".format("gft_session" in (cookie or "")))
        results["panel_login"] = {
            "status": resp.status,
            "ok": resp_data.get("ok"),
            "has_cookie": bool(cookie)
        }

        # 4. Check Threat Perception Audit Table
        if cookie:
            token = cookie.split(";")[0]
            conn2 = http.client.HTTPSConnection(ip, port, context=ctx, timeout=8)
            conn2.request("GET", panel_path + "/api/audit", headers={
                "Host": sni,
                "Cookie": token
            })
            audit_resp = conn2.getresponse()
            audit_data = json.loads(audit_resp.read().decode("utf-8"))
            conn2.close()
            print("\n[TEST 4] Threat Perception Audit Table")
            print("  Entries trapped: {}".format(len(audit_data)))
            for entry in audit_data[:5]:
                print("   -> IP: {}, Count: {}, Reasons: {}".format(entry.get("ip"), entry.get("count"), entry.get("reasons")))
            results["audit"] = audit_data
    except Exception as e:
        print("  [FAIL] Panel login/audit exception: {}".format(e))
        results["panel_login"] = {"error": str(e)}

    # Save results
    with open(r"C:\Users\64520\Desktop\GhostFrame_Project\02_Source_Code\test_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n[+] Verification suite finished. Results saved.")

if __name__ == "__main__":
    main()
