import os
import requests
from urllib.parse import urljoin
from src.mcp_orchestrator.test_vector_registry import TestVectorRegistry


# Target endpoint and base request
url = "http://demo.testfire.net/doLogin"
headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.8",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://demo.testfire.net",
    "Referer": "http://demo.testfire.net/login.jsp",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Sec-GPC": "1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
}
# We'll use a session so cookies set by the server are stored and reused
# We'll use a session so cookies set by the server are stored and reused
session = requests.Session()

# Allow optional Burp proxying by setting USE_BURP=1 in the environment
USE_BURP = os.getenv("USE_BURP", "0") == "1"
if USE_BURP:
    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }
else:
    proxies = None


# --- Normal login request (baseline, as per user HTTP POST) ---
normal_headers = {
    "Host": "demo.testfire.net",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://demo.testfire.net",
    "Referer": "http://demo.testfire.net/login.jsp",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i",
    "Te": "trailers",
    "Connection": "close",
}
normal_data = {"uid": "test", "passw": "trt", "btnSubmit": "Login"}
# Proxy config for Burp Suite
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

findings = []


def analyze_response(
    label, resp, session_obj=None, base_url=None, vector_id=None, vector_payload=None
):
    # Use raw bytes length to match Burp's byte counts
    snippet = ""
    resp_bytes = len(resp.content) if getattr(resp, "content", None) is not None else 0
    content_length_header = (
        resp.headers.get("Content-Length") if getattr(resp, "headers", None) is not None else None
    )
    set_cookie = (
        resp.headers.get("Set-Cookie", None) if getattr(resp, "headers", None) is not None else None
    )
    print(
        f"{label} Status: {getattr(resp, 'status_code', 'N/A')}, Content-Length header: {content_length_header}, Bytes: {resp_bytes}"
    )
    if set_cookie:
        print(f"Set-Cookie: {set_cookie}")
    # Always log a snippet of the response body (raw decoded) for analysis
    if resp_bytes > 0:
        try:
            snippet = (
                resp.content[:400].decode(errors="replace").replace("\n", " ").replace("\r", " ")
            )
        except Exception:
            snippet = "<binary content>"
        print(f"[BODY SNIPPET] {snippet}")

    # Log cookies returned by requests and session
    try:
        print(f"resp.cookies: {resp.cookies.get_dict()}")
    except Exception:
        print("resp.cookies: {}")
    if session_obj is not None:
        try:
            print(f"session.cookies: {session_obj.cookies.get_dict()}")
        except Exception:
            print("session.cookies: {}")

    suspicious = False
    findings_entry = {
        "vector_id": vector_id,
        "payload": vector_payload,
        "initial_status": getattr(resp, "status_code", None),
        "initial_bytes": resp_bytes,
        "initial_content_length_header": content_length_header,
        "initial_set_cookie": set_cookie,
        "label": label,
        "location": None,
        "final_status": None,
        "final_bytes": None,
        "final_set_cookie": None,
        "body_snippet": snippet,
    }

    # If redirect, log Location and optionally follow it to capture final page
    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location")
        findings_entry["location"] = location
        print(f"Location: {location}")
        if resp_bytes == 0:
            print("[INFO] 3xx with empty immediate body")
        else:
            print(f"[WARNING] 3xx response with non-zero body bytes: {resp_bytes}")
            suspicious = True

        # If Location present, follow once using session to capture final page (this models browser behavior)
        if session_obj is not None and location:
            final_url = urljoin(base_url or url, location)
            print(f"Following redirect to: {final_url}")
            try:
                final_resp = session_obj.get(
                    final_url, allow_redirects=True, proxies=proxies, verify=False
                )
                final_bytes = len(final_resp.content)
                final_cl = final_resp.headers.get("Content-Length")
                print(
                    f"Final Status: {final_resp.status_code}, Content-Length header: {final_cl}, Bytes: {final_bytes}"
                )
                try:
                    final_snip = (
                        final_resp.content[:400]
                        .decode(errors="replace")
                        .replace("\n", " ")
                        .replace("\r", " ")
                    )
                except Exception:
                    final_snip = "<binary content>"
                print(f"[FINAL BODY SNIPPET] {final_snip}")
                try:
                    print(f"final resp.cookies: {final_resp.cookies.get_dict()}")
                except Exception:
                    print("final resp.cookies: {}")
                findings_entry.update(
                    {
                        "final_status": final_resp.status_code,
                        "final_bytes": final_bytes,
                        "final_set_cookie": final_resp.headers.get("Set-Cookie"),
                        "body_snippet": final_snip,
                    }
                )
                # If final page looks like a successful login (Welcome/Logout) flag it
                if final_resp.status_code == 200 and (
                    "Welcome" in final_resp.text or "Logout" in final_resp.text
                ):
                    print("[!] Final page indicates possible login success or bypass")
                    suspicious = True
            except Exception as e:
                print(f"[ERROR] Failed to follow redirect: {e}")

    # Flag Set-Cookie/session creation as suspicious for test vectors
    if set_cookie and (
        "JSESSIONID" in set_cookie
        or "session" in set_cookie.lower()
        or "AltoroAccounts" in (set_cookie or "")
    ):
        print(f"[INFO] New session or app cookie set: {set_cookie}")
        suspicious = True

    # Flag direct 200 responses with login indicators
    if resp.status_code == 200 and ("Welcome" in resp.text or "Logout" in resp.text):
        print(
            "[!] Possible vulnerability detected on initial response: login success or session bypass!"
        )
        suspicious = True

    # Always record any suspicious conditions or non-zero 3xx bodies
    if suspicious or (
        getattr(resp, "status_code", None) in (301, 302, 303, 307, 308) and resp_bytes > 0
    ):
        findings.append(findings_entry)

    # Also record history chain if present
    if getattr(resp, "history", None):
        print(
            f"Response history ({len(resp.history)}): {[ (r.status_code, r.headers.get('Location')) for r in resp.history ]}"
        )

    print("-" * 60)


print("\n=== Normal Login Request (Baseline) ===")
resp = session.post(
    url,
    headers=normal_headers,
    data=normal_data,
    allow_redirects=False,
    proxies=proxies,
    verify=False,
)
analyze_response("Normal", resp, session_obj=session, base_url=url)

# Example: Run all SQL Injection vectors against the login form
registry = TestVectorRegistry()
sqli_vectors = [
    v for v in registry.get_all_vectors() if v.vuln_type.value.startswith("sqli") or "sql" in v.tags
]


# This script supports normal requests and advanced test vectors.
for vector in sqli_vectors:
    # Prepare payload for login form
    data = {"uid": vector.payload.base, "passw": "test", "btnSubmit": "Login"}
    print(f"Testing vector: {vector.id} - {vector.name}")
    resp = session.post(
        url, headers=headers, data=data, allow_redirects=False, proxies=proxies, verify=False
    )
    analyze_response(
        f"Vector {vector.id}",
        resp,
        session_obj=session,
        base_url=url,
        vector_id=vector.id,
        vector_payload=vector.payload.base,
    )


# Print summary of findings
if findings:
    print("\n=== Suspicious or Interesting Findings ===")
    for f in findings:
        print(
            f"{f.get('label')}: Vector {f.get('vector_id', '')} | Payload: {f.get('payload', '')} | Initial status: {f.get('initial_status')} | Initial bytes: {f.get('initial_bytes')} | Set-Cookie: {f.get('initial_set_cookie')} | Body snippet: {f.get('body_snippet','')}"
        )
else:
    print("\nNo suspicious responses or possible vulnerabilities detected.")
