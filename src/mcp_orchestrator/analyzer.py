import json
import logging
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from statistics import mean, stdev
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import difflib
import requests

LOG = logging.getLogger(__name__)


def _safe_text(content: bytes) -> str:
    try:
        return content.decode('utf-8', errors='replace')
    except Exception:
        return str(content)


SQL_ERROR_RE = r'(sql syntax|mysql|syntax error|ora-|oracle|sqlite|postgresql|unhandled exception|sqlstate)'
SUCCESS_KEYWORDS = ['Welcome', 'Logout', 'Dashboard', 'My Account', 'Sign out']


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
    def __init__(self, base_url: str, proxies: Optional[Dict[str, str]] = None, verify: bool = False,
                 timeout: int = 10, concurrency: int = 1, skip_hosts: Optional[List[str]] = None):
        self.base_url = base_url
        self.proxies = proxies or {}
        self.verify = verify
        self.timeout = timeout
        self.concurrency = max(1, min(4, int(concurrency)))
        self.jitter_min = 0.2
        self.jitter_max = 0.5
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'mcp-orchestrator-analyzer/1.0'})
        self.session.verify = verify
        self.session.proxies.update(self.proxies)
        self.baseline_text = ''
        self.findings: List[Dict[str, Any]] = []

        # skip hosts default includes demo.testfire.net per task
        self.skip_hosts = set(skip_hosts or ['demo.testfire.net'])
        parsed = urlparse(base_url)
        self.base_host = parsed.hostname
        self._skip = self.base_host in self.skip_hosts
        if self._skip:
            LOG.info('Analyzer initialized in skip mode for host: %s', self.base_host)

    # skip policy enforcement helper
    def _enforce_skip(self):
        if self._skip:
            return True
        return False

    def capture_baseline(self, baseline_data: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Send a baseline benign request and store the response text for similarity comparison.
        baseline_data: form data
        headers: optional headers to merge into session
        """
        if self._enforce_skip():
            return {'skipped_by_policy': True}

        hdrs = headers or {}
        try:
            resp = self.session.post(self.base_url, data=baseline_data, headers=hdrs, timeout=self.timeout,
                                     proxies=self.proxies, allow_redirects=True)
            text = _safe_text(resp.content)
            self.baseline_text = text
            return {'status': resp.status_code, 'length': len(resp.content), 'text_snippet': text[:400]}
        except requests.RequestException as exc:
            LOG.exception('Baseline request failed: %s', exc)
            return {'error': str(exc)}

    def _place_payload(self, sink: str, payload: str, base_data: Dict[str, Any], headers: Dict[str, str]) -> (Dict[str, Any], Dict[str, str]):
        data = dict(base_data or {})
        hdrs = dict(headers or {})
        cookie_header = None
        if sink == 'uid':
            data['uid'] = payload
        elif sink == 'passw':
            data['passw'] = payload
        elif sink == 'cookie':
            cookie_header = payload
        elif sink == 'header':
            hdrs['X-Forwarded-For'] = payload
        elif sink == 'referer':
            hdrs['Referer'] = payload
        return data, hdrs, cookie_header

    def _request_with_backoff(self, method: str, url: str, **kwargs):
        max_retries = 3
        backoff = 0.5
        for attempt in range(max_retries + 1):
            try:
                resp = getattr(self.session, method)(url, timeout=self.timeout, proxies=self.proxies, verify=self.verify, **kwargs)
                if resp.status_code in (429, 503) and attempt < max_retries:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except requests.RequestException as exc:
                LOG.debug('request attempt %s failed: %s', attempt, exc)
                if attempt >= max_retries:
                    raise
                time.sleep(backoff)
                backoff *= 2

    def run_vector(self, vector: Dict[str, Any], sinks: List[str] = ['uid', 'passw', 'cookie', 'header', 'referer'],
                   allow_redirects: bool = False, follow_redirects: bool = False) -> List[Dict[str, Any]]:
        """
        Run a single vector (dictionary with 'id' and 'payload') across multiple sinks.
        Returns list of findings dicts for each sink.
        """
        if self._enforce_skip():
            return [{'skipped_by_policy': True, 'vector_id': vector.get('id')}]

        results = []
        base_data = {'uid': '', 'passw': '', 'btnSubmit': 'Login'}
        base_headers = {}

        for sink in sinks:
            payload = vector.get('payload') if isinstance(vector, dict) else str(vector)
            data, hdrs, cookie_header = self._place_payload(sink, payload, base_data, base_headers)

            # set cookie via headers if required
            if cookie_header:
                hdrs['Cookie'] = cookie_header

            # jitter
            if self.concurrency > 1:
                time.sleep(random.uniform(self.jitter_min, self.jitter_max))

            try:
                start = time.time()
                resp = self._request_with_backoff('post', self.base_url, data=data, headers=hdrs, allow_redirects=allow_redirects)
                elapsed = time.time() - start
            except Exception as e:
                LOG.exception('Request failed for vector %s sink %s: %s', vector.get('id'), sink, e)
                results.append({'vector_id': vector.get('id'), 'sink': sink, 'error': str(e)})
                continue

            content_bytes = len(resp.content)
            text = _safe_text(resp.content)

            # sql error detection
            import re
            sql_error = bool(re.search(SQL_ERROR_RE, text, re.IGNORECASE))

            # success keywords
            found_success = [k for k in SUCCESS_KEYWORDS if k in text]

            # similarity
            similarity = difflib.SequenceMatcher(a=self.baseline_text or '', b=text).ratio() if self.baseline_text else 0.0

            redirect_chain = [(r.status_code, r.headers.get('Location')) for r in getattr(resp, 'history', [])]
            if resp.headers.get('Location'):
                redirect_chain.append((resp.status_code, resp.headers.get('Location')))

            session_snapshot = dict(self.session.cookies.get_dict())

            finding = {
                'vector_id': vector.get('id'),
                'payload': payload,
                'sink': sink,
                'status': resp.status_code,
                'length': content_bytes,
                'elapsed': elapsed,
                'headers': dict(resp.headers),
                'redirect_chain': redirect_chain,
                'response_text': text[:2000],
                'session_cookies': session_snapshot,
                'sql_error_found': sql_error,
                'similarity': similarity,
                'success_keywords': found_success,
                'time_probe': None,
                'suspicious': False,
                'notes': []
            }

            # follow redirect once if requested
            if follow_redirects and resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get('Location'):
                try:
                    final_url = urljoin(self.base_url, resp.headers.get('Location'))
                    final_resp = self.session.get(final_url, timeout=self.timeout, proxies=self.proxies, verify=self.verify)
                    final_text = _safe_text(final_resp.content)
                    finding.update({
                        'final_status': final_resp.status_code,
                        'final_length': len(final_resp.content),
                        'final_headers': dict(final_resp.headers),
                        'response_text': final_text[:2000]
                    })
                    # re-evaluate success keywords on final page
                    finding['success_keywords'] = [k for k in SUCCESS_KEYWORDS if k in final_text]
                except Exception as e:
                    finding['notes'].append(f'Failed following redirect: {e}')

            # suspicious heuristics
            if finding['length'] > 0 and resp.status_code in (301, 302, 303, 307, 308):
                finding['suspicious'] = True
                finding['notes'].append('Non-zero redirect body')
            if finding['sql_error_found']:
                finding['suspicious'] = True
                finding['notes'].append('SQL error patterns detected')
            if finding['success_keywords']:
                finding['suspicious'] = True
                finding['notes'].append('Success keywords present')

            results.append(finding)

        # append to internal findings list
        for r in results:
            self.findings.append(r)
        return results

    def run_time_probe(self, control_payload_fn, sleep_payload_fn, trials: int = 2) -> Dict[str, Any]:
        """
        control_payload_fn and sleep_payload_fn should be callables returning payload strings to put into uid/passw fields.
        Runs trials times each and measures means/stdevs.
        """
        if self._enforce_skip():
            return {'skipped_by_policy': True}

        ctrl_times = []
        sleep_times = []
        for _ in range(trials):
            payload = control_payload_fn()
            start = time.time()
            try:
                resp = self.session.post(self.base_url, data={'uid': payload, 'passw': 'test'}, timeout=self.timeout,
                                         proxies=self.proxies, verify=self.verify)
                ctrl_times.append(time.time() - start)
            except Exception:
                ctrl_times.append(float('nan'))

            payload = sleep_payload_fn()
            start = time.time()
            try:
                resp = self.session.post(self.base_url, data={'uid': payload, 'passw': 'test'}, timeout=self.timeout,
                                         proxies=self.proxies, verify=self.verify)
                sleep_times.append(time.time() - start)
            except Exception:
                sleep_times.append(float('nan'))

        # compute means ignoring NaN
        def _clean_stats(lst):
            vals = [v for v in lst if v == v]
            return {'mean': mean(vals) if vals else float('nan'), 'stdev': stdev(vals) if len(vals) > 1 else 0.0}

        ctrl_stats = _clean_stats(ctrl_times)
        sleep_stats = _clean_stats(sleep_times)
        delta = (sleep_stats['mean'] - ctrl_stats['mean']) if ctrl_stats['mean'] and sleep_stats['mean'] else None

        return {'ctrl': ctrl_stats, 'sleep': sleep_stats, 'delta': delta}

    def run_all(self, vector_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run all vectors (list of dicts with 'id' and 'payload'). Writes artifacts/findings.json and returns findings list.
        """
        if self._enforce_skip():
            LOG.warning('run_all skipped by policy for host: %s', self.base_host)
            return [{'skipped_by_policy': True}]

        if self.concurrency > 1:
            workers = min(4, self.concurrency)
        else:
            workers = 1

        futures = []
        with ThreadPoolExecutor(max_workers=workers) as exe:
            for vec in vector_list:
                futures.append(exe.submit(self.run_vector, vec))

            # gather results
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    LOG.exception('vector run failed')

        # write findings.json
        os.makedirs('artifacts', exist_ok=True)
        outf = os.path.join('artifacts', 'findings.json')
        with open(outf, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2)

        # print short human summary
        suspicious = [f for f in self.findings if f.get('suspicious')]
        print(f"Run complete: {len(self.findings)} total findings, {len(suspicious)} suspicious")
        for s in suspicious[:10]:
            print(f"- {s.get('vector_id')} sink={s.get('sink')} status={s.get('status')} length={s.get('length')} notes={s.get('notes')}")

        return self.findings
