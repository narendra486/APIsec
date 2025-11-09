#!/usr/bin/env python3
import argparse
import json
import logging
from src.mcp_orchestrator.analyzer import Analyzer


def parse_args():
    p = argparse.ArgumentParser(description='Run analyzer')
    p.add_argument('--url', required=True)
    p.add_argument('--vectors-file', required=True)
    p.add_argument('--proxies', default=None)
    p.add_argument('--verify', action='store_true')
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--concurrency', type=int, default=1)
    p.add_argument('--skip-hosts', default='demo.testfire.net')
    p.add_argument('--follow-redirects', action='store_true')
    p.add_argument('--time-probe', action='store_true')
    p.add_argument('--verbose', action='store_true')
    return p.parse_args()


def main():
    args = parse_args()
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level)

    proxies = None
    if args.proxies:
        try:
            proxies = json.loads(args.proxies)
        except Exception:
            proxies = None

    skip_hosts = [h.strip() for h in args.skip_hosts.split(',') if h.strip()]
    analyzer = Analyzer(args.url, proxies=proxies, verify=args.verify, timeout=args.timeout,
                        concurrency=args.concurrency, skip_hosts=skip_hosts)

    with open(args.vectors_file, 'r', encoding='utf-8') as f:
        vectors = json.load(f)

    findings = analyzer.run_all(vectors)
    print('Findings written to artifacts/findings.json')


if __name__ == '__main__':
    main()
