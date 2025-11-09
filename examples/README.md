APIsec examples

This folder contains example scripts demonstrating how to use the lightweight TestEngine
and Analyzer to run security vectors against test targets.

Core-level test flags supported in vectors

- idor_path: a path template containing `{id}` to run IDOR checks. Example: `/api/items/{id}`.
- idor_ids: optional list of ids to test. If omitted, Analyzer will generate a short sequence.
- rate_limit: boolean to request a rate-limit burst test. Optional settings: `rate_limit_url`, `rate_limit_attempts`, `rate_limit_interval`.
- session_fixation: boolean to request a session-fixation test. Optional `login_data` to customize credentials.

Example usage

Use `TestEngine.execute(target_url, vectors=...)` to run a custom set of vectors that include the flags above. The test engine enforces skip-host policy for known demo hosts (e.g., `demo.testfire.net`).

Safety

These example vectors are intentionally non-destructive. When running against live targets, ensure you have permission to test.
