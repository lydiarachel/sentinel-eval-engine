# Project Sentinel: Model Safety Evaluation Engine

A lightweight, modular Python framework and CLI dashboard that acts as a read-only,
out-of-band scanner for language model outputs. It evaluates a mock model transaction
log against structural safety and policy compliance rules, persists findings without
ever mutating source data, and reports a Model Safety Passing Metric.

**Why this exists:** I built this to demonstrate how I think about safety evaluation
pipelines: policy rules translated into testable code, findings that carry evidence
(rule ID, raw match, full payload), a strict read-only boundary between the scanner
and the data it audits, and reporting that a non-technical stakeholder can act on.
My background is a decade of claims auditing and regulatory enforcement in health
insurance, where the same principles decide whether real people get paid.

## Sample output

```
=====================================================
  PROJECT SENTINEL :: Model Safety Evaluation Engine
=====================================================

  Records evaluated : 15
  Passing records   : 8
  New findings      : 7
  -----------------------------------------------
  COMP-003   |   2 | ##
  FWA-001    |   3 | ###
  LEAK-002   |   2 | ##
  -----------------------------------------------
  MODEL SAFETY PASSING METRIC : 53.33%
=====================================================
```

## Layout

```
project-sentinel/
├── config.py                  # env-driven config + SQLAlchemy engine/session
├── models.py                  # ORM: model_prompts, safety_findings
├── validators/
│   ├── base.py                # shared validator contract
│   ├── policy_fwa.py          # FWA-001: fraud/waste/abuse + bypass patterns
│   ├── data_leakage.py        # LEAK-002: secrets, keys, non-public data markers
│   └── structural_integrity.py# COMP-003: response schema regression checks
├── audit_log.py               # evaluation loop, finding persistence, CSV telemetry
├── main.py                    # CLI: one-shot or --daemon with ASCII dashboard
├── mock_data.py               # seeds 15 mock conversations (passing + anomalies)
├── generate_report.py         # renders site/index.html from live evaluation data
└── site/index.html            # static evaluation report (deployed via Netlify)
```

## Quick start

```bash
pip install -r requirements.txt
python mock_data.py     # seed the mock transaction log
python main.py          # run one evaluation pass + dashboard
python main.py --daemon --interval 5   # polling mode, Ctrl+C for graceful shutdown
python generate_report.py              # regenerate the static report page
```

## Detection rules

| Rule ID  | Validator                 | What it catches                                                                 |
|----------|---------------------------|---------------------------------------------------------------------------------|
| FWA-001  | `policy_fwa.py`           | Responses that assist fraud, waste, or abuse: fabricated documents, control/audit bypass advice, structuring patterns |
| LEAK-002 | `data_leakage.py`         | Credential-shaped material in responses: API secret keys, cloud access key IDs, JWTs, private key blocks, SSN patterns |
| COMP-003 | `structural_integrity.py` | Structured responses that break contract: invalid JSON, missing required fields, unmapped keys that suggest internal state leaking into output |

The seed data (`mock_data.py`) contains 8 realistic benign conversations and 7
known-positive policy traps, so every rule has both true-positive and true-negative
test material. The benign set deliberately includes near-miss content (a personal
finance question, a debugging conversation) to exercise false-positive behavior.

## Design notes

- **Read-only guarantee**: source `model_prompts` rows are never altered. Violations are
  written to the separate `safety_findings` table and appended to
  `safety_evaluation_snapshot.csv`.
- **Evidence-first findings**: every finding persists the full record payload, the raw
  matched string, and the rule ID, so a reviewer can reproduce the determination
  without re-running the scan.
- **Configuration**: `SENTINEL_DATABASE_URL`, `SENTINEL_SNAPSHOT_CSV`,
  `SENTINEL_POLL_INTERVAL` environment variables override defaults.

## Limitations and next steps

This is deliberately a structural/pattern-based scanner, and pattern matching is the
floor, not the ceiling, of safety evaluation. Real-world model safety evals lean
heavily on model-based grading and human review. Natural extensions:

- An LLM-as-judge scoring layer for policy areas where intent matters more than
  surface patterns (the FWA rules are the obvious first candidate)
- Severity tiers and finding deduplication across runs
- Eval saturation tracking: flag rules that stop producing findings so they can be
  reviewed for staleness rather than mistaken for safety

## Note on synthetic secrets in mock data

All credential-like strings in `mock_data.py` are synthetic and exist only as
known-positive test material for the LEAK-002 validator. The `sk_live_...` value
is a fabricated string in Stripe's key format, and `AKIAIOSFODNN7EXAMPLE` is the
official example access key ID from AWS documentation. Neither is, or ever was,
a real credential. If this repository is pushed to a public host, automated
secret scanners (e.g., GitHub secret scanning) may still flag these patterns;
such alerts can be safely dismissed as test fixtures.
