"""Generate a static HTML evaluation report (site/index.html) from live engine data.

Run after an evaluation pass so the page reflects real findings:
    python mock_data.py && python main.py && python generate_report.py
"""

import html
import json
import os
from datetime import datetime, timezone

from config import get_session
from models import ModelPrompt, SafetyFinding

RULE_META = {
    "FWA-001": ("Fraud / Waste / Abuse", "policy_fwa.py",
                "Responses that assist fraud: fabricated documents, control-bypass advice, structuring patterns."),
    "LEAK-002": ("Data Leakage", "data_leakage.py",
                 "Credential-shaped material in responses: API secret keys, cloud key IDs, JWTs, private key blocks."),
    "COMP-003": ("Structural Integrity", "structural_integrity.py",
                 "Structured responses that break contract: invalid JSON, missing required fields, unmapped keys."),
}
RULE_ORDER = ["FWA-001", "LEAK-002", "COMP-003"]


def esc(s, limit=None):
    if limit and len(s) > limit:
        s = s[:limit].rstrip() + "…"
    return html.escape(s)


def collect():
    session = get_session()
    try:
        total = session.query(ModelPrompt).count()
        findings = session.query(SafetyFinding).all()
        flagged_ids = {f.prompt_id for f in findings}
        counts = {r: 0 for r in RULE_ORDER}
        examples = {}
        for f in findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
            if f.rule_id not in examples:
                rec = session.get(ModelPrompt, f.prompt_id)
                examples[f.rule_id] = {
                    "prompt": rec.prompt_text, "response": rec.response_text,
                    "detail": f.error_detail, "severity": f.severity,
                }
        passing = total - len(flagged_ids)
        metric = (passing / total * 100) if total else 0.0
        return total, passing, len(findings), metric, counts, examples
    finally:
        session.close()


def render():
    total, passing, n_findings, metric, counts, examples = collect()
    max_count = max(counts.values()) or 1
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    bars = ""
    for i, rule in enumerate(RULE_ORDER, start=1):
        name, module, _ = RULE_META[rule]
        pct = counts[rule] / max_count * 100
        bars += f"""
      <div class="bar-row" tabindex="0" data-tip="{rule} · {counts[rule]} finding(s) · validators/{module}">
        <span class="bar-label">{rule}<em>{name}</em></span>
        <span class="bar-track"><span class="bar-fill s{i}" style="width:{pct:.0f}%"></span></span>
        <span class="bar-value">{counts[rule]}</span>
      </div>"""

    cards = ""
    for i, rule in enumerate(RULE_ORDER, start=1):
        ex = examples.get(rule)
        if not ex:
            continue
        name, module, desc = RULE_META[rule]
        cards += f"""
      <article class="card">
        <header><span class="chip s{i}">{rule}</span><h3>{name}</h3><code>validators/{module}</code></header>
        <p class="rule-desc">{desc}</p>
        <div class="convo">
          <div class="msg user"><span>User prompt</span><p>{esc(ex['prompt'], 180)}</p></div>
          <div class="msg model"><span>Model response (flagged)</span><p>{esc(ex['response'], 260)}</p></div>
        </div>
        <div class="evidence"><span>Evidence persisted with finding</span><pre>{esc(ex['detail'], 200)}</pre></div>
      </article>"""

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Project Sentinel · Model Safety Evaluation Report</title>
<style>
  :root {{
    color-scheme: light;
    --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e;
    --muted: #898781; --grid: #e1e0d9; --ring: rgba(11,11,11,0.10);
    --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --good-text: #006300;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      color-scheme: dark;
      --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7;
      --muted: #898781; --grid: #2c2c2a; --ring: rgba(255,255,255,0.10);
      --s1: #3987e5; --s2: #d95926; --s3: #199e70; --good-text: #0ca30c;
    }}
  }}
  * {{ box-sizing: border-box; margin: 0; }}
  body {{ background: var(--page); color: var(--ink); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  main {{ max-width: 880px; margin: 0 auto; padding: 40px 20px 64px; }}
  .masthead h1 {{ font-size: 1.5rem; letter-spacing: -0.01em; }}
  .masthead p.sub {{ color: var(--ink-2); max-width: 62ch; margin-top: 6px; }}
  .masthead .links {{ margin-top: 10px; font-size: 0.9rem; }}
  a {{ color: var(--s1); }}
  .meta {{ color: var(--muted); font-size: 0.8rem; margin-top: 8px; }}
  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 28px 0; }}
  .tile {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px 16px; }}
  .tile b {{ display: block; font-size: 1.7rem; font-weight: 650; letter-spacing: -0.01em; }}
  .tile.hero b {{ color: var(--good-text); }}
  .tile span {{ color: var(--ink-2); font-size: 0.82rem; }}
  section h2 {{ font-size: 1.05rem; margin: 34px 0 4px; }}
  section p.lede {{ color: var(--ink-2); font-size: 0.9rem; margin-bottom: 14px; max-width: 68ch; }}
  .chart {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 18px; }}
  .bar-row {{ display: grid; grid-template-columns: 170px 1fr 2.5em; align-items: center; gap: 12px; padding: 7px 4px; border-radius: 6px; position: relative; }}
  .bar-row:hover, .bar-row:focus-visible {{ background: color-mix(in srgb, var(--ink) 5%, transparent); outline: none; }}
  .bar-row:hover::after, .bar-row:focus-visible::after {{
    content: attr(data-tip); position: absolute; left: 178px; top: -1.9em; z-index: 2;
    background: var(--ink); color: var(--page); font-size: 0.75rem; padding: 3px 9px; border-radius: 6px; white-space: nowrap;
  }}
  .bar-label {{ font-size: 0.85rem; font-variant-numeric: tabular-nums; }}
  .bar-label em {{ display: block; font-style: normal; color: var(--muted); font-size: 0.75rem; }}
  .bar-track {{ background: color-mix(in srgb, var(--grid) 55%, transparent); border-radius: 4px; height: 14px; overflow: hidden; }}
  .bar-fill {{ display: block; height: 100%; border-radius: 0 4px 4px 0; }}
  .s1 {{ background: var(--s1); }} .s2 {{ background: var(--s2); }} .s3 {{ background: var(--s3); }}
  .bar-value {{ text-align: right; font-variant-numeric: tabular-nums; color: var(--ink-2); font-size: 0.9rem; }}
  .cards {{ display: grid; gap: 14px; }}
  .card {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 18px; }}
  .card header {{ display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }}
  .card h3 {{ font-size: 0.95rem; }}
  .card header code {{ color: var(--muted); font-size: 0.75rem; }}
  .chip {{ color: #fff; font-size: 0.72rem; font-weight: 600; padding: 2px 8px; border-radius: 99px; }}
  .rule-desc {{ color: var(--ink-2); font-size: 0.85rem; margin: 8px 0 12px; }}
  .convo {{ display: grid; gap: 8px; }}
  .msg {{ border: 1px solid var(--grid); border-radius: 8px; padding: 10px 12px; font-size: 0.85rem; }}
  .msg span {{ display: block; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; }}
  .msg.model {{ border-left: 3px solid var(--s2); }}
  .evidence {{ margin-top: 10px; }}
  .evidence span {{ display: block; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; }}
  .evidence pre {{ background: color-mix(in srgb, var(--grid) 40%, transparent); border-radius: 8px; padding: 10px 12px; font-size: 0.78rem; white-space: pre-wrap; word-break: break-word; }}
  .pipeline {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
  .step {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px 16px; font-size: 0.85rem; }}
  .step b {{ display: block; margin-bottom: 4px; font-size: 0.85rem; }}
  .step em {{ color: var(--muted); font-style: normal; font-size: 0.75rem; }}
  footer {{ margin-top: 44px; padding-top: 16px; border-top: 1px solid var(--grid); color: var(--ink-2); font-size: 0.85rem; }}
  footer p + p {{ margin-top: 6px; }}
</style>
</head>
<body>
<main>
  <header class="masthead">
    <h1>Project Sentinel: Model Safety Evaluation Engine</h1>
    <p class="sub">A read-only, out-of-band scanner that evaluates language model outputs against
    structural safety and policy compliance rules. Findings carry evidence: the rule ID, the raw
    matched string, and the full record payload. Source data is never mutated.</p>
    <p class="links"><a href="https://github.com/lydiarachel/sentinel-eval-engine">Source on GitHub</a> ·
    built with Python, SQLAlchemy, and Claude Code by <a href="https://www.linkedin.com/in/lydia-bordnick">Lydia Bordnick</a></p>
    <p class="meta">Report generated {generated} from a live evaluation run over the mock transaction log.</p>
  </header>

  <div class="tiles">
    <div class="tile"><b>{total}</b><span>Records evaluated</span></div>
    <div class="tile"><b>{passing}</b><span>Passing records</span></div>
    <div class="tile"><b>{n_findings}</b><span>Findings raised</span></div>
    <div class="tile hero"><b>{metric:.1f}%</b><span>Model Safety Passing Metric</span></div>
  </div>

  <section>
    <h2>Findings by rule</h2>
    <p class="lede">The mock transaction log seeds 8 realistic benign conversations and 7 known-positive
    policy traps, so every rule is tested against both true positives and near-miss negatives.</p>
    <div class="chart">{bars}
    </div>
  </section>

  <section>
    <h2>Example findings</h2>
    <p class="lede">One representative finding per rule, exactly as the engine persisted it. All
    conversations are synthetic test fixtures; the credential strings are fabricated, non-functional examples.</p>
    <div class="cards">{cards}
    </div>
  </section>

  <section>
    <h2>How it works</h2>
    <div class="pipeline">
      <div class="step"><b>1 · Pull</b>Read records from the model transaction log<em> config.py · models.py</em></div>
      <div class="step"><b>2 · Evaluate</b>Stream each record through independent rule validators<em> validators/</em></div>
      <div class="step"><b>3 · Persist</b>Write findings + evidence to a separate table and CSV telemetry<em> audit_log.py</em></div>
      <div class="step"><b>4 · Report</b>CLI dashboard, daemon polling with graceful shutdown, this page<em> main.py</em></div>
    </div>
  </section>

  <footer>
    <p>Pattern-based scanning is the floor, not the ceiling, of safety evaluation: the natural next layer
    is LLM-as-judge scoring for policy areas where intent matters more than surface patterns. The
    <a href="https://github.com/lydiarachel/sentinel-eval-engine#limitations-and-next-steps">README</a> covers
    the roadmap.</p>
    <p>Every string in this dataset is synthetic. No real user data, credentials, or model transcripts appear anywhere in this project.</p>
  </footer>
</main>
</body>
</html>
"""
    os.makedirs("site", exist_ok=True)
    with open(os.path.join("site", "index.html"), "w") as fh:
        fh.write(page)
    print(f"[report] site/index.html written ({total} records, {n_findings} findings, metric {metric:.1f}%)")


if __name__ == "__main__":
    render()
