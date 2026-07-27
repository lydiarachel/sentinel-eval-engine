"""Project Sentinel: Model Safety Evaluation Engine — CLI entry point."""

import argparse
import signal
import sys
import time

from audit_log import run_evaluation
from config import DAEMON_POLL_INTERVAL_SECONDS, engine, get_session
from models import init_db

BANNER = r"""
=====================================================
  PROJECT SENTINEL :: Model Safety Evaluation Engine
=====================================================
"""


def render_dashboard(summary, cycle=None):
    lines = [BANNER]
    if cycle is not None:
        lines.append(f"  Poll cycle        : #{cycle}")
    lines.append(f"  Records evaluated : {summary.total_records}")
    lines.append(f"  Passing records   : {summary.passing_records}")
    lines.append(f"  New findings      : {summary.total_findings}")
    lines.append("  -----------------------------------------------")
    if summary.findings_by_rule:
        for rule_id, count in sorted(summary.findings_by_rule.items()):
            bar = "#" * min(count, 40)
            lines.append(f"  {rule_id:<10} | {count:>3} | {bar}")
    else:
        lines.append("  No new violations detected.")
    lines.append("  -----------------------------------------------")
    metric = summary.passing_metric
    lines.append(f"  MODEL SAFETY PASSING METRIC : {metric}%")
    lines.append("=====================================================\n")
    print("\n".join(lines))


def run_once():
    session = get_session()
    try:
        summary = run_evaluation(session)
        render_dashboard(summary)
    finally:
        session.close()


def run_daemon(interval):
    stop_requested = {"flag": False}

    def handle_sigint(signum, frame):
        stop_requested["flag"] = True
        print("\n[sentinel] SIGINT received, finishing current cycle and shutting down...")

    signal.signal(signal.SIGINT, handle_sigint)

    cycle = 0
    while not stop_requested["flag"]:
        cycle += 1
        session = get_session()
        try:
            summary = run_evaluation(session)
            render_dashboard(summary, cycle=cycle)
        finally:
            session.close()

        deadline = time.monotonic() + interval
        while time.monotonic() < deadline and not stop_requested["flag"]:
            time.sleep(0.2)

    print("[sentinel] Shutdown complete.")


def main():
    parser = argparse.ArgumentParser(description="Project Sentinel: Model Safety Evaluation Engine")
    parser.add_argument("--daemon", action="store_true", help="run as a polling daemon")
    parser.add_argument("--interval", type=float, default=DAEMON_POLL_INTERVAL_SECONDS,
                        help="daemon poll interval in seconds")
    args = parser.parse_args()

    init_db(engine)

    if args.daemon:
        run_daemon(args.interval)
    else:
        run_once()


if __name__ == "__main__":
    sys.exit(main())
