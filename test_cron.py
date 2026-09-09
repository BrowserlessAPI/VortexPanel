from croniter import croniter, CroniterBadCronError
from datetime import datetime, timezone
import sys

def test_cron(expression: str, count: int = 10, start_time: datetime = None):
    print(f"\n{'='*55}")
    print(f"  Cron Expression: '{expression}'")
    print(f"{'='*55}")

    # Validate
    if not croniter.is_valid(expression):
        print("  ❌ INVALID cron expression!")
        return

    print("  ✅ Expression is VALID\n")

    # Describe frequency
    parts = expression.split()
    labels = ["Minute", "Hour", "Day(month)", "Month", "Day(week)"]
    print("  📋 Field Breakdown:")
    for label, part in zip(labels, parts):
        print(f"     {label:<12}: {part}")

    # Next N occurrences
    start = start_time or datetime.now()
    cron = croniter(expression, start)
    print(f"\n  🕐 Next {count} scheduled runs (from {start.strftime('%Y-%m-%d %H:%M:%S')}):")
    for i in range(count):
        next_run = cron.get_next(datetime)
        print(f"     {i+1:>2}. {next_run.strftime('%Y-%m-%d %H:%M:%S')} ({next_run.strftime('%A')})")

    # Previous N occurrences
    cron_prev = croniter(expression, start)
    print(f"\n  🕐 Last {count} scheduled runs (before {start.strftime('%Y-%m-%d %H:%M:%S')}):")
    prev_runs = [cron_prev.get_prev(datetime) for _ in range(count)]
    for i, run in enumerate(prev_runs):
        print(f"     {i+1:>2}. {run.strftime('%Y-%m-%d %H:%M:%S')} ({run.strftime('%A')})")

    print()

# ── Demo: test several common expressions ──────────────────────
examples = [
    ("* * * * *",        "Every minute"),
    ("*/15 * * * *",     "Every 15 minutes"),
    ("0 9 * * 1-5",      "9 AM on weekdays"),
    ("0 0 1 * *",        "Midnight on 1st of every month"),
    ("30 6 * * 0",       "6:30 AM every Sunday"),
    ("0 */6 * * *",      "Every 6 hours"),
    ("0 8-18 * * 1-5",   "Every hour 8 AM–6 PM on weekdays"),
]

print("\n🔍 CRON SCHEDULE TESTER")
print("Testing common cron expressions...\n")

for expr, description in examples:
    print(f"  📌 {description}")
    test_cron(expr, count=5)

