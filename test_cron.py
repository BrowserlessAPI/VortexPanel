from croniter import croniter, CroniterBadCronError
from datetime import datetime, timezone
import sys

def test_cron_schedule(expression, num_occurrences=10, base_time=None):
    """
    Test a cron schedule expression and display useful information.
    
    Args:
        expression: Cron expression string (5 or 6 fields)
        num_occurrences: Number of upcoming occurrences to display
        base_time: Base datetime to calculate from (defaults to now)
    """
    print("=" * 60)
    print(f"  CRON SCHEDULE TESTER")
    print("=" * 60)
    print(f"  Expression : {expression}")

    if base_time is None:
        base_time = datetime.now()

    print(f"  Base Time  : {base_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Validate the expression
    if not croniter.is_valid(expression):
        print(f"\n  ❌ ERROR: '{expression}' is NOT a valid cron expression!")
        print("\n  Valid format: [minute] [hour] [day] [month] [weekday]")
        print("  Example:  */15 * * * *   → every 15 minutes")
        print("            0 9 * * 1-5    → 9 AM on weekdays")
        print("            0 0 1 * *      → midnight on 1st of each month")
        return

    print(f"\n  ✅ Valid cron expression!\n")

    # Parse the fields
    fields = expression.strip().split()
    labels = ["Minute", "Hour", "Day (Month)", "Month", "Day (Week)"]
    if len(fields) == 6:
        labels = ["Second", "Minute", "Hour", "Day (Month)", "Month", "Day (Week)"]

    print("  Field Breakdown:")
    for label, field in zip(labels, fields):
        print(f"    {label:<15}: {field}")

    print()

    # Calculate upcoming occurrences
    cron = croniter(expression, base_time)
    print(f"  Next {num_occurrences} Occurrences:")
    print(f"  {'#':<4} {'Date & Time':<30} {'From Now'}")
    print(f"  {'-'*4} {'-'*30} {'-'*20}")

    now = datetime.now()
    for i in range(1, num_occurrences + 1):
        next_run = cron.get_next(datetime)
        delta = next_run - now
        total_seconds = int(delta.total_seconds())

        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        if days > 0:
            relative = f"in {days}d {hours}h {minutes}m"
        elif hours > 0:
            relative = f"in {hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            relative = f"in {minutes}m {seconds}s"
        else:
            relative = f"in {seconds}s"

        print(f"  {i:<4} {next_run.strftime('%Y-%m-%d %H:%M:%S (%A)'):<30} {relative}")

    # Calculate interval statistics
    cron2 = croniter(expression, base_time)
    times = [cron2.get_next(datetime) for _ in range(20)]
    intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
    avg_interval = sum(intervals) / len(intervals)
    min_interval = min(intervals)
    max_interval = max(intervals)

    def fmt_seconds(s):
        s = int(s)
        if s < 60:
            return f"{s} sec"
        elif s < 3600:
            return f"{s//60} min {s%60} sec"
        elif s < 86400:
            return f"{s//3600} hr {(s%3600)//60} min"
        else:
            return f"{s//86400} day(s) {(s%86400)//3600} hr"

    print()
    print("  Interval Statistics (based on next 20 runs):")
    print(f"    Average interval : {fmt_seconds(avg_interval)}")
    print(f"    Min interval     : {fmt_seconds(min_interval)}")
    print(f"    Max interval     : {fmt_seconds(max_interval)}")
    print()

    # Runs per time period
    cron3 = croniter(expression, base_time)
    runs_per_hour = sum(1 for _ in range(1000) if cron3.get_next(datetime) - base_time <= __import__('datetime').timedelta(hours=1))
    cron4 = croniter(expression, base_time)
    runs_per_day = sum(1 for _ in range(1000) if cron4.get_next(datetime) - base_time <= __import__('datetime').timedelta(days=1))
    cron5 = croniter(expression, base_time)
    runs_per_week = sum(1 for _ in range(10000) if cron5.get_next(datetime) - base_time <= __import__('datetime').timedelta(weeks=1))

    print("  Frequency Estimate:")
    print(f"    Runs per hour  : ~{runs_per_hour}")
    print(f"    Runs per day   : ~{runs_per_day}")
    print(f"    Runs per week  : ~{runs_per_week}")
    print()
    print("=" * 60)


# --- Test multiple common cron schedules ---
schedules_to_test = [
    ("* * * * *",        "Every minute"),
    ("*/15 * * * *",     "Every 15 minutes"),
    ("0 * * * *",        "Every hour (at :00)"),
    ("0 9 * * 1-5",      "9 AM on weekdays (Mon-Fri)"),
    ("0 0 * * *",        "Daily at midnight"),
    ("0 0 1 * *",        "Monthly (1st of each month at midnight)"),
    ("30 8 * * 1",       "Every Monday at 8:30 AM"),
    ("0 0 * * 0",        "Every Sunday at midnight"),
    ("0 6,12,18 * * *",  "Three times daily: 6 AM, 12 PM, 6 PM"),
    ("INVALID_EXPR",     "Invalid expression test"),
]

for expr, description in schedules_to_test:
    print(f"\n  📌 Description: {description}")
    try:
        test_cron_schedule(expr, num_occurrences=5)
    except CroniterBadCronError as e:
        print(f"  ❌ CroniterBadCronError: {e}")
    print()

