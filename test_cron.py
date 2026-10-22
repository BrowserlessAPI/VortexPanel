from croniter import croniter, CroniterBadCronError, CroniterBadDateError
from datetime import datetime, timezone
import sys

# ── Common cron expressions to test ──────────────────────────────────────────
EXAMPLES = [
    ("* * * * *",        "Every minute"),
    ("*/15 * * * *",     "Every 15 minutes"),
    ("0 * * * *",        "Every hour (on the hour)"),
    ("0 9 * * *",        "Every day at 09:00"),
    ("0 9 * * 1-5",      "Weekdays at 09:00"),
    ("0 9 * * 1",        "Every Monday at 09:00"),
    ("0 0 1 * *",        "First day of every month at midnight"),
    ("0 0 1 1 *",        "Every January 1st at midnight (yearly)"),
    ("30 6 * * 0,6",     "Weekends at 06:30"),
    ("0 */6 * * *",      "Every 6 hours"),
    ("0 9,17 * * 1-5",   "Weekdays at 09:00 and 17:00"),
    ("INVALID CRON",     "❌ Bad expression (should fail gracefully)"),
]

HOW_MANY_NEXT = 5          # next N occurrences to display
BASE_TIME     = datetime.now(timezone.utc).replace(second=0, microsecond=0)

# ── Helpers ───────────────────────────────────────────────────────────────────
def describe_field(value, unit):
    if value == "*":
        return f"every {unit}"
    if value.startswith("*/"):
        return f"every {value[2:]} {unit}(s)"
    if "-" in value:
        a, b = value.split("-", 1)
        return f"{unit}s {a}–{b}"
    if "," in value:
        return f"{unit}s {value}"
    return f"{unit} {value}"

WEEKDAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
MONTH_NAMES   = ["Jan","Feb","Mar","Apr","May","Jun",
                 "Jul","Aug","Sep","Oct","Nov","Dec"]

def human_readable(expr):
    parts = expr.split()
    if len(parts) != 5:
        return "  ⚠  Cannot parse (need exactly 5 fields)"
    minute, hour, dom, month, dow = parts
    return (
        f"  minute : {describe_field(minute, 'minute')}\n"
        f"  hour   : {describe_field(hour,   'hour')}\n"
        f"  day/mo : {describe_field(dom,    'day-of-month')}\n"
        f"  month  : {describe_field(month,  'month')}\n"
        f"  day/wk : {describe_field(dow,    'day-of-week')}"
    )

def test_expression(expr, label):
    print(f"\n{'='*62}")
    print(f"  EXPRESSION : {expr}")
    print(f"  LABEL      : {label}")
    print(f"{'='*62}")

    try:
        cron = croniter(expr, BASE_TIME)
    except (CroniterBadCronError, CroniterBadDateError, KeyError, ValueError) as e:
        print(f"  ❌  INVALID EXPRESSION — {e}")
        return

    print("  ✅  Valid expression")
    print(human_readable(expr))

    print(f"\n  Next {HOW_MANY_NEXT} occurrences (from {BASE_TIME.strftime('%Y-%m-%d %H:%M')} UTC):")
    cron2 = croniter(expr, BASE_TIME)          # fresh iterator
    for i in range(HOW_MANY_NEXT):
        nxt = cron2.get_next(datetime)
        print(f"    {i+1}. {nxt.strftime('%Y-%m-%d %H:%M %Z')}")

    print(f"\n  Previous {HOW_MANY_NEXT} occurrences:")
    cron3 = croniter(expr, BASE_TIME)
    for i in range(HOW_MANY_NEXT):
        prv = cron3.get_prev(datetime)
        print(f"    {i+1}. {prv.strftime('%Y-%m-%d %H:%M %Z')}")

# ── Run tests ─────────────────────────────────────────────────────────────────
print(f"\n{'#'*62}")
print(f"  CRON SCHEDULE TESTER")
print(f"  Reference time : {BASE_TIME.strftime('%Y-%m-%d %H:%M')} UTC")
print(f"{'#'*62}")

for expr, label in EXAMPLES:
    test_expression(expr, label)

print(f"\n{'#'*62}")
print("  ALL TESTS COMPLETE")
print(f"{'#'*62}\n")
