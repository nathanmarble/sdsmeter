"""python -m sds_meter: runs the overlay (meter.py)."""
from .meter import main, report_crash

try:
    main()
except Exception:
    report_crash()
