import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class BlockScheduler:
    """Checks scheduled blocks and applies/removes firewall rules as needed."""

    def __init__(self, firewall, app):
        self.firewall = firewall
        self.app = app

    def tick(self):
        """Call this periodically (e.g. every minute) to enforce schedules."""
        with self.app.app_context():
            self._enforce_schedules()

    def _enforce_schedules(self):
        from app.models import ScheduledBlock, Device
        from app import db

        now = datetime.now()
        current_day = now.weekday()   # 0=Monday
        current_minutes = now.hour * 60 + now.minute

        blocks = ScheduledBlock.query.filter_by(is_active=True).all()
        for block in blocks:
            device = block.device
            if not device or not device.ip:
                continue

            try:
                days = [int(d) for d in block.days.split(',')]
            except ValueError:
                continue

            if current_day not in days:
                continue

            start_m = block.start_hour * 60 + block.start_minute
            end_m = block.end_hour * 60 + block.end_minute

            should_block = self._in_range(current_minutes, start_m, end_m)

            if should_block and not device.is_blocked:
                logger.info(f"Schedule: blocking {device.ip} ({device.display_name})")
                self.firewall.block_ip(device.ip)
                device.is_blocked = True
                db.session.commit()
            elif not should_block and device.is_blocked:
                # Only unblock if the block was schedule-driven
                # (don't unblock manually blocked devices)
                sched_driven = any(
                    self._has_active_schedule(b, now)
                    for b in device.scheduled_blocks
                    if b.is_active
                )
                if not sched_driven:
                    logger.info(f"Schedule: unblocking {device.ip} ({device.display_name})")
                    self.firewall.unblock_ip(device.ip)
                    device.is_blocked = False
                    db.session.commit()

    def _in_range(self, current: int, start: int, end: int) -> bool:
        """Check if current minute-of-day is within [start, end). Handles overnight ranges."""
        if start <= end:
            return start <= current < end
        else:
            # Overnight: e.g. 23:00 to 08:00
            return current >= start or current < end

    def _has_active_schedule(self, block, now: datetime) -> bool:
        try:
            days = [int(d) for d in block.days.split(',')]
        except ValueError:
            return False
        current_day = now.weekday()
        if current_day not in days:
            return False
        current_minutes = now.hour * 60 + now.minute
        start_m = block.start_hour * 60 + block.start_minute
        end_m = block.end_hour * 60 + block.end_minute
        return self._in_range(current_minutes, start_m, end_m)
