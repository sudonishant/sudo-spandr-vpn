"""Anti-Replay window tracking and sequence gap detection (RFC 4303 Section 3.4.3)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AntiReplayWindow:
    """Sliding window tracking for ESP / AH sequence numbers."""
    window_size: int = 64
    highest_seq: int = 0
    bitmap: int = 0
    replayed_packets: int = 0
    out_of_order_packets: int = 0
    gaps_detected: int = 0

    def check_and_update(self, seq: int) -> bool:
        """Check if packet sequence number is valid and update the sliding bitmap.

        Returns:
            True if packet is fresh (accepted).
            False if packet is replayed or older than window (rejected).
        """
        if seq == 0:
            # Sequence number 0 is illegal in RFC 4303
            return False

        if self.highest_seq == 0:
            # First packet seen
            self.highest_seq = seq
            self.bitmap = 1
            return True

        diff = seq - self.highest_seq
        if diff > 0:
            # Newer packet arrived
            if diff > 1:
                self.gaps_detected += (diff - 1)
            if diff >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = ((self.bitmap << diff) | 1) & ((1 << self.window_size) - 1)
            self.highest_seq = seq
            return True
        else:
            # Older packet arrived
            behind = -diff
            if behind >= self.window_size:
                # Outside the sliding window: replay or excessively delayed
                self.replayed_packets += 1
                return False
            # Check if already seen in window
            bit = 1 << behind
            if self.bitmap & bit:
                self.replayed_packets += 1
                return False
            # Valid out-of-order packet within window
            self.bitmap |= bit
            self.out_of_order_packets += 1
            return True
