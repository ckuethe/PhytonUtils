"""Port of firmware/time.go."""

import datetime


class DateTime:
    """Port of firmware.DateTime (uint32 DOS-ish timestamp)."""

    def __init__(self, value=0):
        self._value = value & 0xFFFFFFFF

    @property
    def value(self):
        return self._value

    def time(self):
        high = (self._value >> 16) & 0xFFFF
        low = self._value & 0xFFFF

        year = ((high >> 9) & 127) + 1980
        month = (high >> 5) & 15
        day = high & 31
        hours = (low >> 11) & 31
        minutes = (low >> 5) & 63
        seconds = (low & 31) * 2

        return datetime.datetime(year, month, day, hours, minutes, seconds)

    def __str__(self):
        return self.time().isoformat(" ")
