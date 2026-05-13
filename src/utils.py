import sys
import time
from typing import Iterable, TypeVar

T = TypeVar("T")
_COLORS = sys.stderr.isatty()
_RESET  = "\033[0m"  if _COLORS else ""
_BOLD   = "\033[1m"  if _COLORS else ""
_CYAN   = "\033[36m" if _COLORS else ""
_YELLOW = "\033[33m" if _COLORS else ""
_RED    = "\033[31m" if _COLORS else ""
_GREEN  = "\033[32m" if _COLORS else ""
_DIM    = "\033[2m"  if _COLORS else ""

def _ts() -> str:
    return time.strftime("%H:%M:%S")

def log_info(msg: str) -> None:
    print(f"{_DIM}{_ts()}{_RESET}  {_CYAN}{_BOLD}[INFO]{_RESET}  {msg}")

def log_warn(msg: str) -> None:
    print(f"{_DIM}{_ts()}{_RESET}  {_YELLOW}{_BOLD}[WARN]{_RESET}  {msg}", file=sys.stderr)

def log_fail(msg: str) -> None:
    print(f"{_DIM}{_ts()}{_RESET}  {_RED}{_BOLD}[FAIL]{_RESET}  {msg}", file=sys.stderr)

def log_ok(msg: str) -> None:
    print(f"{_DIM}{_ts()}{_RESET}  {_GREEN}{_BOLD}[INFO]{_RESET}  {_GREEN}OK{_RESET}  {msg}")

class ProgressBar:
    BAR_WIDTH = 36
    def __init__(self, total: int, label: str = "") -> None:
        self.total = max(total, 1)
        self.label = label
        self._current = 0
        self._start = time.monotonic()
        self._tty = sys.stderr.isatty()
        if self._tty:
            self.render()

    def advance(self, n: int = 1) -> None:
        self._current = min(self._current + n, self.total)
        if self._tty:
            self.render()

    def finish(self) -> None:
        self._current = self.total
        if self._tty:
            self.render()
            sys.stderr.write("\n")
            sys.stderr.flush()

    def render(self) -> None:
        pct = self._current / self.total
        filled = int(pct * self.BAR_WIDTH)
        bar = "#" * filled + "-" * (self.BAR_WIDTH - filled)
        elapsed = time.monotonic() - self._start
        label_part = f"  {self.label}" if self.label else ""
        line = (
            f"\r{_DIM}[{_RESET}{_CYAN}{bar}{_RESET}{_DIM}]{_RESET}"
            f"  {_BOLD}{int(pct * 100):3d}%{_RESET}"
            f"  {self._current}/{self.total}"
            f"  {_DIM}{elapsed:.1f}s{_RESET}"
            f"{label_part}"
        )
        sys.stderr.write(line)
        sys.stderr.flush()

def iter_progress(items: list[T], label: str = "") -> Iterable[T]:
    bar = ProgressBar(total=len(items), label=label)
    for item in items:
        yield item
        bar.advance()
    bar.finish()
