import re
from typing import List, Tuple

MAX_FRAME_CONTENT_BYTES = 4096
MAX_FRAME_HEADER_BYTES = 128
MAX_FRAME_BYTES = MAX_FRAME_HEADER_BYTES + MAX_FRAME_CONTENT_BYTES + 1

_FRAME_HEADER = re.compile(
    rb"\[([A-Za-z0-9_-]{1,16})\*([A-Za-z0-9_.-]{1,64})\*([0-9A-Fa-f]{2,4})\*"
)

# Kept for callers that use the public pattern to identify frame-shaped data.
FRAME_REGEX = re.compile(
    rb"^\[[A-Za-z0-9_-]{1,16}\*[A-Za-z0-9_.-]{1,64}\*[0-9A-Fa-f]{2,4}\*.*\]$",
    re.DOTALL,
)


def _next_frame_start(buffer: bytes, start: int) -> int:
    return buffer.find(b"[", start + 1)


def _recover_after_malformed_frame(buffer: bytes, start: int, payload_start: int, expected_end: int) -> int:
    next_start = buffer.find(b"[", start + 1, expected_end + 1)
    closing = buffer.find(b"]", payload_start, expected_end)
    if next_start >= 0 and (closing < 0 or next_start < closing):
        return next_start
    if closing >= 0:
        return closing + 1
    next_start = _next_frame_start(buffer, expected_end)
    return next_start if next_start >= 0 else len(buffer)


def extract_frames_with_errors(buffer: bytes) -> Tuple[List[Tuple[str, str, bytes]], bytes, int]:
    """Extract complete length-checked frames and retain only a partial tail."""
    frames: List[Tuple[str, str, bytes]] = []
    rejected = 0
    cursor = 0

    while cursor < len(buffer):
        start = buffer.find(b"[", cursor)
        if start < 0:
            if buffer[cursor:].strip():
                rejected += 1
            return frames, b"", rejected
        if start > cursor:
            rejected += 1

        header = _FRAME_HEADER.match(buffer, start)
        if header is None:
            closing = buffer.find(b"]", start + 1)
            next_start = _next_frame_start(buffer, start)
            if next_start >= 0 and (closing < 0 or next_start < closing):
                rejected += 1
                cursor = next_start
                continue
            if closing >= 0:
                rejected += 1
                cursor = closing + 1
                continue
            if len(buffer) - start > MAX_FRAME_HEADER_BYTES:
                rejected += 1
                cursor = start + 1
                continue
            return frames, buffer[start:], rejected

        content_length = int(header.group(3), 16)
        payload_start = header.end()
        expected_end = payload_start + content_length
        if content_length > MAX_FRAME_CONTENT_BYTES:
            rejected += 1
            cursor = _recover_after_malformed_frame(buffer, start, payload_start, expected_end)
            continue

        if len(buffer) <= expected_end:
            if len(buffer) - start > MAX_FRAME_BYTES:
                rejected += 1
                cursor = start + 1
                continue
            return frames, buffer[start:], rejected

        if buffer[expected_end] != ord("]"):
            rejected += 1
            cursor = _recover_after_malformed_frame(buffer, start, payload_start, expected_end)
            continue

        frames.append(
            (
                header.group(1).decode("ascii"),
                header.group(2).decode("ascii"),
                buffer[payload_start:expected_end],
            )
        )
        cursor = expected_end + 1

    return frames, b"", rejected


def extract_frames(buffer: bytes) -> Tuple[List[Tuple[str, str, bytes]], bytes]:
    """Backward-compatible frame extraction interface."""
    frames, remainder, _ = extract_frames_with_errors(buffer)
    return frames, remainder


def is_valid_frame(frame: str) -> bool:
    try:
        frame_bytes = frame.encode("latin1")
    except UnicodeEncodeError:
        return False
    header = _FRAME_HEADER.match(frame_bytes)
    if header is None:
        return False
    content_length = int(header.group(3), 16)
    if content_length > MAX_FRAME_CONTENT_BYTES:
        return False
    expected_end = header.end() + content_length
    return expected_end == len(frame_bytes) - 1 and frame_bytes[-1:] == b"]"
