#!/usr/bin/env python3
"""Decode one bounded Syslinux LSS16 splash to PPM and PNG.

The parser follows the public Syslinux lss16toppm format/decoding logic while
rejecting truncated input and recording malformed runs and unused payload.
It never loads or invokes code from the ISO.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from PIL import Image


MAGIC = 0x1413F33D  # little-endian bytes: 3d f3 13 14
HEADER_SIZE = 56
MAX_PIXELS = 16_000_000


class Nibbles:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.byte_pos = 0
        self.pending_high: int | None = None

    def reset_line(self) -> None:
        # Syslinux resets the nibble buffer at each scanline boundary.
        self.pending_high = None

    def get(self) -> int:
        if self.pending_high is not None:
            value = self.pending_high
            self.pending_high = None
            return value
        if self.byte_pos >= len(self.payload):
            raise ValueError("truncated RLE stream")
        byte = self.payload[self.byte_pos]
        self.byte_pos += 1
        self.pending_high = byte >> 4
        return byte & 0x0F


def decode(path: Path) -> tuple[Image.Image, dict[str, object]]:
    raw = path.read_bytes()
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"short header: {len(raw)} bytes")
    magic, width, height = struct.unpack_from("<IHH", raw)
    if magic != MAGIC:
        raise ValueError(f"bad LSS16 magic: 0x{magic:08x}")
    if width == 0 or height == 0 or width * height > MAX_PIXELS:
        raise ValueError(f"unsafe dimensions: {width}x{height}")

    palette_raw = raw[8:56]
    palette6 = [tuple(palette_raw[i:i + 3]) for i in range(0, 48, 3)]
    palette = [tuple((channel * 255 + 31) // 63 for channel in rgb) for rgb in palette6]
    nibbles = Nibbles(raw[HEADER_SIZE:])
    pixels = bytearray(width * height)
    anomalies: list[str] = []

    for y in range(height):
        nibbles.reset_line()
        x = 0
        last = 0
        while x < width:
            color = nibbles.get()
            if color != last:
                pixels[y * width + x] = color
                last = color
                x += 1
                continue

            count = nibbles.get()
            if count == 0:
                count = nibbles.get() + (nibbles.get() << 4) + 16
            remaining = width - x
            if count > remaining:
                anomalies.append(f"row {y}: run length {count} clipped to {remaining}")
                count = remaining
            pixels[y * width + x:y * width + x + count] = bytes([color]) * count
            x += count

    rgb = bytearray(width * height * 3)
    for i, idx in enumerate(pixels):
        rgb[3 * i:3 * i + 3] = bytes(palette[idx])
    image = Image.frombytes("RGB", (width, height), bytes(rgb))
    unused_bytes = len(raw) - HEADER_SIZE - nibbles.byte_pos
    info: dict[str, object] = {
        "input_bytes": len(raw),
        "header_bytes": HEADER_SIZE,
        "magic_hex": raw[:4].hex(" "),
        "width": width,
        "height": height,
        "palette_6bit": palette6,
        "palette_rgb8": palette,
        "rle_payload_bytes": len(raw) - HEADER_SIZE,
        "rle_bytes_consumed": nibbles.byte_pos,
        "unused_complete_bytes": unused_bytes,
        "unused_high_nibble_in_last_read_byte": nibbles.pending_high is not None,
        "run_anomalies": anomalies,
        "distinct_palette_indices_used": sorted(set(pixels)),
    }
    return image, info


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=repo / "output/iso-audit/iso-files/BOOT/ISOLINUX/SPLASH.RLE",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=repo / "output/iso-audit",
    )
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    image, info = decode(args.input)
    ppm_path = args.out_dir / "splash-decoded.ppm"
    png_path = args.out_dir / "splash-decoded.png"
    json_path = args.out_dir / "splash-decode-report.json"
    image.save(ppm_path, format="PPM")
    image.save(png_path, format="PNG", optimize=False)
    info.update({"input": str(args.input), "ppm": str(ppm_path), "png": str(png_path)})
    json_path.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
