#!/usr/bin/env python3
"""
romloader.py — CoCo ROM/BIN file format detector and loader
Usage: python3 romloader.py <file>
"""

import sys
import argparse
import hashlib

# Known ROM fingerprints (MD5 of full ROM image)
KNOWN_ROMS = {
    "b507bd7de1fee2fd7db1dbe82e7ae15d": "Color BASIC 1.0 (1980)",
    "ac2a770d7ce8ba12d8f6b2e4bce2c710": "Color BASIC 1.1 (1982)",
    "d8a2340c0e63ce85e030fb5f61b3b50d": "Color BASIC 1.2 (1983)",
    "11162e1f3cea8f8c04f4d6c5f0add214": "Color BASIC 1.3 (1986, CoCo3)",
    "54726a53b9656f8f789e9956e00d8e5d": "Extended BASIC 1.0 (1982)",
    "2154c030ad8b21e5e1fecba36f059fee": "Extended BASIC 1.1 (1984, CoCo2)",
    "6f16b5b81be6f2d31bca57ff97eb6237": "Disk BASIC 1.0 (1981)",
    "22f7c6df3c834fe98ead85f5f3c57bfe": "Disk BASIC 1.1 (1984)",
    "07c4ed9e4026b6f4f9a5ff2f697e03f0": "Super Extended BASIC 2.0 (CoCo3)",
}


def identify_file(filepath: str) -> dict:
    """Analyze a binary file and identify its format and contents."""
    with open(filepath, "rb") as f:
        data = f.read()
    
    info = {
        "filename": filepath,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "format": "unknown",
        "segments": [],
        "exec_addr": None,
        "rom_id": None,
    }
    
    # Check known ROM fingerprints
    if info["md5"] in KNOWN_ROMS:
        info["rom_id"] = KNOWN_ROMS[info["md5"]]
        info["format"] = "rom_image"
    
    # Check for DECB BIN format
    if len(data) > 5 and data[0] == 0x00:
        segments, exec_addr = _try_decb(data)
        if segments:
            info["format"] = "decb_bin"
            info["segments"] = [(org, len(d)) for org, d in segments]
            info["exec_addr"] = exec_addr
    
    # Check for CAS (cassette) format
    if len(data) > 10:
        # Look for leader (0x55 bytes) followed by sync (0x3C)
        leader_pos = _find_cas_leader(data)
        if leader_pos is not None:
            info["format"] = "cas_tape"
            info["cas_header_offset"] = leader_pos
    
    # Common ROM sizes
    if info["format"] == "unknown":
        if len(data) == 8192:
            info["format"] = "rom_8k"
            info["note"] = "8K ROM image (standard CoCo ROM slot size)"
        elif len(data) == 16384:
            info["format"] = "rom_16k"
            info["note"] = "16K ROM image (two 8K slots or Extended BASIC)"
        elif len(data) == 32768:
            info["format"] = "rom_32k"
            info["note"] = "32K ROM image (full CoCo3 ROM space)"
        elif len(data) <= 65536:
            info["format"] = "raw_binary"
    
    # Check for reset vector (ROM images typically have valid vectors at end)
    if len(data) >= 2:
        last_two = (data[-2] << 8) | data[-1]
        if 0x8000 <= last_two <= 0xFFFF:
            info["possible_reset_vector"] = f"${last_two:04X}"
    
    # ASCII content check
    ascii_count = sum(1 for b in data if 32 <= b <= 126)
    info["ascii_ratio"] = ascii_count / len(data) if data else 0
    
    return info


def _try_decb(data: bytes):
    """Try to parse as DECB BIN format."""
    segments = []
    exec_addr = None
    pos = 0
    
    try:
        while pos < len(data):
            if data[pos] == 0x00:
                if pos + 4 >= len(data):
                    break
                length = (data[pos+1] << 8) | data[pos+2]
                addr = (data[pos+3] << 8) | data[pos+4]
                pos += 5
                if pos + length > len(data):
                    return [], None  # Invalid
                if length == 0 and addr == 0:
                    return [], None  # Probably not DECB
                seg_data = data[pos:pos+length]
                segments.append((addr, seg_data))
                pos += length
            elif data[pos] == 0xFF:
                if pos + 4 < len(data):
                    exec_addr = (data[pos+3] << 8) | data[pos+4]
                break
            else:
                if not segments:
                    return [], None  # Not DECB format
                break
    except Exception:
        return [], None
    
    return segments, exec_addr


def _find_cas_leader(data: bytes):
    """Look for CAS format leader + sync pattern."""
    # CAS format: series of 0x55 followed by 0x3C sync byte
    for i in range(len(data) - 2):
        if data[i] == 0x55 and data[i+1] == 0x55:
            # Found leader, look for sync
            j = i
            while j < len(data) and data[j] == 0x55:
                j += 1
            if j < len(data) and data[j] == 0x3C:
                return i
    return None


def print_report(info: dict):
    """Print human-readable file analysis report."""
    print("=" * 60)
    print(f"  CoCo Binary File Analysis")
    print("=" * 60)
    print(f"  File:    {info['filename']}")
    print(f"  Size:    {info['size']} bytes (${info['size']:04X})")
    print(f"  MD5:     {info['md5']}")
    print(f"  Format:  {info['format']}")
    
    if info.get("rom_id"):
        print(f"  ROM ID:  {info['rom_id']}")
    
    if info.get("note"):
        print(f"  Note:    {info['note']}")
    
    if info["segments"]:
        print(f"\n  Segments ({len(info['segments'])}):")
        for i, (org, size) in enumerate(info["segments"]):
            end = org + size - 1
            print(f"    [{i}] ${org:04X}-${end:04X}  ({size} bytes)")
    
    if info.get("exec_addr") is not None:
        print(f"\n  Exec Address: ${info['exec_addr']:04X}")
    
    if info.get("possible_reset_vector"):
        print(f"  Possible Reset Vector: {info['possible_reset_vector']}")
    
    if info.get("cas_header_offset") is not None:
        print(f"  CAS Leader at offset: {info['cas_header_offset']}")
    
    print(f"\n  ASCII ratio: {info['ascii_ratio']:.1%}")
    if info['ascii_ratio'] > 0.7:
        print("  (High ASCII ratio - may contain text/BASIC source)")
    
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="CoCo ROM/BIN File Analyzer")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()
    
    info = identify_file(args.file)
    
    if args.json:
        import json
        print(json.dumps(info, indent=2))
    else:
        print_report(info)


if __name__ == "__main__":
    main()
