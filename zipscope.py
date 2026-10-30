#!/usr/bin/env python3
"""ZipScope 1.0.0: compare bounded ZIP central-directory metadata to a policy.

No member is opened, decompressed, extracted, executed, or modified. This is
not a ZIP integrity validator: local headers, payloads and CRCs are not checked.
"""

import argparse
import json
import os
import re
import stat
import struct
import sys
import unicodedata
from contextlib import contextmanager

VERSION = "1.0.0"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_CENTRAL_BYTES = 4 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_ENTRIES = 4096
MAX_NAME_BYTES = 1024
EOCD = struct.Struct("<4s4H2LH")
CENTRAL = struct.Struct("<4s6H3L5H2L")


class InputError(Exception):
    def __init__(self, code, path=None):
        self.code, self.path = code, path


@contextmanager
def regular_input(path, limit, kind):
    """Open read-only; refuse special files and input symlinks where supported."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise InputError(kind + "_not_regular")
            if info.st_size > limit:
                raise InputError(kind + "_size_limit")
            yield stream, info.st_size
            after = os.fstat(stream.fileno())
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise InputError(kind + "_changed_during_read")
    except OSError:
        raise InputError(kind + "_unreadable") from None


def path_problem(name, directory=False):
    if not name or len(name.encode("utf-8", errors="surrogatepass")) > MAX_NAME_BYTES:
        return "name_size"
    if any(unicodedata.category(c) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for c in name):
        return "control_character"
    if "\\" in name or ":" in name or name.startswith("/"):
        return "ambiguous_or_absolute_path"
    body = name[:-1] if directory and name.endswith("/") else name
    if not body or any(part in {"", ".", ".."} for part in body.split("/")):
        return "invalid_component"
    for part in body.split("/"):
        if part.endswith((" ", ".")) or re.fullmatch(
            r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part
        ):
            return "nonportable_component"
    return None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("policy_duplicate_key")
        result[key] = value
    return result


def load_policy(path):
    with regular_input(path, MAX_POLICY_BYTES, "policy") as (stream, _):
        raw = stream.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise InputError("policy_size_limit")
    try:
        policy = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InputError("policy_invalid_json") from None
    if (not isinstance(policy, dict) or set(policy) != {"version", "files"}
            or type(policy["version"]) is not int or policy["version"] != 1
            or not isinstance(policy["files"], list)
            or not 1 <= len(policy["files"]) <= MAX_ENTRIES):
        raise InputError("policy_invalid_schema")
    files = set()
    for name in policy["files"]:
        if not isinstance(name, str) or path_problem(name) is not None:
            raise InputError("policy_invalid_path")
        if name in files:
            raise InputError("policy_duplicate_path", name)
        files.add(name)
    validate_hierarchy(files, set(), "policy")
    return files


def validate_hierarchy(files, directories, kind):
    for name in sorted(files | directories):
        parts = name.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in files:
                raise InputError(kind + "_file_directory_collision", name)
    for name in sorted(files & directories):
        raise InputError(kind + "_file_directory_collision", name)


def central_bytes(stream, size):
    if size < EOCD.size:
        raise InputError("archive_invalid_metadata")
    # A bounded raw tail scan locates metadata; no member body is interpreted.
    tail_size = min(size, EOCD.size + 65535)
    stream.seek(size - tail_size)
    tail = stream.read(tail_size)
    candidates = []
    start = 0
    while True:
        index = tail.find(b"PK\x05\x06", start)
        if index < 0:
            break
        start = index + 1
        if index + EOCD.size <= len(tail):
            fields = EOCD.unpack_from(tail, index)
            if index + EOCD.size + fields[-1] == len(tail):
                candidates.append((size - tail_size + index, fields))
    if len(candidates) != 1:
        raise InputError("archive_invalid_or_ambiguous_trailer")
    offset, (_, disk, cd_disk, count_disk, count, cd_size, cd_offset, _) = candidates[0]
    if (disk or cd_disk or count_disk != count or count == 65535
            or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF):
        raise InputError("archive_zip64_or_multidisk_unsupported")
    if count > MAX_ENTRIES:
        raise InputError("archive_entry_limit")
    if cd_size > MAX_CENTRAL_BYTES:
        raise InputError("archive_central_size_limit")
    if cd_offset + cd_size != offset or (count == 0 and cd_offset != 0):
        raise InputError("archive_invalid_metadata")
    if offset >= 20:
        stream.seek(offset - 20)
        if stream.read(4) == b"PK\x06\x07":
            raise InputError("archive_zip64_or_multidisk_unsupported")
    stream.seek(cd_offset)
    data = stream.read(cd_size)
    if len(data) != cd_size:
        raise InputError("archive_invalid_metadata")
    return data, count, cd_offset


def validate_extra(extra):
    index = 0
    while index < len(extra):
        if index + 4 > len(extra):
            raise InputError("archive_invalid_extra")
        kind, size = struct.unpack_from("<HH", extra, index)
        index += 4
        if index + size > len(extra):
            raise InputError("archive_invalid_extra")
        if kind in {0x0001, 0x000D, 0x7075, 0x756E, 0x9901}:
            raise InputError("archive_extended_format_unsupported")
        index += size


def inventory(path):
    with regular_input(path, MAX_ARCHIVE_BYTES, "archive") as (stream, size):
        data, declared_count, cd_offset = central_bytes(stream, size)
        index = 0
        files, directories, seen = set(), set(), set()
        count = 0
        offsets = []
        while index < len(data):
            count += 1
            if count > MAX_ENTRIES:
                raise InputError("archive_entry_limit")
            if index + CENTRAL.size > len(data):
                raise InputError("archive_invalid_metadata")
            fields = CENTRAL.unpack_from(data, index)
            (magic, made, needed, flags, method, _, _, _, packed, unpacked,
             name_len, extra_len, comment_len, disk, _, attrs, local_offset) = fields
            end = index + CENTRAL.size + name_len + extra_len + comment_len
            if magic != b"PK\x01\x02" or end > len(data):
                raise InputError("archive_invalid_metadata")
            if not 1 <= name_len <= MAX_NAME_BYTES:
                raise InputError("archive_name_size_limit")
            if (disk or 0xFFFFFFFF in {packed, unpacked, local_offset}
                    or needed > 63 or flags & ~0x080E or method not in {0, 8, 12, 14}):
                raise InputError("archive_entry_format_unsupported")
            if local_offset >= cd_offset:
                raise InputError("archive_invalid_metadata")
            offsets.append(local_offset)
            raw = data[index + CENTRAL.size:index + CENTRAL.size + name_len]
            try:
                name = raw.decode("utf-8" if flags & 0x800 else "cp437")
            except UnicodeError:
                raise InputError("archive_invalid_name_encoding") from None
            directory = name.endswith("/")
            problem = path_problem(name, directory)
            if problem:
                raise InputError("archive_" + problem, name)
            if name in seen:
                raise InputError("archive_duplicate_path", name)
            seen.add(name)
            mode = (attrs >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode) if made >> 8 == 3 else 0
            if stat.S_IFMT(mode) == stat.S_IFLNK or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise InputError("archive_special_entry_unsupported", name)
            if (file_type == stat.S_IFDIR or attrs & 0x10) and not directory:
                raise InputError("archive_type_name_mismatch", name)
            if directory and (file_type == stat.S_IFREG or unpacked):
                raise InputError("archive_type_name_mismatch", name)
            extra_start = index + CENTRAL.size + name_len
            validate_extra(data[extra_start:extra_start + extra_len])
            if directory:
                directories.add(name[:-1])
            else:
                files.add(name)
            index = end
        if count != declared_count or (offsets and min(offsets) != 0):
            raise InputError("archive_invalid_metadata")
        validate_hierarchy(files, directories, "archive")
    return files, directories


def inspect(archive, policy):
    result = {"schema_version": 1, "status": "error", "missing": [],
              "unexpected": [], "issues": [], "counts": {}}
    try:
        expected = load_policy(policy)
        actual, directories = inventory(archive)
        result["missing"] = sorted(expected - actual)
        result["unexpected"] = sorted(actual - expected)
        result["counts"] = {"expected_files": len(expected), "archive_files": len(actual),
                            "directory_entries": len(directories)}
        code = int(bool(result["missing"] or result["unexpected"]))
        result["status"] = "findings" if code else "match"
    except InputError as error:
        issue = {"code": error.code}
        if error.path is not None:
            issue["path"] = error.path
        result["issues"] = [issue]
        code = 2
    return code, result


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = Parser(description="Compare ZIP metadata to an independently prepared file policy.",
                    allow_abbrev=False)
    parser.add_argument("archive", help="explicit ZIP input (regular file)")
    parser.add_argument("policy", help="UTF-8 JSON policy (regular file)")
    parser.add_argument("--json", action="store_true", help="deterministic JSON output")
    parser.add_argument("--version", action="version", version="ZipScope " + VERSION)
    option_args = argv[:argv.index("--")] if "--" in argv else argv
    json_output = "--json" in option_args
    try:
        args = parser.parse_args(argv)
        json_output = args.json
        code, result = inspect(args.archive, args.policy)
    except (InputError, KeyboardInterrupt) as error:
        code = 2
        result = {"schema_version": 1, "status": "error", "missing": [], "unexpected": [],
                  "issues": [{"code": getattr(error, "code", "interrupted")}], "counts": {}}
    if json_output:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print("ZipScope: " + {"match": "inventory matches policy", "findings": "inventory differs from policy",
                              "error": "comparison incomplete"}[result["status"]])
        for key in ["missing", "unexpected"]:
            for name in result[key]:
                print(key + ": " + json.dumps(name, ensure_ascii=True))
        for issue in result["issues"]:
            print("issue: " + issue["code"] + (" " + json.dumps(issue["path"], ensure_ascii=True)
                  if "path" in issue else ""))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
