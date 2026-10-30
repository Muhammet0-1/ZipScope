"""Synthetic-only behavioral, boundary, and no-side-effect checks."""
import ast
import bz2
import contextlib
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import zipscope as zs

SENTINEL = b"SYNTHETIC_BODY_MUST_NEVER_APPEAR_7d89"


class ZipScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "demo.zip"
        self.policy = self.root / "policy.json"
        self.write_policy(["README.md", "LICENSE", "tool.py"])

    def write_policy(self, files):
        self.policy.write_text(json.dumps({"version": 1, "files": files}), encoding="utf-8")

    def make_zip(self, names, compression=zipfile.ZIP_DEFLATED):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w", compression=compression) as output:
                for name in names:
                    output.writestr(name, b"" if str(name).endswith("/") else SENTINEL)
                output.comment = b"SYNTHETIC_COMMENT_MUST_NEVER_APPEAR"

    def inspect(self):
        return zs.inspect(self.archive, self.policy)

    def mutate_central(self, offset, fmt, value):
        data = bytearray(self.archive.read_bytes())
        index = data.index(b"PK\x01\x02")
        struct.pack_into(fmt, data, index + offset, value)
        self.archive.write_bytes(data)

    def assert_error(self, expected=None):
        code, result = self.inspect()
        self.assertEqual(code, 2, result)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], [])
        if expected:
            self.assertEqual(result["issues"][0]["code"], expected)

    def test_exact_match(self):
        self.make_zip(["tool.py", "README.md", "LICENSE"])
        code, result = self.inspect()
        self.assertEqual((code, result["status"]), (0, "match"))

    def test_extra_log_env_and_missing_docs(self):
        self.make_zip(["tool.py", "debug.log", ".env"])
        code, result = self.inspect()
        self.assertEqual(code, 1)
        self.assertEqual(result["missing"], ["LICENSE", "README.md"])
        self.assertEqual(result["unexpected"], [".env", "debug.log"])

    def test_directories_explicit_and_implicit(self):
        self.write_policy(["src/tool.py"])
        for names, dirs in [(["src/tool.py"], 0), (["src/", "src/tool.py", "empty/"], 2)]:
            with self.subTest(names=names):
                self.make_zip(names)
                code, result = self.inspect()
                self.assertEqual(code, 0, result)
                self.assertEqual(result["counts"]["directory_entries"], dirs)

    def test_unicode_is_exact_not_normalized(self):
        self.write_policy(["çözüm.py", "é.txt"])
        self.make_zip(["çözüm.py", "e\u0301.txt"])
        code, result = self.inspect()
        self.assertEqual(code, 1)
        self.assertEqual(result["missing"], ["é.txt"])
        self.assertEqual(result["unexpected"], ["e\u0301.txt"])

    def test_case_sensitive(self):
        self.write_policy(["Readme.md"])
        self.make_zip(["README.md"])
        self.assertEqual(self.inspect()[0], 1)

    def test_policy_empty_bad_schema_and_malformed(self):
        for raw in [b"", b" ", b"{", b"[]", b"{}", b"null", b"\xff", b'\xef\xbb\xbf{}',
                    b'{"version":1,"files":[]}', b'{"version":true,"files":["x"]}',
                    b'{"version":2,"files":["x"]}', b'{"version":1,"files":"x"}',
                    b'{"version":1,"files":[4]}', b'{"version":1,"files":["x"],"extra":0}']:
            with self.subTest(raw=raw):
                self.policy.write_bytes(raw)
                self.assert_error()

    def test_policy_duplicates_keys_and_paths(self):
        self.policy.write_text('{"version":1,"version":1,"files":["x"]}')
        self.assert_error("policy_duplicate_key")
        self.write_policy(["x", "x"])
        self.assert_error("policy_duplicate_path")

    def test_policy_invalid_paths(self):
        for name in ["", "src/", "../x", "/x", "a\\b", "a//b", "a/./b", "a\x1bb", "NUL"]:
            with self.subTest(name=name):
                self.write_policy([name])
                self.assert_error("policy_invalid_path")

    def test_policy_hierarchy_collision(self):
        self.write_policy(["a", "a/b"])
        self.assert_error("policy_file_directory_collision")

    def test_archive_duplicate_file_and_directory(self):
        for names in [["tool.py", "tool.py"], ["src/", "src/"]]:
            with self.subTest(names=names):
                self.make_zip(names)
                self.assert_error("archive_duplicate_path")

    def test_archive_unsafe_paths(self):
        for name in ["/etc/passwd", "../x", "a/../../x", "C:/x", "C:x", "//server/x",
                     "a\\b", "a//b", "./x", "a/./x", "a\x1bb", "x\ny", "x\ty",
                     "a\u202eb", "x\u2028y", "NUL", "a./b", "x /y"]:
            with self.subTest(name=name):
                self.make_zip([name])
                self.assert_error()

    def test_nul_is_not_truncated(self):
        self.make_zip(["abc"])
        data = self.archive.read_bytes().replace(b"abc", b"a\x00c")
        self.archive.write_bytes(data)
        self.assert_error("archive_control_character")

    def test_symlink_and_other_unix_types(self):
        for kind in [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR]:
            with self.subTest(kind=kind):
                info = zipfile.ZipInfo("link")
                info.create_system = 3
                info.external_attr = (kind | 0o777) << 16
                self.make_zip([info])
                self.assert_error("archive_special_entry_unsupported")

    def test_symlink_bits_with_dos_creator_refused(self):
        info = zipfile.ZipInfo("link")
        info.create_system = 0
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.make_zip([info])
        self.assert_error("archive_special_entry_unsupported")

    def test_archive_hierarchy_collisions(self):
        for names in [["a", "a/b"], ["a/", "a"]]:
            with self.subTest(names=names):
                self.make_zip(names)
                self.assert_error("archive_file_directory_collision")

    def test_bad_directory_metadata(self):
        info = zipfile.ZipInfo("dir/")
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        self.make_zip([info])
        self.assert_error("archive_type_name_mismatch")

    def test_broken_truncated_empty_and_unreadable_zip(self):
        for raw in [b"", b"bad zip", b"PK\x03\x04", b"PK\x05\x06" + b"\x00" * 8]:
            with self.subTest(raw=raw):
                self.archive.write_bytes(raw)
                self.assert_error()
        self.archive.unlink()
        self.assert_error("archive_unreadable")

    def test_unreadable_os_error_is_sanitized(self):
        with patch.object(zs.os, "open", side_effect=PermissionError("PRIVATE_PATH_SECRET")):
            code, result = self.inspect()
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE_PATH_SECRET", json.dumps(result))

    def test_unreadable_archive_permission_error(self):
        self.make_zip(["tool.py"])
        original_open = zs.os.open
        def fail_archive(path, flags):
            if Path(path) == self.archive:
                raise PermissionError("PRIVATE_ARCHIVE_PATH")
            return original_open(path, flags)
        with patch.object(zs.os, "open", side_effect=fail_archive):
            self.assert_error("archive_unreadable")

    def test_real_unreadable_archive_permissions(self):
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            self.skipTest("root bypasses normal mode permissions")
        self.make_zip(["tool.py"])
        self.archive.chmod(0)
        try:
            self.assert_error("archive_unreadable")
        finally:
            self.archive.chmod(0o600)

    def test_special_input_file_no_block(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unavailable")
        self.archive.unlink(missing_ok=True)
        os.mkfifo(self.archive)
        self.assert_error("archive_not_regular")

    def test_input_symlink_refused_on_linux(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW unavailable")
        self.make_zip(["tool.py"])
        target = self.root / "target.zip"
        self.archive.rename(target)
        self.archive.symlink_to(target)
        self.assert_error("archive_unreadable")

    def test_archive_size_boundary(self):
        self.make_zip(["tool.py"])
        size = self.archive.stat().st_size
        with patch.object(zs, "MAX_ARCHIVE_BYTES", size):
            self.assertEqual(self.inspect()[0], 1)
        with patch.object(zs, "MAX_ARCHIVE_BYTES", size - 1):
            self.assert_error("archive_size_limit")
        with self.archive.open("wb") as stream:
            stream.truncate(zs.MAX_ARCHIVE_BYTES + 1)
        self.assert_error("archive_size_limit")

    def test_policy_size_and_count_limits(self):
        self.policy.write_bytes(b" " * (zs.MAX_POLICY_BYTES + 1))
        self.assert_error("policy_size_limit")
        self.write_policy(["x" + str(i) for i in range(zs.MAX_ENTRIES + 1)])
        self.assert_error("policy_invalid_schema")

    def test_entry_limit_declared_and_actual(self):
        self.write_policy(["x"])
        self.make_zip(["x", "y"])
        with patch.object(zs, "MAX_ENTRIES", 1):
            self.assert_error("archive_entry_limit")
        data = bytearray(self.archive.read_bytes())
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<HH", data, end + 8, 1, 1)
        self.archive.write_bytes(data)
        with patch.object(zs, "MAX_ENTRIES", 1):
            self.assert_error("archive_entry_limit")

    def test_real_max_entry_boundary(self):
        names = ["x" + str(i) for i in range(zs.MAX_ENTRIES)]
        self.write_policy(names)
        self.make_zip(names)
        self.assertEqual(self.inspect()[0], 0)
        self.make_zip(names + ["overflow"])
        self.assert_error("archive_entry_limit")

    def test_central_size_boundary(self):
        self.make_zip(["tool.py"])
        data = self.archive.read_bytes()
        end = data.rindex(b"PK\x05\x06")
        size = struct.unpack_from("<L", data, end + 12)[0]
        with patch.object(zs, "MAX_CENTRAL_BYTES", size):
            self.assertEqual(self.inspect()[0], 1)
        with patch.object(zs, "MAX_CENTRAL_BYTES", size - 1):
            self.assert_error("archive_central_size_limit")

    def test_name_limit(self):
        self.make_zip(["x" * (zs.MAX_NAME_BYTES + 1)])
        self.assert_error("archive_name_size_limit")
        self.write_policy(["x" * (zs.MAX_NAME_BYTES + 1)])
        self.assert_error("policy_invalid_path")

    def test_unsupported_flags_method_zip64_and_multidisk(self):
        for offset, fmt, value in [(8, "<H", 1), (8, "<H", 64), (10, "<H", 99),
                                   (6, "<H", 64), (42, "<L", 0xFFFFFFFF)]:
            with self.subTest(offset=offset, value=value):
                self.make_zip(["tool.py"])
                self.mutate_central(offset, fmt, value)
                self.assert_error()
        self.make_zip(["tool.py"])
        data = bytearray(self.archive.read_bytes())
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<H", data, end + 4, 1)
        self.archive.write_bytes(data)
        self.assert_error("archive_zip64_or_multidisk_unsupported")

    def test_extra_fields_and_encoding(self):
        for extra in [b"x", struct.pack("<HH", 0x7075, 0), struct.pack("<HH", 1, 0),
                      struct.pack("<HH", 0x000D, 0), struct.pack("<HH", 0x756E, 0),
                      struct.pack("<HH", 0x9901, 0), struct.pack("<HH", 0x1234, 20)]:
            with self.subTest(extra=extra):
                info = zipfile.ZipInfo("tool.py")
                info.extra = extra
                self.make_zip([info])
                self.assert_error()
        self.make_zip(["abc"])
        self.mutate_central(8, "<H", 0x800)
        data = self.archive.read_bytes().replace(b"abc", b"\xffbc")
        self.archive.write_bytes(data)
        self.assert_error("archive_invalid_name_encoding")

    def test_central_count_and_signature_corruption(self):
        self.make_zip(["tool.py"])
        self.mutate_central(0, "<4s", b"NOPE")
        self.assert_error("archive_invalid_metadata")
        self.make_zip(["tool.py"])
        data = bytearray(self.archive.read_bytes())
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<HH", data, end + 8, 0, 0)
        self.archive.write_bytes(data)
        self.assert_error("archive_invalid_metadata")

    def test_empty_zip_is_missing_files(self):
        self.make_zip([])
        code, result = self.inspect()
        self.assertEqual(code, 1)
        self.assertEqual(result["missing"], ["LICENSE", "README.md", "tool.py"])

    def test_prefixed_empty_and_nonempty_archives_refused(self):
        for names in [[], ["tool.py"]]:
            with self.subTest(names=names):
                self.make_zip(names)
                data = bytearray(self.archive.read_bytes())
                end = data.rindex(b"PK\x05\x06")
                offset = struct.unpack_from("<L", data, end + 16)[0]
                struct.pack_into("<L", data, end + 16, offset + 4)
                if names:
                    central = data.index(b"PK\x01\x02")
                    struct.pack_into("<L", data, central + 42, 4)
                self.archive.write_bytes(b"STUB" + data)
                self.assert_error("archive_invalid_metadata")

    def test_cp437_legacy_name(self):
        self.write_policy(["é.txt"])
        self.make_zip(["a.txt"])
        self.archive.write_bytes(self.archive.read_bytes().replace(b"a.txt", b"\x82.txt"))
        self.assertEqual(self.inspect()[0], 0)

    def test_deterministic_text_json_and_no_body_or_comments(self):
        self.make_zip(["tool.py", "debug.log"])
        snapshots = []
        for extra in [[], ["--json"]]:
            for _ in range(2):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = zs.main([str(self.archive), str(self.policy)] + extra)
                self.assertEqual(code, 1)
                self.assertNotIn(SENTINEL.decode(), output.getvalue())
                self.assertNotIn("SYNTHETIC_COMMENT", output.getvalue())
                self.assertNotIn(str(self.root), output.getvalue())
                snapshots.append(output.getvalue())
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[2], snapshots[3])
        self.assertEqual(json.loads(snapshots[2])["status"], "findings")

    def test_control_name_rendered_safely(self):
        self.make_zip(["x\x1b[31m.py"])
        for extra in [[], ["--json"]]:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(zs.main([str(self.archive), str(self.policy)] + extra), 2)
            self.assertNotIn("\x1b", output.getvalue())
            self.assertIn("\\u001b", output.getvalue())

    def test_argument_errors_are_sanitized_in_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = zs.main(["--json", "--unknown\x1bSECRET"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["issues"], [{"code": "invalid_arguments"}])
        self.assertNotIn("SECRET", output.getvalue())

    def test_json_option_abbreviations_are_refused(self):
        self.make_zip(["README.md", "LICENSE", "tool.py"])
        for abbreviation in ["--j", "--js", "--jso"]:
            with self.subTest(abbreviation=abbreviation):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = zs.main([str(self.archive), str(self.policy), abbreviation])
                self.assertEqual(code, 2)
                self.assertTrue(output.getvalue().startswith("ZipScope: comparison incomplete"))

    def test_option_like_input_names_do_not_select_output_format(self):
        self.make_zip(["README.md", "LICENSE", "tool.py"])
        option_name = self.root / "--json"
        previous_directory = Path.cwd()
        try:
            os.chdir(self.root)
            self.archive.rename(option_name)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(zs.main(["--", "--json", "policy.json"]), 0)
            self.assertEqual(output.getvalue(), "ZipScope: inventory matches policy\n")
            option_name.rename(self.archive)
            self.policy.rename(option_name)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(zs.main(["--", "demo.zip", "--json"]), 0)
            self.assertEqual(output.getvalue(), "ZipScope: inventory matches policy\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(zs.main(["--json", "--", "demo.zip", "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "match")
        finally:
            os.chdir(previous_directory)

    def test_inputs_unchanged_and_no_body_network_or_shell_apis(self):
        self.make_zip(["README.md", "LICENSE", "tool.py"])
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in [self.archive, self.policy]]
        with contextlib.ExitStack() as stack:
            for owner, methods in [(zipfile.ZipFile, ["open", "read", "extract", "extractall", "testzip"]),
                                   (zlib, ["decompress", "decompressobj"]), (bz2, ["decompress", "BZ2Decompressor"]),
                                   (lzma, ["decompress", "LZMADecompressor"]),
                                   (socket, ["socket", "create_connection"]), (os, ["system", "popen"])]:
                for method in methods:
                    stack.enter_context(patch.object(owner, method, side_effect=AssertionError("forbidden API")))
            events = []
            enabled = [True]
            def audit(event, args):
                if enabled[0] and (event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn"))
                                   or event in {"os.system", "os.posix_spawn"}):
                    events.append(event)
                    raise AssertionError("forbidden audit event")
            sys.addaudithook(audit)
            try:
                self.assertEqual(self.inspect()[0], 0)
            finally:
                enabled[0] = False
            self.assertEqual(events, [])
        after = [hashlib.sha256(p.read_bytes()).hexdigest() for p in [self.archive, self.policy]]
        self.assertEqual(before, after)

    def test_payload_corruption_is_not_integrity_checked(self):
        self.write_policy(["tool.py"])
        self.make_zip(["tool.py"], zipfile.ZIP_STORED)
        self.archive.write_bytes(self.archive.read_bytes().replace(SENTINEL, b"X" * len(SENTINEL)))
        self.assertEqual(self.inspect()[0], 0)
        with zipfile.ZipFile(self.archive) as archive:
            with self.assertRaises(zipfile.BadZipFile):
                archive.read("tool.py")

    def test_runtime_source_has_no_network_shell_or_member_apis(self):
        tree = ast.parse(Path(zs.__file__).read_text())
        imports = {alias.name.split(".")[0] for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse(imports & {"socket", "subprocess", "urllib", "http", "zipfile", "zlib", "bz2", "lzma"})
        forbidden = {"extract", "extractall", "testzip", "system", "popen", "exec", "eval"}
        self.assertFalse({node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} & forbidden)


if __name__ == "__main__":
    unittest.main(verbosity=2)
