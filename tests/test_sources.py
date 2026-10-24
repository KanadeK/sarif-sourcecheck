import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sarif_sourcecheck.cli import main
from sarif_sourcecheck.core import InputError, check, load_report


def document(location=None, region=None, **run_fields):
    physical = {"artifactLocation": location or {"uri": "app.py"}}
    if region is not None:
        physical["region"] = region
    return {
        "version": "2.1.0",
        "runs": [{"results": [{"locations": [{"physicalLocation": physical}]}], **run_fields}],
    }


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "checkout"
        self.root.mkdir()
        self.source = self.root / "app.py"
        self.source.write_bytes(b"first\r\nsecond\r\n")
        self.report = self.base / "report.sarif"

    def code(self, report, **options):
        return next(iter(check(report, self.root, **options)["codes"]))

    def test_relative_and_absolute_local_uri(self):
        for location in [{"uri": "app.py"}, {"uri": self.source.as_uri()}]:
            with self.subTest(location=location):
                result = check(document(location, {"startLine": 2}), self.root)
                self.assertTrue(result["passed"])
                self.assertEqual(result["receipts"][0]["path"], "app.py")

    def test_monorepo_mapping_and_chained_bases(self):
        folder = self.root / "packages/api"
        folder.mkdir(parents=True)
        (folder / "app.py").write_text("x\n", encoding="utf-8")
        report = document(
            {"uri": "app.py", "uriBaseId": "API"},
            originalUriBaseIds={
                "OLD": {"uri": "file:///stale/build/"},
                "API": {"uri": "packages/api/", "uriBaseId": "OLD"},
            },
        )
        self.assertFalse(check(report, self.root)["passed"])
        self.assertTrue(check(report, self.root, base_maps={"OLD": "."})["passed"])
        self.assertTrue(check(report, self.root, base_maps={"API": "packages/api"})["passed"])

    def test_base_errors(self):
        for bases, code in [
            ({}, "unknown_base_id"),
            ({"A": {"uri": "x/", "uriBaseId": "A"}}, "base_cycle_or_invalid"),
            ({"A": {"uri": "folder"}}, "base_not_directory"),
        ]:
            self.assertEqual(
                self.code(document({"uri": "app.py", "uriBaseId": "A"}, originalUriBaseIds=bases)),
                code,
            )

    def test_mapping_errors(self):
        for maps in [
            {"A": "../"},
            {"A": str(self.root)},
            {"A": "missing"},
            {"A": "C:/outside"},
            {"A": "some\\folder"},
            {"": "."},
            {"A": 1},
        ]:
            with self.subTest(maps=maps), self.assertRaises(InputError):
                check(document(), self.root, base_maps=maps)

    def test_percent_encoding_and_literal_percent(self):
        (self.root / "with space é.py").write_text("x", encoding="utf-8")
        self.assertEqual(self.code(document({"uri": "with%20space%20%C3%A9.py"})), "resolved")
        (self.root / "%2e%2e").write_text("x", encoding="utf-8")
        self.assertEqual(self.code(document({"uri": "%252e%252e"})), "resolved")

    def test_uri_refusals(self):
        cases = {
            "with space.py": "invalid_uri",
            "x%XX.py": "invalid_uri",
            "x\\y": "invalid_uri",
            "https://example.com/a": "nonlocal_uri",
            "file://remote/app.py": "nonlocal_uri",
            "app.py?x=1": "nonlocal_uri",
            "app.py#x": "nonlocal_uri",
            "x%00": "unsafe_path",
            "%FF": "invalid_uri_encoding",
            "a%5Cb": "unsafe_path",
            "file:///foo:stream": "unsafe_path",
            "app.py:stream": "nonlocal_uri",
            "./app.py:stream": "unsafe_path",
        }
        for uri, code in cases.items():
            with self.subTest(uri=uri):
                self.assertEqual(self.code(document({"uri": uri})), code)

    def test_traversal_and_foreign_root(self):
        (self.base / "secret.py").write_text("private-example", encoding="utf-8")
        for uri in ["../secret.py", "%2e%2e/secret.py", (self.base / "secret.py").as_uri()]:
            with self.subTest(uri=uri):
                self.assertEqual(self.code(document({"uri": uri})), "outside_checkout")

    def test_symlink_escape(self):
        outside = self.base / "outside.py"
        outside.write_text("private-example", encoding="utf-8")
        try:
            (self.root / "link.py").symlink_to(outside)
        except OSError:
            self.skipTest("Host does not permit symlink creation")
        self.assertEqual(self.code(document({"uri": "link.py"})), "outside_checkout")

    def test_missing_directory_and_size(self):
        self.assertEqual(self.code(document({"uri": "missing.py"})), "missing_or_unreadable_source")
        self.assertEqual(self.code(document({"uri": "."})), "not_regular_file")
        self.assertEqual(self.code(document(), max_source_bytes=2), "source_too_large")

    def test_line_ranges(self):
        for region, code in [
            ({"startLine": 1, "endLine": 2}, "resolved"),
            ({"startLine": 3}, "line_out_of_range"),
            ({"startLine": 0}, "invalid_line_range"),
            ({"startLine": True}, "invalid_line_range"),
            ({"startLine": 2, "endLine": 1}, "invalid_line_range"),
            ({"startLine": "1"}, "invalid_line_range"),
        ]:
            with self.subTest(region=region):
                self.assertEqual(self.code(document(region=region)), code)
        self.source.write_bytes(b"")
        self.assertEqual(self.code(document(region={"startLine": 1})), "line_out_of_range")
        self.source.write_bytes(b"a\rb\rc")
        self.assertEqual(self.code(document(region={"endLine": 3})), "resolved")
        self.source.write_bytes(b"\xff")
        self.assertEqual(
            self.code(document(region={"startLine": 1})), "source_encoding_unsupported"
        )

    def test_index_and_hash(self):
        descriptor = {
            "location": {"uri": "app.py"},
            "hashes": {"sha-256": hashlib.sha256(self.source.read_bytes()).hexdigest().upper()},
        }
        report = document({"index": 0}, artifacts=[descriptor])
        result = check(report, self.root)
        self.assertEqual(result["sha256_checked"], 1)
        self.assertTrue(result["passed"])
        descriptor["hashes"]["sha-256"] = "0" * 64
        self.assertEqual(self.code(report), "sha256_mismatch")
        descriptor["hashes"]["sha-256"] = "not-a-hash"
        self.assertEqual(self.code(report), "invalid_sha256")
        self.assertEqual(
            self.code(document({"index": 5}, artifacts=[descriptor])), "invalid_artifact_index"
        )
        self.assertEqual(
            self.code(document({"index": True}, artifacts=[descriptor])), "invalid_artifact_index"
        )
        self.assertEqual(
            self.code(document({"index": 0}, artifacts=[{}])), "indexed_artifact_has_no_uri"
        )

    def test_index_uri_conflict(self):
        artifacts = [{"location": {"uri": "app.py"}}]
        self.assertEqual(
            self.code(document({"uri": "app.py", "index": 0}, artifacts=artifacts)), "resolved"
        )
        self.assertEqual(
            self.code(document({"uri": "other.py", "index": 0}, artifacts=artifacts)),
            "artifact_reference_conflict",
        )

    def test_nested_locations_and_extension_bags(self):
        report = document()
        run = report["runs"][0]
        nested = {"location": {"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}}
        run["results"][0]["codeFlows"] = [{"threadFlows": [{"locations": [nested]}]}]
        run["results"][0]["relatedLocations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}
        ]
        run["properties"] = {"physicalLocation": {"artifactLocation": {"uri": "secret"}}}
        run["private-example"] = {"physicalLocation": {"artifactLocation": {"uri": "secret"}}}
        self.assertEqual(check(report, self.root)["locations_checked"], 3)

    def test_receipt_bound_and_non_disclosure(self):
        report = document()
        report["runs"][0]["results"] *= 10
        result = check(report, self.root, receipt_limit=1)
        self.assertEqual(result["locations_checked"], 10)
        self.assertEqual(len(result["receipts"]), 1)
        self.assertTrue(result["receipts_truncated"])
        self.assertEqual(check(report, self.root, receipt_limit=0)["receipts"], [])
        report["runs"][0]["results"][0]["message"] = {"text": "private-example"}
        self.assertNotIn("private-example", json.dumps(check(report, self.root)))

    def test_empty_and_malformed(self):
        self.assertEqual(self.code({"version": "2.1.0", "runs": []}), "no_physical_locations")
        for report in [
            [],
            {},
            {"version": "1.0", "runs": []},
            {"version": "2.1.0", "runs": "wrong"},
            document(region=[]),
            document(artifacts="wrong"),
        ]:
            with self.subTest(report=report), self.assertRaises(InputError):
                check(report, self.root)
        for options in [{"receipt_limit": -1}, {"max_source_bytes": 0}]:
            with self.assertRaises(InputError):
                check(document(), self.root, **options)
        with self.assertRaises(InputError):
            check(document(), self.source)

    def test_json_loading(self):
        for data in [b'{"version":"2.1.0","version":"2.1.0"}', b'{"x":NaN}', b"\xff", b"{bad"]:
            self.report.write_bytes(data)
            with self.assertRaises(InputError):
                load_report(self.report)
        self.report.write_text(json.dumps(document()), encoding="utf-8-sig")
        self.assertTrue(check(load_report(self.report), self.root)["passed"])
        with self.assertRaises(InputError):
            load_report(self.report, 2)
        with self.assertRaises(InputError):
            load_report(self.report, 0)

    def test_read_only_and_cli(self):
        data = document()
        snapshot = copy.deepcopy(data)
        check(data, self.root)
        self.assertEqual(data, snapshot)
        self.report.write_text(json.dumps(data), encoding="utf-8")
        source_hash = hashlib.sha256(self.source.read_bytes()).digest()
        out, err = io.StringIO(), io.StringIO()
        args = [str(self.report), "--root", str(self.root)]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main([*args, "--json"]), 0)
            self.assertEqual(main(args), 0)
            self.assertEqual(main([*args, "--receipt-limit", "0"]), 0)
            self.assertEqual(main([*args, "--base", "bad"]), 2)
            self.assertEqual(main([*args, "--base", "A=.", "--base", "A=."]), 2)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).digest(), source_hash)
        self.source.unlink()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(args), 1)


if __name__ == "__main__":
    unittest.main()
