"""Exercise the real PHPFixes stdio protocol and its inspection boundary."""
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEST_DIR = Path(__file__).resolve().parent
REPO = TEST_DIR.parent
SERVER_PATH = REPO / "skills/phpfixes-php2shell/php2shell/mcp_server.py"
if not SERVER_PATH.is_file():
    SERVER_PATH = TEST_DIR / "fixture/skill/php2shell/mcp_server.py"
SKILL = SERVER_PATH.parent.parent
spec = importlib.util.spec_from_file_location("phpfixes_mcp_test_module", SERVER_PATH)
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)


def request(method, params=None, request_id=1):
    data = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        data["params"] = params
    return data


def initialize(version="2025-11-25", request_id=1):
    return request("initialize", {"protocolVersion": version, "capabilities": {},
        "clientInfo": {"name": "isolated-test", "version": "1"}}, request_id)


def ready(server):
    response = server.handle(initialize())
    assert "result" in response
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    return server


def wire(messages):
    return b"".join(json.dumps(x, separators=(",", ":")).encode() + b"\n" for x in messages)


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.stat().st_size, p.stat().st_mode & 0o777,
        hashlib.sha256(p.read_bytes()).hexdigest()) for p in root.rglob("*") if p.is_file()}


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = snapshot(SKILL)
        cls.evidence = json.loads((SKILL / "examples/mixed-workers.json").read_text())
        cls.inventory = json.loads((SKILL / "examples/local-inventory.json").read_text())

    @classmethod
    def tearDownClass(cls):
        if snapshot(SKILL) != cls.original:
            raise AssertionError("MCP checks changed bundled files")

    def setUp(self):
        self.server = mcp.Server()

    def call(self, name, arguments, server=None):
        return (server or self.server).handle(request("tools/call", {"name": name,
            "arguments": arguments}, 20))

    def test_initialize_negotiates_both_implemented_legacy_revisions(self):
        for version in mcp.PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                response = mcp.Server().handle(initialize(version))["result"]
                self.assertEqual(response["protocolVersion"], version)
                self.assertEqual(response["capabilities"], {"tools": {"listChanged": False}})
                self.assertEqual(response["serverInfo"], {"name": "phpfixes-local", "version": "1.2.1"})

    def test_newer_revision_negotiates_legacy_without_claiming_mcp_v2(self):
        response = self.server.handle(initialize("2026-07-28"))["result"]
        self.assertEqual(response["protocolVersion"], "2025-11-25")

    def test_discovery_probe_is_unknown_and_does_not_break_initialize(self):
        response = self.server.handle(request("server/discover", {}))
        self.assertEqual(response["error"]["code"], -32601)
        self.assertIn("result", self.server.handle(initialize()))

    def test_tools_require_initialize_and_initialized_notification(self):
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            self.assertEqual(self.call("php2shell_collect_local", {"authorized": True})["error"]["code"], -32002)
            self.server.handle(initialize())
            self.assertEqual(self.server.handle(request("tools/list"))["error"]["code"], -32002)
            self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.assertIn("tools", self.server.handle(request("tools/list"))["result"])
            collect.assert_not_called()

    def test_duplicate_initialize_does_not_reset_ready_connection(self):
        ready(self.server)
        self.assertEqual(self.server.handle(initialize())["error"]["code"], -32602)
        self.assertIn("result", self.server.handle(request("tools/list")))

    def test_ping_needs_no_local_metadata_and_no_initialize(self):
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            self.assertEqual(self.server.handle(request("ping"))["result"], {})
            collect.assert_not_called()

    def test_unknown_method_and_unknown_tool_are_protocol_errors(self):
        ready(self.server)
        self.assertEqual(self.server.handle(request("unknown"))["error"]["code"], -32601)
        self.assertEqual(self.call("unknown-tool", {})["error"]["code"], -32602)

    def test_tool_catalog_has_stable_three_tools_and_no_file_path_argument(self):
        ready(self.server)
        tools = self.server.handle(request("tools/list"))["result"]["tools"]
        self.assertEqual([x["name"] for x in tools], ["php2shell_assess_evidence",
            "php2shell_check_inventory", "php2shell_collect_local"])
        for tool in tools:
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertFalse(tool["inputSchema"]["additionalProperties"])
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertFalse(tool["annotations"]["openWorldHint"])
            self.assertNotIn("path", tool["inputSchema"]["properties"])

    def test_all_notifications_are_silent_and_cannot_collect(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            for method, params in [("tools/call", {"name": "php2shell_collect_local", "arguments": {"authorized": True}}),
                    ("notifications/cancelled", {"requestId": 1}), ("unknown", {}), ("ping", {})]:
                self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": method, "params": params}))
            collect.assert_not_called()

    def test_invalid_request_shapes_ids_and_batches_have_sanitized_errors(self):
        for value in [[], {}, {"jsonrpc": "1.0", "id": 1, "method": "ping"},
                request("ping", request_id=None), request("ping", request_id=True),
                request("ping", request_id=1.2), request("ping", request_id=2 ** 64),
                {**request("ping"), "secret-private-field": "do-not-repeat"}]:
            with self.subTest(value=type(value).__name__):
                response = self.server.handle(value)
                self.assertEqual(response["error"]["code"], -32600)
                self.assertNotIn("do-not-repeat", json.dumps(response))

    def test_unknown_error_id_is_omitted_and_known_valid_error_id_is_echoed(self):
        self.assertNotIn("id", self.server.handle({}))
        self.assertNotIn("id", self.server.handle(request("ping", request_id=None)))
        malformed = {"jsonrpc": "2.0", "id": "known-id", "method": 123}
        self.assertEqual(self.server.handle(malformed)["id"], "known-id")

    def test_unknown_outer_tool_args_are_rejected_without_inspection(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            for args in [{}, {"authorized": True, "path": "/private/do-not-repeat"},
                    {"authorized": True, "command": "anything"}]:
                response = self.call("php2shell_collect_local", args)["result"]
                self.assertTrue(response["isError"])
                self.assertNotIn("do-not-repeat", json.dumps(response))
            collect.assert_not_called()

    def test_collection_requires_true_not_truthy_values(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            for value in [False, None, 1, "true", {}, []]:
                self.assertTrue(self.call("php2shell_collect_local", {"authorized": value})["result"]["isError"])
            collect.assert_not_called()

    def test_collection_occurs_only_after_explicit_authorized_tool_call(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local", return_value=copy.deepcopy(self.inventory)) as collect:
            response = self.call("php2shell_collect_local", {"authorized": True})["result"]
            collect.assert_called_once_with()
            self.assertFalse(response["isError"])
            self.assertEqual(response["structuredContent"]["inventory"], self.inventory)

    def test_collection_failure_does_not_disclose_os_error_paths(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local", side_effect=OSError("/private/secret-token")):
            response = self.call("php2shell_collect_local", {"authorized": True})["result"]
            self.assertTrue(response["isError"])
            self.assertNotIn("secret-token", json.dumps(response))

    def test_saved_evidence_exactly_matches_published_helper(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            response = self.call("php2shell_assess_evidence", {"evidence": copy.deepcopy(self.evidence)})["result"]
            actual = response["structuredContent"]
            now = dt.datetime.fromisoformat(actual["assessed_at"].replace("Z", "+00:00"))
            expected = self.server.assess.assess(copy.deepcopy(self.evidence), now=now)
            self.assertEqual(actual, expected)
            self.assertEqual(json.loads(response["content"][0]["text"]), actual)
            collect.assert_not_called()

    def test_saved_inventory_exactly_matches_published_helper(self):
        ready(self.server)
        with mock.patch.object(self.server.inventory, "collect_local") as collect:
            response = self.call("php2shell_check_inventory", {"inventory": copy.deepcopy(self.inventory)})["result"]
            actual = response["structuredContent"]
            now = dt.datetime.fromisoformat(actual["assessment"]["assessed_at"].replace("Z", "+00:00"))
            self.assertEqual(actual, self.server.inventory.diagnose(copy.deepcopy(self.inventory), now=now))
            self.assertEqual(json.loads(response["content"][0]["text"]), actual)
            collect.assert_not_called()

    def test_bad_saved_payload_is_a_tool_error_without_echoing_unknown_keys(self):
        ready(self.server)
        for name, key in [("php2shell_assess_evidence", "evidence"), ("php2shell_check_inventory", "inventory")]:
            for value in [{"private-secret-field": "do-not-repeat"}, "/private/path", None, []]:
                response = self.call(name, {key: value})["result"]
                self.assertTrue(response["isError"])
                self.assertNotIn("private-secret", json.dumps(response))
                self.assertNotIn("do-not-repeat", json.dumps(response))

    def test_malformed_utf8_duplicate_fields_nan_and_deep_json_are_rejected(self):
        for raw in [b'{bad}\n', b'\xff\n', b'{"jsonrpc":"2.0","jsonrpc":"2.0"}\n',
                b'{"id":NaN}\n', b'{"id":1e999}\n', b'[' * 100 + b'0' + b']' * 100 + b'\n']:
            with self.subTest(size=len(raw)):
                out = io.BytesIO()
                self.assertEqual(self.server.serve(io.BytesIO(raw), out), 0)
                response = json.loads(out.getvalue())
                self.assertEqual(response["error"]["code"], -32700)
                self.assertNotIn("id", response)

    def test_oversized_and_unterminated_lines_close_without_processing_more(self):
        for raw in [b'x' * (mcp.MAX_MESSAGE_BYTES + 1) + b'\n' + wire([initialize()]), b'{}']:
            out = io.BytesIO()
            self.assertEqual(self.server.serve(io.BytesIO(raw), out), 2)
            lines = out.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["error"]["code"], -32700)

    def test_response_limit_never_sends_a_partial_report(self):
        out = io.BytesIO()
        response = mcp.result(1, mcp.tool_result({"oversized": "x" * mcp.MAX_RESPONSE_BYTES}))
        self.server.write(out, response)
        self.assertLessEqual(len(out.getvalue()) - 1, mcp.MAX_RESPONSE_BYTES)
        result = json.loads(out.getvalue())
        self.assertIn("error", result)
        self.assertNotIn("oversized", out.getvalue().decode())

    def test_wire_messages_are_one_json_object_per_line(self):
        messages = [request("server/discover", {}), initialize(),
            {"jsonrpc": "2.0", "method": "notifications/initialized"}, request("ping", request_id=2),
            request("tools/call", {"name": "php2shell_assess_evidence", "arguments": {"evidence": self.evidence}}, 3)]
        process = subprocess.run([sys.executable, "-I", "-B", str(SERVER_PATH)],
            input=wire(messages), capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(process.stderr, b"")
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([x["id"] for x in responses], [1, 1, 2, 3])
        self.assertEqual(responses[0]["error"]["code"], -32601)
        self.assertIn("structuredContent", responses[-1]["result"])

    def test_startup_handshake_and_saved_calls_cannot_read_collector_sources_or_use_network(self):
        # Real process audit hook rejects collection paths, subprocess and network access.
        launcher = '''import sys,runpy
sys.dont_write_bytecode=True
def audit(event,args):
 if event in ("open","os.scandir") and args:
  path=str(args[0])
  if path.startswith(("/proc","/var/lib/dpkg","/etc/os-release","/usr/lib/os-release")):
   raise PermissionError("unexpected local inspection")
 if event.startswith("socket.") or event in ("subprocess.Popen","os.system"):
  raise PermissionError("unexpected external operation")
sys.addaudithook(audit)
runpy.run_path(sys.argv[1],run_name="__main__")
'''
        messages = [initialize(), {"jsonrpc": "2.0", "method": "notifications/initialized"},
            request("tools/list", request_id=2), request("tools/call", {"name": "php2shell_check_inventory", "arguments": {"inventory": self.inventory}}, 3)]
        # run_path sees no script arguments after the path, as in the real launcher.
        launcher = launcher.replace('runpy.run_path(sys.argv[1],run_name="__main__")',
            'path=sys.argv[1];sys.argv=[path];runpy.run_path(path,run_name="__main__")')
        process = subprocess.run([sys.executable, "-I", "-B", "-c", launcher, str(SERVER_PATH)],
            input=wire(messages), capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(process.stderr, b"")
        self.assertEqual(len(process.stdout.splitlines()), 3)
        self.assertFalse(json.loads(process.stdout.splitlines()[-1])["result"]["isError"])

    def test_empty_eof_is_clean_and_cli_arguments_are_refused(self):
        for args, expected in [([], 0), (["--input", "/private/secret-token"], 2)]:
            process = subprocess.run([sys.executable, "-I", "-B", str(SERVER_PATH), *args],
                input=b"", capture_output=True, timeout=10)
            self.assertEqual(process.returncode, expected)
            self.assertEqual(process.stdout, b"")
            self.assertNotIn(b"secret-token", process.stderr)


if __name__ == "__main__":
    unittest.main()
