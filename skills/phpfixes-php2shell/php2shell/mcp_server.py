#!/usr/bin/env python3
"""Declared offline PHPFixes tools over legacy MCP newline-delimited stdio.

Place beside the bundled assess.py and inventory.py. Startup reads bundled code,
facts and schemas only. Only the explicitly authorized collection tool inspects
local Linux metadata; the other tools consume JSON objects supplied in requests.
"""
import importlib
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SERVER_VERSION = "1.2.0"
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18")
MAX_MESSAGE_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 40000
MAX_ID = 2 ** 63 - 1


class InvalidInput(ValueError):
    pass


def fields(value, required=(), optional=()):
    if (not isinstance(value, dict) or not set(required) <= value.keys()
            or value.keys() - set(required) - set(optional)):
        raise InvalidInput()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput()
        result[key] = value
    return result


def reject_constant(value):
    raise InvalidInput()


def bounded_integer(value):
    if len(value.lstrip("-")) > 20:
        raise InvalidInput()
    return int(value)


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise InvalidInput()
    return number


def valid_id(value):
    return ((type(value) is int and -MAX_ID <= value <= MAX_ID)
            or (isinstance(value, str) and 0 < len(value) <= 256))


def check_tree(value):
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise InvalidInput()
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def decode_message(payload):
    value = json.loads(payload.decode("utf-8", errors="strict"),
                       object_pairs_hook=unique_pairs,
                       parse_constant=reject_constant, parse_int=bounded_integer, parse_float=finite_float)
    check_tree(value)
    return value


def error(request_id, code, message):
    response = {"jsonrpc": "2.0", "error": {"code": code, "message": message}}
    if request_id is not None:
        response["id"] = request_id
    return response


def result(request_id, value):
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def tool_error(message):
    return {"content": [{"type": "text", "text": message}], "isError": True}


def tool_result(report):
    return {"content": [{"type": "text", "text": json.dumps(
                report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))}],
            "structuredContent": report, "isError": False}


def load_helpers():
    # No working-directory, environment-selected or caller-selected import path.
    sys.path.insert(0, str(HERE))
    modules = []
    for name in ("assess", "inventory"):
        module = importlib.import_module(name)
        if Path(module.__file__).resolve() != HERE / (name + ".py"):
            raise InvalidInput()
        modules.append(module)
    return modules


def argument_schema(name, filename):
    schema = json.loads((HERE.parent / "data" / filename).read_text(encoding="utf-8"))
    schema.pop("$schema", None)
    schema.pop("$id", None)
    definitions = schema.pop("$defs", None)
    outer = {"type": "object", "properties": {name: schema},
             "required": [name], "additionalProperties": False}
    if definitions is not None:
        outer["$defs"] = definitions
    return outer


class Server:
    def __init__(self):
        self.assess, self.inventory = load_helpers()
        self.phase = "new"
        self.protocol = None
        annotations = {"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": False}
        self.tools = [
            {"name": "php2shell_assess_evidence", "title": "Assess supplied PHP2Shell evidence",
             "description": "Assess the supplied evidence object using bundled dated facts. "
                "Keeps installed and running findings separate. No local inspection, file paths, "
                "PHP execution, network or changes. Supply authorized evidence schema version 1.",
             "inputSchema": argument_schema("evidence", "evidence.schema.json"),
             "outputSchema": {"type": "object"}, "annotations": dict(annotations)},
            {"name": "php2shell_check_inventory", "title": "Check supplied PHP inventory",
             "description": "Normalize and diagnose the supplied minimal inventory object. "
                "Does not collect metadata or inspect the local system. No file-path input, "
                "PHP execution, network or changes. Supply inventory format version 1.",
             "inputSchema": argument_schema("inventory", "inventory.schema.json"),
             "outputSchema": {"type": "object"}, "annotations": dict(annotations)},
            {"name": "php2shell_collect_local", "title": "Collect an explicitly authorized local PHP inventory",
             "description": "Inspect bounded package and process metadata in this local Linux "
                "namespace only after the user directly requests that inspection and confirms "
                "authorization. Pass authorized:true only for that request. No PHP, subprocesses, "
                "network, credentials, environment, command lines, configuration, logs or changes. "
                "A three-second scan budget is soft; coverage can be limited and fix status unknown.",
             "inputSchema": {"type": "object", "properties": {
                 "authorized": {"type": "boolean", "const": True,
                    "description": "The user requested local inspection and is authorized to inspect this namespace."}},
                 "required": ["authorized"], "additionalProperties": False},
             "outputSchema": {"type": "object"}, "annotations": dict(annotations)},
        ]

    def initialize(self, params):
        fields(params, ("protocolVersion", "capabilities", "clientInfo"), ("_meta",))
        if (not isinstance(params["protocolVersion"], str)
                or not 0 < len(params["protocolVersion"]) <= 100
                or not isinstance(params["capabilities"], dict)):
            raise InvalidInput()
        info = params["clientInfo"]
        if (not isinstance(info, dict)
                or any(not isinstance(info.get(key), str) or not 0 < len(info[key]) <= 200
                       for key in ("name", "version"))):
            raise InvalidInput()
        if "_meta" in params and not isinstance(params["_meta"], dict):
            raise InvalidInput()
        if self.phase != "new":
            raise InvalidInput()
        requested = params["protocolVersion"]
        self.protocol = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        self.phase = "waiting-for-initialized"
        return {"protocolVersion": self.protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "phpfixes-local", "version": SERVER_VERSION}}

    def call_tool(self, params):
        fields(params, ("name",), ("arguments", "_meta"))
        if "_meta" in params and not isinstance(params["_meta"], dict):
            raise InvalidInput()
        name = params["name"]
        if not isinstance(name, str) or name not in {tool["name"] for tool in self.tools}:
            raise InvalidInput()
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            raise InvalidInput()
        expected = {"php2shell_assess_evidence": "evidence",
                    "php2shell_check_inventory": "inventory",
                    "php2shell_collect_local": "authorized"}[name]
        try:
            fields(args, (expected,))
        except InvalidInput:
            return tool_error("Tool arguments have missing or unsupported fields; use this tool's input schema.")
        if name == "php2shell_collect_local" and args["authorized"] is not True:
            return tool_error("Local collection was not authorized. The user must explicitly request "
                              "and authorize inspection of this local Linux namespace.")
        if name != "php2shell_collect_local" and not isinstance(args[expected], dict):
            return tool_error("The supplied evidence or inventory must be a JSON object matching its schema.")
        try:
            if name == "php2shell_assess_evidence":
                report = self.assess.assess(args["evidence"])
            elif name == "php2shell_check_inventory":
                report = self.inventory.diagnose(args["inventory"])
            else:
                report = self.inventory.diagnose(self.inventory.collect_local())
            return tool_result(report)
        except (self.assess.EvidenceError, OSError, UnicodeError, ValueError, TypeError,
                KeyError, OverflowError, RecursionError):
            return tool_error("Supplied records or local metadata could not be processed safely. "
                              "No fixed finding was made. Check the documented input schema and coverage.")

    def handle(self, message):
        # JSON-RPC notifications never receive replies and never run a tool.
        request_id = (message.get("id") if isinstance(message, dict)
                      and valid_id(message.get("id")) else None)
        notification = (isinstance(message, dict) and "id" not in message
                        and message.get("jsonrpc") == "2.0"
                        and isinstance(message.get("method"), str))
        try:
            fields(message, ("jsonrpc", "method"), ("id", "params"))
            if message["jsonrpc"] != "2.0" or not isinstance(message["method"], str):
                raise InvalidInput()
            method = message["method"]
            if not 0 < len(method) <= 128:
                raise InvalidInput()
            if not notification:
                if not valid_id(message["id"]):
                    raise InvalidInput()
                request_id = message["id"]
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise InvalidInput()
        except (InvalidInput, TypeError):
            return None if notification else error(request_id, -32600, "Invalid JSON-RPC request.")
        if notification:
            if method == "notifications/initialized" and self.phase == "waiting-for-initialized":
                try:
                    fields(params, optional=("_meta",))
                    if "_meta" in params and not isinstance(params["_meta"], dict):
                        raise InvalidInput()
                    self.phase = "ready"
                except InvalidInput:
                    pass
            return None
        try:
            if method == "initialize":
                return result(request_id, self.initialize(params))
            if method == "ping":
                fields(params, optional=("_meta",))
                if "_meta" in params and not isinstance(params["_meta"], dict):
                    raise InvalidInput()
                return result(request_id, {})
            if method not in ("tools/list", "tools/call"):
                return error(request_id, -32601, "Method not found.")
            if self.phase != "ready":
                return error(request_id, -32002, "Initialize this MCP connection before using tools.")
            if method == "tools/list":
                fields(params, optional=("_meta",))
                if "_meta" in params and not isinstance(params["_meta"], dict):
                    raise InvalidInput()
                return result(request_id, {"tools": self.tools})
            return result(request_id, self.call_tool(params))
        except InvalidInput:
            return error(request_id, -32602, "Invalid method parameters or unknown tool.")
        except Exception:
            return error(request_id, -32603, "The bundled PHPFixes tool could not complete safely.")

    @staticmethod
    def write(output, response):
        try:
            payload = json.dumps(response, ensure_ascii=True, allow_nan=False,
                                 separators=(",", ":")).encode("utf-8")
            if len(payload) > MAX_RESPONSE_BYTES:
                payload = json.dumps(error(response.get("id"), -32603,
                    "Result exceeds the response limit; supply fewer records."),
                    separators=(",", ":")).encode("utf-8")
        except (ValueError, TypeError, RecursionError):
            payload = json.dumps(error(None, -32603, "Response could not be encoded safely.")).encode("utf-8")
        output.write(payload + b"\n")
        output.flush()

    def serve(self, input_stream, output_stream):
        while True:
            line = input_stream.readline(MAX_MESSAGE_BYTES + 2)
            if not line:
                return 0
            if not line.endswith(b"\n") or len(line) - 1 > MAX_MESSAGE_BYTES:
                self.write(output_stream, error(None, -32700,
                    "Message is oversized or missing its newline; closing this connection."))
                return 2
            try:
                message = decode_message(line[:-1])
            except (InvalidInput, ValueError, UnicodeError, RecursionError, OverflowError):
                self.write(output_stream, error(None, -32700, "Invalid UTF-8 JSON message."))
                continue
            response = self.handle(message)
            if response is not None:
                self.write(output_stream, response)


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        sys.stderr.write("PHPFixes MCP accepts no command-line arguments.\n")
        return 2
    try:
        server = Server()
        return server.serve(sys.stdin.buffer, sys.stdout.buffer)
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except Exception:
        sys.stderr.write("PHPFixes bundled MCP server could not start or continue safely.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
