"""Local WDL subset evaluator for tests, not an Azure runtime or deployment validator."""

from __future__ import annotations

import base64
import copy
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, unquote

from jsonschema import Draft4Validator


class Expression:
    def __init__(self, text: str):
        self.text = text
        self.index = 0

    def whitespace(self):
        while self.index < len(self.text) and self.text[self.index].isspace():
            self.index += 1

    def parse(self):
        result = self.value()
        self.whitespace()
        if self.index != len(self.text):
            raise ValueError(f"Unparsed WDL suffix: {self.text[self.index:]}")
        return result

    def value(self):
        self.whitespace()
        if self.text[self.index] == "'":
            self.index += 1
            value = ""
            while True:
                char = self.text[self.index]
                self.index += 1
                if char == "'":
                    if self.index < len(self.text) and self.text[self.index] == "'":
                        self.index += 1
                        value += "'"
                        continue
                    break
                value += char
            node = ("literal", value)
        elif self.text[self.index].isdigit() or self.text[self.index] == "-":
            match = re.match(r"-?[0-9]+(?:\.[0-9]+)?", self.text[self.index:])
            value = match.group()
            self.index += len(value)
            node = ("literal", float(value) if "." in value else int(value))
        else:
            match = re.match(r"[A-Za-z_][A-Za-z_0-9]*", self.text[self.index:])
            if match is None:
                raise ValueError(f"Invalid WDL near {self.text[self.index:]}")
            name = match.group()
            self.index += len(name)
            self.whitespace()
            if name in {"true", "false", "null"}:
                node = ("literal", {"true": True, "false": False, "null": None}[name])
            else:
                if self.text[self.index] != "(":
                    raise ValueError(f"Expected function call: {name}")
                self.index += 1
                args = []
                self.whitespace()
                while self.text[self.index] != ")":
                    args.append(self.value())
                    self.whitespace()
                    if self.text[self.index] == ",":
                        self.index += 1
                        continue
                    if self.text[self.index] != ")":
                        raise ValueError("Expected comma or closing parenthesis.")
                self.index += 1
                node = ("call", name, args)
        while True:
            self.whitespace()
            optional = False
            if self.index < len(self.text) and self.text[self.index] == "?":
                optional = True
                self.index += 1
            if self.index < len(self.text) and self.text[self.index] == "[":
                self.index += 1
                key = self.value()
                self.whitespace()
                if self.text[self.index] != "]":
                    raise ValueError("Expected property closing bracket.")
                self.index += 1
                node = ("property", node, key, optional)
            elif self.index < len(self.text) and self.text[self.index] == ".":
                self.index += 1
                match = re.match(r"[A-Za-z_][A-Za-z_0-9]*", self.text[self.index:])
                self.index += len(match.group())
                node = ("property", node, ("literal", match.group()), optional)
            else:
                if optional:
                    raise ValueError("Incomplete optional property.")
                return node


def check_parse_json_schema(value):
    if isinstance(value, dict):
        unsupported = {"pattern", "patternProperties"}.intersection(value)
        if unsupported:
            raise ValueError("Unsupported native ParseJson schema keyword: " + ", ".join(sorted(unsupported)))
        for child in value.values():
            check_parse_json_schema(child)
    elif isinstance(value, list):
        for child in value:
            check_parse_json_schema(child)


def stringify(value):
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class LocalWorkflow:
    def __init__(self, trigger=None, parameters=None, variables=None, transport=None):
        self.trigger = trigger or {}
        self.parameters = parameters or {}
        self.variables = copy.deepcopy(variables or {})
        self.transport = transport
        self.outputs = {}
        self.status = {}
        self.current_items = {}
        self.item = None
        self.response = None
        self.clock = datetime(2026, 10, 21, 3, tzinfo=timezone.utc)
        self.compiled = {}

    def evaluate(self, node):
        kind = node[0]
        if kind == "literal":
            return node[1]
        if kind == "property":
            value = self.evaluate(node[1])
            key = self.evaluate(node[2])
            if value is None and node[3]:
                return None
            if isinstance(value, dict):
                return value.get(key)
            return value[key]
        name = node[1].lower()
        if name == "if":
            return self.evaluate(node[2][1] if self.evaluate(node[2][0]) else node[2][2])
        args = [self.evaluate(arg) for arg in node[2]]
        if name == "variables": return self.variables[args[0]]
        if name == "parameters": return self.parameters[args[0]]
        if name == "triggerbody": return self.trigger
        if name == "items": return self.current_items[args[0]]
        if name == "item": return self.item
        if name == "outputs": return self.outputs.get(args[0])
        if name == "body": return (self.outputs.get(args[0]) or {}).get("body")
        if name == "actions": return {"status": self.status.get(args[0], "Skipped")}
        if name == "workflow": return {"id": "/test/workflow", "run": {"name": "local-no-mail"}}
        if name == "result": return [{"name": args[0], "status": self.status.get(args[0], "Failed")}]
        if name == "json": return json.loads(args[0])
        if name == "string": return stringify(args[0])
        if name == "int": return int(args[0])
        if name == "length": return len(args[0])
        if name == "empty": return not args[0]
        if name == "concat": return "".join(stringify(value) for value in args)
        if name == "coalesce": return next((value for value in args if value is not None), None)
        if name == "and": return all(args)
        if name == "or": return any(args)
        if name == "not": return not args[0]
        if name == "equals": return args[0] == args[1]
        if name == "greater": return args[0] > args[1]
        if name == "greaterorequals": return args[0] >= args[1]
        if name == "less": return args[0] < args[1]
        if name == "lessorequals": return args[0] <= args[1]
        if name == "contains":
            if isinstance(args[0], str) and isinstance(args[1], str): return args[1].lower() in args[0].lower()
            return args[1] in args[0]
        if name == "join": return args[1].join(args[0])
        if name == "startswith": return args[0].startswith(args[1])
        if name == "endswith": return args[0].endswith(args[1])
        if name == "add": return args[0] + args[1]
        if name == "sub": return args[0] - args[1]
        if name == "mul": return args[0] * args[1]
        if name == "div": return args[0] // args[1]
        if name == "max": return max(args)
        if name == "replace": return args[0].replace(args[1], args[2])
        if name == "split": return args[0].split(args[1])
        if name == "skip": return args[0][args[1]:]
        if name == "take": return args[0][:args[1]]
        if name == "first": return args[0][0]
        if name == "last": return args[0][-1]
        if name == "substring":
            start = args[1]
            end = start + args[2] if len(args) == 3 else len(args[0])
            if start < 0 or start > len(args[0]) or end > len(args[0]):
                raise ValueError("Substring range is outside the string.")
            return args[0][start:end]
        if name == "sort": return sorted(args[0], key=lambda value: value[args[1]]) if len(args) == 2 else sorted(args[0])
        if name == "setproperty": return {**args[0], args[1]: args[2]}
        if name == "removeproperty": return {key: value for key, value in args[0].items() if key != args[1]}
        if name == "union":
            if isinstance(args[0], dict):
                result = {}
                for value in args: result.update(value)
                return result
            result = []
            for values in args:
                for value in values:
                    if value not in result: result.append(value)
            return result
        if name == "decodeuricomponent": return unquote(args[0])
        if name == "encodeuricomponent": return quote(args[0], safe="")
        if name == "base64": return base64.b64encode(args[0].encode("utf-8")).decode("ascii")
        if name == "base64tostring": return base64.b64decode(args[0], validate=True).decode("utf-8")
        if name == "base64tobinary": return base64.b64decode(args[0], validate=True)
        if name == "utcnow": return self.clock.isoformat().replace("+00:00", "Z")
        if name == "guid": return "00000000-0000-0000-0000-000000000001"
        if name in {"ticks", "formatdatetime", "adddays", "addseconds", "convertfromutc", "converttimezone"}:
            stamp = datetime.fromisoformat(args[0].replace("Z", "+00:00"))
            if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
            if name == "ticks": return int(stamp.timestamp() * 10_000_000)
            if name == "adddays": stamp += timedelta(days=args[1])
            if name == "addseconds": stamp += timedelta(seconds=args[1])
            if name == "convertfromutc": stamp = stamp.astimezone(timezone(timedelta(hours=9)))
            if name == "converttimezone":
                stamp = datetime.fromisoformat(args[0]).replace(tzinfo=timezone(timedelta(hours=9))).astimezone(timezone.utc)
            pattern = args[-1] if name in {"formatdatetime", "converttimezone"} else None
            if pattern == "yyyy-MM-dd": return stamp.date().isoformat()
            if pattern == "HH": return f"{stamp.hour:02d}"
            if pattern == "yyyy-MM-ddTHH:mm:ss": return stamp.strftime("%Y-%m-%dT%H:%M:%S")
            if pattern == "yyyy-MM-ddTHH:mm:ss.fffZ": return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if pattern == "r": return stamp.strftime("%a, %d %b %Y %H:%M:%S GMT")
            return stamp.isoformat().replace("+00:00", "Z")
        raise ValueError(f"Unsupported local WDL function: {node[1]}")

    def resolve(self, value):
        if isinstance(value, str) and value.startswith("@"):
            if value.startswith("@@"): return value[1:]
            if value not in self.compiled:
                self.compiled[value] = Expression(value[1:]).parse()
            return self.evaluate(self.compiled[value])
        if isinstance(value, list):
            return [self.resolve(item) for item in value]
        if isinstance(value, dict):
            return {key: self.resolve(item) for key, item in value.items()}
        return value

    def run(self, actions):
        for name, action in actions.items():
            allowed = all(self.status.get(previous) in states for previous, states in action.get("runAfter", {}).items())
            if not allowed:
                self.status[name] = "Skipped"
                self.outputs[name] = None
                continue
            self.execute(name, action)
            self.status[name] = "Succeeded"
        return self.response

    def execute(self, name, action):
        kind = action["type"]
        if kind == "InitializeVariable":
            for variable in action["inputs"]["variables"]:
                self.variables[variable["name"]] = copy.deepcopy(self.resolve(variable["value"]))
        elif kind == "SetVariable":
            self.variables[action["inputs"]["name"]] = copy.deepcopy(self.resolve(action["inputs"]["value"]))
        elif kind in {"AppendToStringVariable", "AppendToArrayVariable", "IncrementVariable"}:
            key = action["inputs"]["name"]; value = self.resolve(action["inputs"]["value"])
            if kind == "AppendToArrayVariable": self.variables[key].append(copy.deepcopy(value))
            else: self.variables[key] += value
        elif kind == "Compose":
            self.outputs[name] = self.resolve(action["inputs"])
        elif kind == "ParseJson":
            inputs = self.resolve(action["inputs"])
            check_parse_json_schema(inputs["schema"])
            value = inputs["content"]
            if isinstance(value, str) and inputs["schema"].get("type") != "string":
                value = json.loads(value)
            Draft4Validator(inputs["schema"]).validate(value)
            self.outputs[name] = {"body": value}
        elif kind == "If":
            branch = action["actions"] if self.resolve(action["expression"]) else action.get("else", {}).get("actions", {})
            self.run(branch)
        elif kind == "Foreach":
            for value in copy.deepcopy(self.resolve(action["foreach"])):
                self.current_items[name] = value
                self.run(action["actions"])
            self.current_items.pop(name, None)
        elif kind == "Until":
            for iteration in range(action["limit"]["count"]):
                self.run(action["actions"])
                if self.resolve(action["expression"]): break
            else:
                raise ValueError(f"Until limit reached: {name}")
        elif kind in {"Select", "Query"}:
            result = []; previous = self.item
            for item in self.resolve(action["inputs"]["from"]):
                self.item = item
                if kind == "Select": result.append(copy.deepcopy(self.resolve(action["inputs"]["select"])))
                elif self.resolve(action["inputs"]["where"]): result.append(copy.deepcopy(item))
            self.item = previous
            self.outputs[name] = {"body": result}
        elif kind == "Scope":
            self.run(action["actions"])
        elif kind == "Switch":
            value = self.resolve(action["expression"])
            branch = next((case["actions"] for case in action["cases"].values() if case["case"] == value), action["default"]["actions"])
            self.run(branch)
        elif kind == "Wait":
            if "until" in action["inputs"]:
                self.clock = datetime.fromisoformat(self.resolve(action["inputs"]["until"]["timestamp"]).replace("Z", "+00:00"))
        elif kind == "Response":
            self.response = self.resolve(action["inputs"])
        elif kind == "Http":
            if self.transport is None: raise ValueError("No network is allowed in a local replay.")
            self.outputs[name] = self.transport(self.resolve(action["inputs"]))
        else:
            raise ValueError(f"Unsupported local action: {kind}")
