import ast
import base64
import hashlib
import operator
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pack

P = 2**127 - 1
MAX_SOURCE_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 512
NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Mod: operator.mod,
}

BANNER_ART = r"""
   _____  _____ ____   ___
  |__  / | ____|  _ \ / _ \
    / /  |  _| | |_) | | | |
   / /_  | |___|  _ <| |_| |
  /____| |_____|_| \_\\___/
          R E P O R T

"""
BANNER_LORE = (
    "  Hi. I built this auditor.\n"
    "  If it approves a program, its report is all zeros.\n"
    "  It passed all my tests. Can you prove me wrong?\n\n"
)
BANNER_INSTRUCTION = "  Submit one base64-encoded program.\n"
BANNER = BANNER_ART + BANNER_LORE + BANNER_INSTRUCTION + "> "

REJECT_REQUEST = "REJECT invalid_request"
REJECT_REPORT = "REJECT invalid_report"


def report_from_source(source: bytes) -> tuple[int, int]:
    if not source or len(source) > MAX_SOURCE_BYTES:
        raise ValueError("source size")
    text = source.decode("utf-8")
    body = pack.extract_body(text)
    if len(body.encode("utf-8")) > 2048 or pack.pack(body).encode("utf-8") != source:
        raise ValueError("noncanonical source")

    tree = ast.parse(text)
    fn = next(node for node in tree.body
              if isinstance(node, ast.FunctionDef) and node.name == "generate")
    if not 1 <= len(fn.body) <= 32:
        raise ValueError("statement count")

    stack = [(node, 1) for node in fn.body]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 256 or depth > 32:
            raise ValueError("program too complex")
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))

    source_hash = int.from_bytes(hashlib.sha256(source).digest(), "big") % P
    names: dict[str, int] = {}

    def value(node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            if node.value.bit_length() > 256:
                raise ValueError("literal too large")
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "P":
                return P
            if node.id in names:
                return names[node.id]
            raise ValueError("unknown name")
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Name) and node.func.id == "H"
                    and len(node.args) == 1 and not node.keywords
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "SOURCE"):
                return source_hash
            raise ValueError("invalid call")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            result = value(node.operand)
            if isinstance(node.op, ast.USub):
                result = -result
        elif isinstance(node, ast.BinOp) and type(node.op) in OPS:
            left = value(node.left)
            right = value(node.right)
            result = OPS[type(node.op)](left, right)
        else:
            raise ValueError("invalid expression")
        if result.bit_length() > 512:
            raise ValueError("intermediate too large")
        return result

    for stmt in fn.body[:-1]:
        if (not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1
                or not isinstance(stmt.targets[0], ast.Name)):
            raise ValueError("invalid assignment")
        name = stmt.targets[0].id
        if not NAME.fullmatch(name):
            raise ValueError("invalid name")
        names[name] = value(stmt.value)

    final = fn.body[-1]
    if (not isinstance(final, ast.Return)
            or not isinstance(final.value, (ast.List, ast.Tuple))
            or len(final.value.elts) != 2):
        raise ValueError("invalid return")
    return value(final.value.elts[0]), value(final.value.elts[1])


def audit(source: bytes) -> tuple[tuple[int, int], bool]:
    report = report_from_source(source)
    a, b = report
    source_hash = int.from_bytes(hashlib.sha256(source).digest(), "big") % P
    accepted = (
        0 <= a < P and 0 <= b < P
        and (a != 0 or b != 0)
        and ((1 - source_hash) * a + source_hash * b) % P == 0
    )
    return report, accepted


def show_banner() -> None:
    print(BANNER_ART + BANNER_LORE, end="", flush=True)
    for char in BANNER_INSTRUCTION:
        print(char, end="", flush=True)
        time.sleep(0.04)
    print("> ", end="", flush=True)


def serve(flag: str) -> None:
    show_banner()
    try:
        line = input()
        if not line or len(line) > 21848:
            raise ValueError("invalid transport line")
        source = base64.b64decode(line, validate=True)
        _, accepted = audit(source)
        response = flag if accepted else REJECT_REPORT
    except Exception:
        response = REJECT_REQUEST
    if len(response.encode("utf-8")) > MAX_RESPONSE_BYTES:
        response = REJECT_REQUEST
    print(response, end="", flush=True)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--preflight":
        return 0 if os.environ.get("FLAG") else 1
    if len(argv) == 2:
        try:
            with open(argv[1], "rb") as stream:
                source = stream.read(MAX_SOURCE_BYTES + 1)
            report, accepted = audit(source)
        except Exception as exc:
            print(f"Reason: {exc}\nREJECT")
            return 1
        print(BANNER_ART + BANNER_LORE, end="")
        print(f"Report: {list(report)}")
        print("ACCEPT" if accepted else "REJECT")
        return 0 if accepted else 1
    if len(argv) != 1:
        sys.stderr.write("usage: service.py [program.py]\n")
        return 2

    flag = os.environ.get("FLAG")
    if not flag:
        sys.stderr.write("FATAL: FLAG is not set\n")
        return 1
    serve(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
