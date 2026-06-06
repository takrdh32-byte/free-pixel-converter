#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          ██████╗ ██████╗ ██████╗ ███████╗                       ║
║         ██╔════╝██╔═══██╗██╔══██╗██╔════╝                       ║
║         ██║     ██║   ██║██║  ██║█████╗                         ║
║         ██║     ██║   ██║██║  ██║██╔══╝                         ║
║         ╚██████╗╚██████╔╝██████╔╝███████╗                       ║
║          ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝                       ║
║                  W A T C H                                       ║
║                                                                  ║
║     Ultra Powerful Code Review & Bug Detection Engine            ║
║     Termux + Linux + Windows — Sab pe Chalta Hai                ║
║     Zero External Dependencies — Pure Python 3                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

TERMUX INSTALL:
    pkg install python
    python codewatch.py --help

API MODE (Web Server):
    python codewatch.py --server --port 8000

FILE ANALYZE:
    python codewatch.py --file mycode.py

DIRECT CODE:
    python codewatch.py --code "eval(input())"

SCAN FOLDER:
    python codewatch.py --dir /path/to/project
"""

import ast
import re
import os
import sys
import json
import time
import hashlib
import argparse
import textwrap
import platform
import threading
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any, Optional, Tuple

# ══════════════════════════════════════════════
# TERMINAL COLOR ENGINE — Auto detect support
# ══════════════════════════════════════════════
class Colors:
    _enabled = sys.stdout.isatty() and platform.system() != "Windows"

    RED      = "\033[91m"   if _enabled else ""
    GREEN    = "\033[92m"   if _enabled else ""
    YELLOW   = "\033[93m"   if _enabled else ""
    BLUE     = "\033[94m"   if _enabled else ""
    MAGENTA  = "\033[95m"   if _enabled else ""
    CYAN     = "\033[96m"   if _enabled else ""
    WHITE    = "\033[97m"   if _enabled else ""
    BOLD     = "\033[1m"    if _enabled else ""
    DIM      = "\033[2m"    if _enabled else ""
    RESET    = "\033[0m"    if _enabled else ""
    BG_RED   = "\033[41m"   if _enabled else ""
    BG_GREEN = "\033[42m"   if _enabled else ""

C = Colors()

def color_severity(severity: str) -> str:
    return {
        "CRITICAL": f"{C.BG_RED}{C.WHITE}{C.BOLD} CRITICAL {C.RESET}",
        "HIGH":     f"{C.RED}{C.BOLD}[HIGH]{C.RESET}",
        "MEDIUM":   f"{C.YELLOW}{C.BOLD}[MEDIUM]{C.RESET}",
        "LOW":      f"{C.CYAN}[LOW]{C.RESET}",
        "INFO":     f"{C.DIM}[INFO]{C.RESET}",
    }.get(severity, f"[{severity}]")

# ══════════════════════════════════════════════
# ISSUE MODEL
# ══════════════════════════════════════════════
class Issue:
    def __init__(self, line: int, severity: str, category: str,
                 message: str, suggestion: str, code_snippet: str = ""):
        self.line = line
        self.severity = severity
        self.category = category
        self.message = message
        self.suggestion = suggestion
        self.code_snippet = code_snippet

    def to_dict(self) -> dict:
        return {
            "line": self.line,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "suggestion": self.suggestion,
            "code_snippet": self.code_snippet
        }

# ══════════════════════════════════════════════
# BASE ANALYZER CLASS
# ══════════════════════════════════════════════
class BaseAnalyzer:
    def analyze(self, code: str, lines: List[str]) -> List[Issue]:
        raise NotImplementedError

    def _get_snippet(self, lines: List[str], lineno: int, context: int = 1) -> str:
        start = max(0, lineno - 1 - context)
        end = min(len(lines), lineno + context)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>>" if i == lineno - 1 else "   "
            snippet_lines.append(f"{marker} {i+1:3d} | {lines[i].rstrip()}")
        return "\n".join(snippet_lines)

# ══════════════════════════════════════════════
# PYTHON DEEP ANALYZER
# ══════════════════════════════════════════════
class PythonAnalyzer(BaseAnalyzer):

    DANGER_CALLS = {
        "eval":        ("CRITICAL", "Security",     "eval() se arbitrary code execute hota hai — RCE risk!",           "ast.literal_eval() use karo"),
        "exec":        ("CRITICAL", "Security",     "exec() arbitrary code run karta hai",                             "Static logic prefer karo"),
        "compile":     ("HIGH",     "Security",     "compile() dynamic code banata hai",                               "Static imports use karo"),
        "os.system":   ("HIGH",     "Security",     "os.system() shell injection ke liye vulnerable",                  "subprocess.run(list) use karo"),
        "__import__":  ("HIGH",     "Security",     "Dynamic import — injection possible",                             "Static import use karo"),
        "breakpoint":  ("MEDIUM",   "Debug",        "Debugger production mein reh gaya!",                              "Remove karo"),
        "pdb.set_trace":("MEDIUM",  "Debug",        "pdb debugger call production mein hai",                           "Remove karo"),
        "pickle.loads":("HIGH",     "Security",     "pickle.loads untrusted data pe dangerous hai",                    "json.loads use karo"),
        "marshal.loads":("HIGH",    "Security",     "marshal.loads arbitrary code run kar sakta hai",                  "Safe serialization use karo"),
        "yaml.load":   ("HIGH",     "Security",     "yaml.load() arbitrary objects load karta hai",                    "yaml.safe_load() use karo"),
        "input":       ("LOW",      "Validation",   "input() ka result validate nahi ho raha",                         "Type check aur sanitize karo"),
        "print":       ("LOW",      "Quality",      "Production mein print() avoid karo",                              "logging module use karo"),
        "open":        ("LOW",      "Safety",       "File open — exception handling check karo",                       "with open() as f: pattern use karo"),
    }

    PATTERN_CHECKS = [
        # Hardcoded secrets
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',   "CRITICAL", "Secret",      "Hardcoded password mila!",            "os.environ.get('PASSWORD') use karo"),
        (r'(?i)(secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{5,}["\']', "CRITICAL","Secret","Hardcoded secret/token mila!", ".env file + python-dotenv use karo"),
        (r'(?i)private_key\s*=\s*["\']-----BEGIN',                  "CRITICAL", "Secret",      "Private key hardcoded hai!",          "File se load karo, commit mat karo"),

        # SQL Injection
        (r'(?i)(execute|query)\s*\(\s*["\'].*%s',                    "HIGH",     "SQLi",        "SQL Injection risk — string formatting!", "Parameterized queries use karo"),
        (r'(?i)(execute|query)\s*\(.*\+.*\)',                        "HIGH",     "SQLi",        "SQL mein string concatenation — injection!", "Prepared statements use karo"),
        (r'(?i)f["\'].*SELECT.*{',                                   "HIGH",     "SQLi",        "f-string mein SQL — injection risk!",  "Parameterized queries use karo"),

        # Insecure network
        (r'http://',                                                  "MEDIUM",   "Network",     "HTTP use ho raha hai — data unencrypted", "HTTPS use karo"),
        (r'verify\s*=\s*False',                                      "HIGH",     "Security",    "SSL certificate verification disabled!", "verify=True rakho"),
        (r'ssl\._create_unverified_context',                         "HIGH",     "Security",    "Unverified SSL context!",              "Default SSL context use karo"),

        # Weak crypto
        (r'(?i)(import\s+md5|hashlib\.md5|from\s+md5)',              "HIGH",     "Crypto",      "MD5 cryptographically broken hai",     "hashlib.sha256() use karo"),
        (r'(?i)hashlib\.sha1\(',                                     "MEDIUM",   "Crypto",      "SHA1 weak hai passwords ke liye",      "bcrypt ya argon2 use karo"),
        (r'(?i)random\.random\(\)|random\.randint\(',                "MEDIUM",   "Crypto",      "random module crypto ke liye safe nahi","secrets module use karo"),
        (r'DES\.|DES3\.',                                            "HIGH",     "Crypto",      "DES/3DES outdated encryption",         "AES-256 use karo"),

        # Command injection
        (r'shell\s*=\s*True',                                        "HIGH",     "CmdInj",      "shell=True — command injection risk!",  "subprocess.run(list, shell=False) use karo"),
        (r'os\.popen\(',                                             "HIGH",     "CmdInj",      "os.popen() shell injection vulnerable", "subprocess.run() use karo"),

        # Path traversal
        (r'open\s*\(.*\+.*\)',                                       "MEDIUM",   "PathTraversal","Dynamic path — traversal risk!",      "os.path.abspath + basedir check karo"),

        # Debug/temp code
        (r'#\s*(TODO|FIXME|HACK|XXX|BUG)\b',                        "LOW",      "Quality",     "Unfinished work marker mila",          "Fix karo ya issue tracker mein daalo"),
        (r'(?m)^\s*#.*def |^\s*#.*class |^\s*#.*import ',           "LOW",      "Quality",     "Commented out code mila",              "Dead code remove karo — git history mein rahega"),
    ]

    def analyze(self, code: str, lines: List[str]) -> List[Issue]:
        issues = []

        # Syntax check first
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            snippet = self._get_snippet(lines, e.lineno or 1)
            issues.append(Issue(
                line=e.lineno or 1,
                severity="CRITICAL",
                category="Syntax",
                message=f"Syntax Error: {e.msg}",
                suggestion="Code ka syntax fix karo — parse hi nahi ho raha",
                code_snippet=snippet
            ))
            return issues  # Syntax error ke baad AST analysis possible nahi

        # AST deep walk
        issues.extend(self._ast_walk(tree, lines))

        # Pattern-based checks
        full_code = code
        for pattern, severity, category, message, suggestion in self.PATTERN_CHECKS:
            for match in re.finditer(pattern, full_code, re.MULTILINE):
                lineno = full_code[:match.start()].count('\n') + 1
                snippet = self._get_snippet(lines, lineno)
                issues.append(Issue(
                    line=lineno, severity=severity, category=category,
                    message=message, suggestion=suggestion, code_snippet=snippet
                ))

        # Quality + complexity checks
        issues.extend(self._quality_checks(lines))

        return issues

    def _ast_walk(self, tree, lines) -> List[Issue]:
        issues = []

        for node in ast.walk(tree):

            # ── Dangerous function calls ──
            if isinstance(node, ast.Call):
                name = self._call_name(node)
                if name in self.DANGER_CALLS:
                    sev, cat, msg, sug = self.DANGER_CALLS[name]
                    issues.append(Issue(
                        line=node.lineno, severity=sev, category=cat,
                        message=f"`{name}()` detected — {msg}",
                        suggestion=sug,
                        code_snippet=self._get_snippet(lines, node.lineno)
                    ))

            # ── Mutable default arguments ──
            if isinstance(node, ast.FunctionDef):
                for default in node.args.defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        issues.append(Issue(
                            line=node.lineno, severity="HIGH", category="Bug",
                            message=f"`{node.name}()` mein mutable default argument — classic Python bug!",
                            suggestion="Default None rakho: def fn(x=None):\n    if x is None: x = []",
                            code_snippet=self._get_snippet(lines, node.lineno)
                        ))

                # ── Missing return type / docstring ──
                has_doc = (node.body and isinstance(node.body[0], ast.Expr)
                           and isinstance(node.body[0].value, ast.Constant)
                           and isinstance(node.body[0].value.value, str))
                if not has_doc and len(node.body) > 3:
                    issues.append(Issue(
                        line=node.lineno, severity="LOW", category="Quality",
                        message=f"`{node.name}()` mein docstring nahi hai",
                        suggestion=f'def {node.name}(...):\n    """Yahan describe karo kya karta hai"""\n    ...',
                        code_snippet=self._get_snippet(lines, node.lineno)
                    ))

                # ── Too many arguments ──
                arg_count = len(node.args.args)
                if arg_count > 6:
                    issues.append(Issue(
                        line=node.lineno, severity="LOW", category="Design",
                        message=f"`{node.name}()` mein {arg_count} arguments — bahut zyada!",
                        suggestion="Arguments ko dataclass ya dict mein wrap karo",
                        code_snippet=self._get_snippet(lines, node.lineno)
                    ))

                # ── Function too long ──
                func_lines = (node.end_lineno or node.lineno) - node.lineno
                if func_lines > 60:
                    issues.append(Issue(
                        line=node.lineno, severity="MEDIUM", category="Complexity",
                        message=f"`{node.name}()` bahut lamba hai ({func_lines} lines)",
                        suggestion="Function ko chhote functions mein tod do — Single Responsibility Principle",
                        code_snippet=self._get_snippet(lines, node.lineno)
                    ))

            # ── Bare except ──
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                issues.append(Issue(
                    line=node.lineno, severity="MEDIUM", category="Bug",
                    message="Bare `except:` — sab exceptions pakad leta hai silently!",
                    suggestion="Specific exceptions pakdo: except (ValueError, TypeError) as e:",
                    code_snippet=self._get_snippet(lines, node.lineno)
                ))

            # ── assert in production code ──
            if isinstance(node, ast.Assert):
                issues.append(Issue(
                    line=node.lineno, severity="MEDIUM", category="Bug",
                    message="`assert` production mein reliable nahi — -O flag se disabled ho jaata hai",
                    suggestion="Proper if/raise use karo: if not condition: raise ValueError('...')",
                    code_snippet=self._get_snippet(lines, node.lineno)
                ))

            # ── global keyword ──
            if isinstance(node, ast.Global):
                issues.append(Issue(
                    line=node.lineno, severity="LOW", category="Design",
                    message=f"global keyword: `{', '.join(node.names)}` — anti-pattern hai",
                    suggestion="Class attribute ya function parameter use karo",
                    code_snippet=self._get_snippet(lines, node.lineno)
                ))

            # ── Division without guard ──
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                if not isinstance(node.right, ast.Constant):
                    issues.append(Issue(
                        line=node.lineno, severity="LOW", category="Bug",
                        message="Division — ZeroDivisionError possible!",
                        suggestion="try/except ZeroDivisionError ya `if denominator != 0:` check karo",
                        code_snippet=self._get_snippet(lines, node.lineno)
                    ))

            # ── Comparison with None using == ──
            if isinstance(node, ast.Compare):
                for op in node.ops:
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        for comp in node.comparators:
                            if isinstance(comp, ast.Constant) and comp.value is None:
                                issues.append(Issue(
                                    line=node.lineno, severity="LOW", category="Bug",
                                    message="`== None` use ho raha hai — yeh bug prone hai",
                                    suggestion="`is None` ya `is not None` use karo",
                                    code_snippet=self._get_snippet(lines, node.lineno)
                                ))

        return issues

    def _quality_checks(self, lines: List[str]) -> List[Issue]:
        issues = []
        long_line_count = 0

        for i, raw_line in enumerate(lines, 1):
            line = raw_line.rstrip()

            # Long lines
            if len(line) > 119:
                long_line_count += 1
                if long_line_count <= 5:  # Spam mat karo
                    issues.append(Issue(
                        line=i, severity="LOW", category="Style",
                        message=f"Line bahut lambi hai ({len(line)} chars) — PEP8 max 119",
                        suggestion="Line tod do ya variables extract karo",
                        code_snippet=line[:100] + "..."
                    ))

            # Trailing whitespace
            if raw_line != raw_line.rstrip() and raw_line.strip():
                issues.append(Issue(
                    line=i, severity="LOW", category="Style",
                    message="Trailing whitespace — invisible clutter",
                    suggestion="Editor mein 'trim trailing whitespace' on karo",
                    code_snippet=repr(raw_line[:50])
                ))

            # Mixed tabs and spaces (Python nightmare)
            if '\t' in line and line.startswith(' '):
                issues.append(Issue(
                    line=i, severity="HIGH", category="Syntax",
                    message="Mixed tabs aur spaces — Python 3 mein yeh TabError dega!",
                    suggestion="Sirf spaces use karo (4 spaces per indent)",
                    code_snippet=line[:80]
                ))

        return issues

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ""


# ══════════════════════════════════════════════
# JAVASCRIPT ANALYZER
# ══════════════════════════════════════════════
class JavaScriptAnalyzer(BaseAnalyzer):
    PATTERNS = [
        (r'\beval\s*\(',                                "CRITICAL", "Security",   "eval() — arbitrary code execution!",          "JSON.parse() ya Function constructor avoid karo"),
        (r'innerHTML\s*[+]?=',                         "HIGH",     "XSS",        "innerHTML — XSS attack possible!",            "textContent use karo ya DOMPurify se sanitize karo"),
        (r'document\.write\s*\(',                      "HIGH",     "XSS",        "document.write() — XSS risk!",                "DOM methods use karo"),
        (r'outerHTML\s*=',                             "HIGH",     "XSS",        "outerHTML — XSS risk!",                       "Safe DOM manipulation use karo"),
        (r'javascript:\s*["\']',                       "HIGH",     "XSS",        "javascript: URI — XSS!",                      "Event listeners use karo"),
        (r'\bvar\s+',                                  "LOW",      "Quality",    "var — function-scoped, bug prone",            "let ya const use karo"),
        (r'[^=!]==[^=]',                               "LOW",      "Bug",        "Loose equality (==) — type coercion bugs!",   "Strict equality (===) use karo"),
        (r'[^=!]!=[^=]',                               "LOW",      "Bug",        "Loose inequality (!=)",                       "Strict (!==) use karo"),
        (r'console\.(log|warn|error)\s*\(',            "LOW",      "Quality",    "console statement production mein hai",       "Proper logging library use karo"),
        (r'(?i)(password|secret|api_key)\s*=\s*["\']',"CRITICAL", "Secret",     "Hardcoded credential JS mein!",               "Environment variables ya config file use karo"),
        (r'Math\.random\(\)',                          "LOW",      "Crypto",     "Math.random() crypto ke liye safe nahi",      "crypto.getRandomValues() use karo"),
        (r'http://',                                   "MEDIUM",   "Network",    "HTTP — insecure connection",                  "HTTPS use karo"),
        (r'new\s+Function\s*\(',                       "HIGH",     "Security",   "new Function() — eval jaisa dangerous!",      "Static functions define karo"),
        (r'setTimeout\s*\(\s*["\']',                   "HIGH",     "Security",   "setTimeout string — eval jaisa!",             "setTimeout(function, delay) use karo"),
        (r'\.then\s*\([^)]+\)\s*(?!\.catch)',          "LOW",      "Bug",        "Promise .then() bina .catch() ke",            ".catch() add karo ya async/await with try-catch"),
    ]

    def analyze(self, code: str, lines: List[str]) -> List[Issue]:
        return self._pattern_scan(code, lines, self.PATTERNS)

    def _pattern_scan(self, code, lines, patterns):
        issues = []
        for pattern, severity, category, message, suggestion in patterns:
            for match in re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE):
                lineno = code[:match.start()].count('\n') + 1
                issues.append(Issue(
                    line=lineno, severity=severity, category=category,
                    message=message, suggestion=suggestion,
                    code_snippet=self._get_snippet(lines, lineno)
                ))
        return issues

# ══════════════════════════════════════════════
# BASH/SHELL ANALYZER
# ══════════════════════════════════════════════
class BashAnalyzer(BaseAnalyzer):
    PATTERNS = [
        (r'rm\s+-rf\s+[/$]',                          "CRITICAL", "Destructive", "Dangerous rm -rf — system delete possible!", "Path verify karo: [ -d \"$dir\" ] && rm -rf \"$dir\""),
        (r'curl\s+.*\|\s*(bash|sh)',                   "CRITICAL", "Security",   "Remote script directly execute — RCE!",       "Script download karo, verify karo, phir run karo"),
        (r'wget\s+.*\|\s*(bash|sh)',                   "CRITICAL", "Security",   "wget pipe to shell — RCE risk!",              "Download aur verify pehle"),
        (r'eval\s+["\$`]',                             "HIGH",     "Injection",  "eval — code injection possible!",             "Avoid eval, direct commands use karo"),
        (r'(?i)password=\S+',                          "CRITICAL", "Secret",     "Hardcoded password in bash!",                 "read -s PASSWORD ya env variable use karo"),
        (r'chmod\s+[0-9]*777',                         "HIGH",     "Permission", "chmod 777 — sab ko full access!",             "Minimum required permissions do: chmod 755 ya 644"),
        (r'sudo\s+.*rm|rm\s+.*sudo',                   "HIGH",     "Dangerous",  "sudo rm — accidental system damage!",         "Double check path, use trash-cli"),
        (r'\$\{\w+\}.*(?:rm|mv|cp)',                   "MEDIUM",   "Safety",     "Variable expansion with file ops — unquoted?","Variables always quote karo: \"${var}\""),
        (r'>/dev/null\s+2>&1',                         "LOW",      "Quality",    "All output suppressed — errors bhi!",         "Errors alag log karo: 2>/tmp/errors.log"),
        (r'set\s+-[^e]*$|^(?!.*set\s+-e)',             "LOW",      "Safety",     "set -e nahi hai — errors silently fail!",     "Script ke start mein: set -euo pipefail"),
        (r'`[^`]+`',                                   "LOW",      "Quality",    "Backtick command substitution — old style",   "$(...) syntax use karo"),
        (r'\[\s+.*==\s+',                              "LOW",      "Bug",        "[ ] mein == — bash specific, POSIX nahi",     "[[ == ]] ya [ = ] use karo"),
    ]

    def analyze(self, code: str, lines: List[str]) -> List[Issue]:
        issues = []
        for pattern, severity, category, message, suggestion in self.PATTERNS:
            for match in re.finditer(pattern, code, re.MULTILINE):
                lineno = code[:match.start()].count('\n') + 1
                issues.append(Issue(
                    line=lineno, severity=severity, category=category,
                    message=message, suggestion=suggestion,
                    code_snippet=self._get_snippet(lines, lineno)
                ))
        return issues

# ══════════════════════════════════════════════
# PHP ANALYZER
# ══════════════════════════════════════════════
class PHPAnalyzer(BaseAnalyzer):
    PATTERNS = [
        (r'\$_(?:GET|POST|REQUEST|COOKIE)\[.*\](?!\s*,)',   "HIGH",  "Injection", "Unsanitized user input!",              "htmlspecialchars() ya filter_input() use karo"),
        (r'mysql_(?:query|connect|select_db)\s*\(',         "CRITICAL","Deprecated","mysql_* functions deprecated + SQLi!", "PDO ya mysqli prepared statements use karo"),
        (r'(?i)echo\s+\$_(?:GET|POST|REQUEST)',              "HIGH",  "XSS",       "User input directly echo — XSS!",      "htmlspecialchars($input, ENT_QUOTES) use karo"),
        (r'(?i)include\s*\(\s*\$',                           "HIGH",  "LFI",       "Dynamic include — LFI attack!",         "Whitelist of allowed files use karo"),
        (r'shell_exec\s*\(',                                 "CRITICAL","CmdInj",  "shell_exec — command injection!",       "escapeshellarg() use karo ya avoid karo"),
        (r'system\s*\(\s*\$',                                "CRITICAL","CmdInj",  "system() user input ke saath!",         "escapeshellcmd() aur escapeshellarg() use karo"),
        (r'md5\s*\(\s*\$',                                   "HIGH",  "Crypto",    "MD5 for hashing — weak!",               "password_hash() use karo"),
        (r'(?i)(password|secret|api_key)\s*=\s*["\']',      "CRITICAL","Secret",  "Hardcoded credential PHP mein!",        ".env file use karo"),
        (r'error_reporting\s*\(\s*0\s*\)',                   "MEDIUM","Quality",   "Error reporting disabled",              "Development mein enable rakho, production pe log karo"),
        (r'@\$',                                             "LOW",   "Quality",   "Error suppression operator (@)",        "Proper try-catch use karo"),
    ]

    def analyze(self, code: str, lines: List[str]) -> List[Issue]:
        issues = []
        for pattern, severity, category, message, suggestion in self.PATTERNS:
            for match in re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE):
                lineno = code[:match.start()].count('\n') + 1
                issues.append(Issue(
                    line=lineno, severity=severity, category=category,
                    message=message, suggestion=suggestion,
                    code_snippet=self._get_snippet(lines, lineno)
                ))
        return issues

# ══════════════════════════════════════════════
# RUBY ANALYZER
# ══════════════════════════════════════════════
class RubyAnalyzer(BaseAnalyzer):
    PATTERNS = [
        (r'\beval\s*\(',                               "CRITICAL","Security",   "Ruby eval() — arbitrary code!",          "Static code prefer karo"),
        (r'`[^`]+`',                                   "HIGH",    "CmdInj",    "Shell command via backticks",            "Open3 ya system() with array use karo"),
        (r'system\s*\(\s*["\'].*#\{',                  "HIGH",    "CmdInj",    "String interpolation in system() — injection!", "Array form use karo: system('cmd', arg)"),
        (r'Marshal\.load\s*\(',                        "HIGH",    "Security",  "Marshal.load untrusted data — RCE!",     "JSON use karo"),
        (r'(?i)(password|secret)\s*=\s*["\']',         "CRITICAL","Secret",    "Hardcoded secret Ruby mein!",            "ENV['KEY'] use karo"),
        (r'params\[.*\]\s*(?!\.permit)',               "MEDIUM",  "Security",  "Strong parameters use nahi ho rahi",     ".permit() use karo Rails mein"),
        (r'html_safe\s*$',                             "HIGH",    "XSS",       "html_safe — XSS risk!",                  "sanitize() helper use karo"),
        (r'raw\s+',                                    "HIGH",    "XSS",       "raw() — unescaped HTML!",                "h() ya sanitize() use karo"),
    ]

    def analyze(self, code: str, lines: List[str]) -> List[Issue]:
        issues = []
        for pattern, severity, category, message, suggestion in self.PATTERNS:
            for match in re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE):
                lineno = code[:match.start()].count('\n') + 1
                issues.append(Issue(
                    line=lineno, severity=severity, category=category,
                    message=message, suggestion=suggestion,
                    code_snippet=self._get_snippet(lines, lineno)
                ))
        return issues

# ══════════════════════════════════════════════
# ANALYZER REGISTRY
# ══════════════════════════════════════════════
ANALYZERS = {
    "python": PythonAnalyzer,
    "py":     PythonAnalyzer,
    "javascript": JavaScriptAnalyzer,
    "js":     JavaScriptAnalyzer,
    "typescript": JavaScriptAnalyzer,
    "ts":     JavaScriptAnalyzer,
    "bash":   BashAnalyzer,
    "shell":  BashAnalyzer,
    "sh":     BashAnalyzer,
    "php":    PHPAnalyzer,
    "ruby":   RubyAnalyzer,
    "rb":     RubyAnalyzer,
}

EXTENSION_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".sh": "bash", ".bash": "bash", ".php": "php",
    ".rb": "ruby", ".jsx": "javascript", ".tsx": "typescript",
}

# ══════════════════════════════════════════════
# SCORING ENGINE
# ══════════════════════════════════════════════
SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
GRADE_TABLE = [(95,"A+"), (90,"A"), (85,"A-"), (80,"B+"), (75,"B"),
               (70,"B-"), (65,"C+"), (60,"C"), (50,"D"), (0,"F")]

def score_issues(issues: List[Issue], total_lines: int) -> Tuple[int, str]:
    penalty = sum(SEVERITY_WEIGHTS.get(i.severity, 0) for i in issues)
    # Larger files get slight leniency
    leniency = min(10, total_lines // 50)
    score = max(0, min(100, 100 - penalty + leniency))
    grade = next(g for threshold, g in GRADE_TABLE if score >= threshold)
    return score, grade

# ══════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════
class Reporter:

    @staticmethod
    def terminal(result: dict, verbose: bool = True):
        issues = result["issues"]
        summary = result["summary"]

        # Header
        print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
        print(f"{C.BOLD}  CodeWatch Analysis Report{C.RESET}")
        print(f"{C.DIM}  {result['filename']} — {result['language'].upper()} — {result['total_lines']} lines{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")

        # Score display
        score = summary["score"]
        grade = summary["grade"]
        if score >= 80:
            score_color = C.GREEN
        elif score >= 60:
            score_color = C.YELLOW
        else:
            score_color = C.RED

        print(f"\n  Score: {score_color}{C.BOLD}{score}/100{C.RESET}  Grade: {score_color}{C.BOLD}{grade}{C.RESET}")
        print(f"  Verdict: {summary['verdict']}\n")

        # Counts
        counts = summary["by_severity"]
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = counts.get(sev, 0)
            if count > 0:
                parts.append(f"{color_severity(sev)} {count}")
        if parts:
            print("  " + "  ".join(parts))
        print()

        # Issues
        if not issues:
            print(f"  {C.GREEN}{C.BOLD}✓ No issues found! Clean code!{C.RESET}\n")
            return

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_issues = sorted(issues, key=lambda x: (severity_order.get(x["severity"], 5), x["line"]))

        print(f"{C.BOLD}  Issues ({len(issues)} total):{C.RESET}")
        print(f"  {'─'*56}")

        for issue in sorted_issues:
            print(f"\n  {color_severity(issue['severity'])} "
                  f"{C.DIM}Line {issue['line']}{C.RESET} "
                  f"{C.YELLOW}[{issue['category']}]{C.RESET}")
            print(f"  {C.WHITE}{issue['message']}{C.RESET}")
            print(f"  {C.GREEN}→ {issue['suggestion']}{C.RESET}")
            if verbose and issue.get("code_snippet"):
                print(f"{C.DIM}")
                for line in issue["code_snippet"].split('\n'):
                    print(f"    {line}")
                print(C.RESET, end="")

        print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}\n")

    @staticmethod
    def json_out(result: dict) -> str:
        return json.dumps(result, indent=2, ensure_ascii=False)

    @staticmethod
    def summary_line(result: dict) -> str:
        s = result["summary"]
        counts = result["summary"]["by_severity"]
        c = counts.get("CRITICAL", 0)
        h = counts.get("HIGH", 0)
        m = counts.get("MEDIUM", 0)
        l = counts.get("LOW", 0)
        return (f"{result['filename']}: Score={s['score']} Grade={s['grade']} "
                f"Critical={c} High={h} Medium={m} Low={l}")

# ══════════════════════════════════════════════
# CORE ANALYSIS FUNCTION
# ══════════════════════════════════════════════
def analyze(code: str, language: str = "python", filename: str = "code") -> dict:
    language = language.lower().strip()
    lines = code.split('\n')

    analyzer_class = ANALYZERS.get(language)
    if analyzer_class is None:
        # Try generic pattern scan
        issues_raw = []
    else:
        analyzer = analyzer_class()
        issues_raw = analyzer.analyze(code, lines)

    # Deduplicate (same line + message)
    seen = set()
    issues = []
    for issue in issues_raw:
        key = (issue.line, issue.message[:40])
        if key not in seen:
            seen.add(key)
            issues.append(issue)

    total_lines = len(lines)
    score, grade = score_issues(issues, total_lines)

    # Build summary
    by_sev = {}
    by_cat = {}
    for issue in issues:
        by_sev[issue.severity] = by_sev.get(issue.severity, 0) + 1
        by_cat[issue.category] = by_cat.get(issue.category, 0) + 1

    verdict_map = [
        (90, "Excellent! Code bahut clean hai"),
        (75, "Good code — kuch improvements possible hain"),
        (60, "Average — significant issues hain"),
        (40, "Poor — major refactoring zaroori hai"),
        (0,  "Critical — production ke liye ready nahi!"),
    ]
    verdict = next(v for threshold, v in verdict_map if score >= threshold)

    return {
        "filename": filename,
        "language": language,
        "total_lines": total_lines,
        "analyzed_at": datetime.now().isoformat(),
        "issues": [i.to_dict() for i in issues],
        "summary": {
            "score": score,
            "grade": grade,
            "verdict": verdict,
            "total_issues": len(issues),
            "by_severity": by_sev,
            "by_category": by_cat,
        }
    }

# ══════════════════════════════════════════════
# FOLDER SCANNER
# ══════════════════════════════════════════════
def scan_directory(path: str, extensions: Optional[List[str]] = None) -> List[dict]:
    results = []
    skip_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.tox', 'dist', 'build'}

    if extensions is None:
        extensions = list(EXTENSION_MAP.keys())

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext in extensions:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    lang = EXTENSION_MAP.get(ext, "python")
                    result = analyze(code, lang, fpath)
                    results.append(result)
                except Exception as e:
                    results.append({"filename": fpath, "error": str(e)})

    return results

# ══════════════════════════════════════════════
# HTTP API SERVER (Zero Dependencies!)
# ══════════════════════════════════════════════
class APIHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Silent logging

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/" or path == "/health":
            self.send_json({
                "status": "ok",
                "name": "CodeWatch API",
                "version": "2.0",
                "supported_languages": list(ANALYZERS.keys()),
                "endpoints": {
                    "POST /analyze": "Code analyze karo",
                    "POST /analyze/batch": "Multiple files analyze karo",
                    "GET /health": "Health check",
                }
            })
        else:
            self.send_json({"error": "Route nahi mila"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path

        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8')
            data = json.loads(body) if body else {}
        except Exception as e:
            self.send_json({"error": f"JSON parse error: {e}"}, 400)
            return

        if path == "/analyze":
            code = data.get("code", "")
            language = data.get("language", "python")
            filename = data.get("filename", "code")

            if not code.strip():
                self.send_json({"error": "Code empty hai!"}, 400)
                return
            if len(code) > 500_000:
                self.send_json({"error": "Code bahut bada hai (max 500KB)"}, 400)
                return

            result = analyze(code, language, filename)
            self.send_json(result)

        elif path == "/analyze/batch":
            files = data.get("files", [])
            if not files:
                self.send_json({"error": "files array empty hai"}, 400)
                return

            results = []
            for f in files[:20]:  # Max 20 files per batch
                try:
                    r = analyze(f.get("code", ""), f.get("language", "python"), f.get("filename", "file"))
                    results.append(r)
                except Exception as e:
                    results.append({"error": str(e)})

            self.send_json({"results": results, "total": len(results)})

        else:
            self.send_json({"error": "Route nahi mila"}, 404)


def start_server(host: str = "0.0.0.0", port: int = 8000):
    server = HTTPServer((host, port), APIHandler)
    print(f"{C.GREEN}{C.BOLD}")
    print(f"╔══════════════════════════════════════════╗")
    print(f"║  CodeWatch API Server Running!           ║")
    print(f"║  http://{host}:{port}                   ║")
    print(f"║  POST /analyze  — Single file            ║")
    print(f"║  POST /analyze/batch — Multiple files    ║")
    print(f"║  GET  /health   — Status check           ║")
    print(f"║  Ctrl+C to stop                          ║")
    print(f"╚══════════════════════════════════════════╝")
    print(C.RESET)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Server stopped.{C.RESET}")

# ══════════════════════════════════════════════
# CLI INTERFACE
# ══════════════════════════════════════════════
def detect_language(filepath: str) -> str:
    ext = Path(filepath).suffix.lower()
    return EXTENSION_MAP.get(ext, "python")

def main():
    parser = argparse.ArgumentParser(
        description="CodeWatch — Ultra Powerful Code Review Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python codewatch.py --file app.py
          python codewatch.py --file app.js --language javascript
          python codewatch.py --code "eval(input())" --language python
          python codewatch.py --dir ./myproject
          python codewatch.py --server --port 8000
          python codewatch.py --file code.py --output json
        """)
    )
    parser.add_argument("--file",     "-f", help="File analyze karo")
    parser.add_argument("--code",     "-c", help="Direct code string analyze karo")
    parser.add_argument("--dir",      "-d", help="Pura folder scan karo")
    parser.add_argument("--language", "-l", help="Language specify karo (python/js/php/bash/ruby)", default="python")
    parser.add_argument("--output",   "-o", help="Output format: terminal/json/summary", default="terminal")
    parser.add_argument("--server",   "-s", action="store_true", help="API server start karo")
    parser.add_argument("--port",     "-p", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--host",           default="0.0.0.0", help="Server host")
    parser.add_argument("--no-snippet",     action="store_true", help="Code snippets mat dikhao")
    parser.add_argument("--min-severity",   default="LOW", choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                        help="Minimum severity filter")

    args = parser.parse_args()

    # Server mode
    if args.server:
        start_server(args.host, args.port)
        return

    # No args — show help
    if not args.file and not args.code and not args.dir:
        parser.print_help()
        return

    severity_levels = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_level = severity_levels.get(args.min_severity, 3)

    # Directory scan
    if args.dir:
        if not os.path.isdir(args.dir):
            print(f"{C.RED}Error: Directory nahi mila: {args.dir}{C.RESET}")
            sys.exit(1)

        print(f"{C.CYAN}Scanning: {args.dir}{C.RESET}")
        results = scan_directory(args.dir)

        if args.output == "json":
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            total_issues = 0
            for result in results:
                if "error" in result:
                    print(f"{C.RED}Error {result['filename']}: {result['error']}{C.RESET}")
                    continue
                # Filter issues
                result["issues"] = [i for i in result["issues"]
                                    if severity_levels.get(i["severity"], 3) <= min_level]
                total_issues += len(result["issues"])
                if args.output == "summary":
                    print(Reporter.summary_line(result))
                else:
                    Reporter.terminal(result, verbose=not args.no_snippet)

            print(f"\n{C.BOLD}Total: {len(results)} files, {total_issues} issues{C.RESET}")
        return

    # Single file
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{C.RED}Error: File nahi mila: {args.file}{C.RESET}")
            sys.exit(1)
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except Exception as e:
            print(f"{C.RED}File read error: {e}{C.RESET}")
            sys.exit(1)
        lang = args.language if args.language != "python" else detect_language(args.file)
        filename = args.file

    # Direct code
    elif args.code:
        code = args.code
        lang = args.language
        filename = "<inline>"

    result = analyze(code, lang, filename)

    # Filter by severity
    result["issues"] = [i for i in result["issues"]
                        if severity_levels.get(i["severity"], 3) <= min_level]

    if args.output == "json":
        print(Reporter.json_out(result))
    elif args.output == "summary":
        print(Reporter.summary_line(result))
    else:
        Reporter.terminal(result, verbose=not args.no_snippet)

    # Exit code based on critical issues
    critical = result["summary"]["by_severity"].get("CRITICAL", 0)
    high = result["summary"]["by_severity"].get("HIGH", 0)
    sys.exit(1 if (critical + high) > 0 else 0)


if __name__ == "__main__":
    main()
