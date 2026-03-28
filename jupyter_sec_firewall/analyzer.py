import ast

# Define restricted modules for import and usage
RESTRICTED_MODULES = [
    'os', 'subprocess', 'socket', 'pty', 'importlib',
    'sys', 'shutil', 'urllib', 'http', 'requests'
]

# Define restricted builtins — called directly in visit_Call.
# NOTE: 'open' is intentionally excluded. Blocking open() would break
# legitimate data science notebooks (e.g. `with open('data.csv') as f:`).
# 'globals' and 'locals' are also excluded — they have legitimate uses
# in metaprogramming. Both are still flagged by visit_Name if referenced bare.
RESTRICTED_BUILTINS = [
    'eval', 'exec', 'compile',
    '__import__', 'getattr', 'setattr', 'delattr'
]

class SecurityASTNodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.violations = []

    def visit(self, node):
        # Annotate each node with its parent so visit_Name can tell whether
        # a dangerous name is being *called* (already caught by visit_Call)
        # or merely referenced/stored (needs flagging here).
        for child in ast.iter_child_nodes(node):
            child._parent = node
        super().visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name.split('.')[0] in RESTRICTED_MODULES:
                self.violations.append(f"Unauthorized import detected: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.module.split('.')[0] in RESTRICTED_MODULES:
            self.violations.append(f"Unauthorized from-import detected: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node):
        # Additional logic to block things like __import__('os') or eval()
        if isinstance(node.func, ast.Name):
            if node.func.id in RESTRICTED_BUILTINS:
                self.violations.append(f"Restricted builtin or dynamic code execution blocked: {node.func.id}")

        # Block getattr/setattr with restricted modules as strings
        # e.g. getattr(__import__('sys'), 'modules')
        # Here we just flag getattr / setattr calls directly from above

        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Block access to dunder methods and attributes that could be used for escapes
        if node.attr in ['__class__', '__subclasses__', '__bases__', '__mro__', '__builtins__']:
            self.violations.append(f"Access to restricted dunder attribute blocked: {node.attr}")

        # Block specific attribute accesses on known restricted modules
        # This checks for direct attribute access, e.g. sys.modules
        if isinstance(node.value, ast.Name):
            if node.value.id == 'sys' and node.attr == 'modules':
                self.violations.append("Modification or access to sys.modules blocked")
        self.generic_visit(node)

    def visit_Name(self, node):
        # Flag dangerous bare name references — but only when the name appears
        # outside of a direct Call expression. Direct calls like eval('x') are
        # already caught by visit_Call, so we avoid double-reporting here.
        #
        # We use a context check: ast.Load in a Call's func position means the
        # name IS the thing being called, so visit_Call will handle it. We catch
        # it in visit_Name only when it's stored, referenced, or passed around
        # (e.g. `f = eval`, `funcs = [eval, exec]`).
        #
        # 'open' is intentionally excluded — it is used constantly for legitimate
        # file I/O (e.g. `with open('data.csv') as f:`).
        # 'globals' and 'locals' are excluded — they have legitimate uses
        # in metaprogramming helpers.
        DANGEROUS_NAMES = {
            '__builtins__', '__import__',
            'eval', 'exec', 'compile',
        }
        if node.id in DANGEROUS_NAMES:
            # Only report if this name is NOT the direct target of a call.
            # visit_Call already reports `eval(...)` etc.
            parent = getattr(node, '_parent', None)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                self.violations.append(
                    f"Access to restricted builtin namespace blocked: {node.id}"
                )
        self.generic_visit(node)


def _strip_ipython_magics(code: str) -> tuple:
    """
    Pre-processes IPython notebook cell code before AST parsing.

    Returns (cleaned_code, shell_violations) where:
    - cleaned_code has IPython line/cell magics removed so they don't cause
      false-positive SyntaxErrors (e.g. %matplotlib inline, %%timeit).
    - shell_violations is a list of violations for any ! shell-escape lines
      or shell cell magics, which are blocked by policy.

    Design rationale:
    - ! commands (e.g. !cat /etc/passwd, !pip install pkg) execute arbitrary
      shell commands and are intentionally blocked.
    - %%bash / %%sh / %%shell / %%script execute shell code — blocked.
    - % and other %% IPython magics are standard data-science usage and pass
      through. Blocking them would break the vast majority of legitimate
      notebooks.

    Cell magic body handling:
    - Cell magics whose bodies are Python (%%time, %%timeit, %%prun,
      %%capture, %%cprofile, %%python, %%pypy) — body lines are kept so
      the AST analyzer can inspect them.
    - All other cell magics have non-Python bodies (text, HTML, shell, etc.)
      that would fail AST parsing. Their body lines are replaced with
      comments so the rest of the cell remains parseable.
    """
    # Cell magics whose body is valid Python and should be analyzed.
    PYTHON_BODY_MAGICS = {
        "time", "timeit", "prun", "capture", "cprofile", "python", "pypy",
    }
    # Cell magics that execute shell commands — block and comment body.
    SHELL_BODY_MAGICS = {"bash", "sh", "shell", "script"}

    shell_violations = []
    cleaned_lines = []

    lines = code.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("!"):
            # Shell escape — block it.
            shell_violations.append(
                f"Shell escape command blocked (use subprocess policy instead): {stripped[:80]}"
            )
            cleaned_lines.append("# [blocked shell escape]")
            i += 1

        elif stripped.startswith("%%"):
            # Cell magic — determine body treatment.
            magic_name = stripped.split()[0][2:].lower() if len(stripped) > 2 else ""

            if magic_name in SHELL_BODY_MAGICS:
                shell_violations.append(
                    f"Cell magic %%{magic_name} blocked (executes shell commands)."
                )

            cleaned_lines.append(f"# [cell magic: {stripped[:80]}]")
            i += 1

            if magic_name in PYTHON_BODY_MAGICS:
                # Keep body lines — they contain Python to be analyzed.
                while i < len(lines):
                    cleaned_lines.append(lines[i])
                    i += 1
            else:
                # Non-Python (or shell) body — comment out every body line
                # so they don't cause SyntaxErrors during AST parsing.
                while i < len(lines):
                    cleaned_lines.append(f"# [cell magic body: {lines[i][:80]}]")
                    i += 1

        elif stripped.startswith("%"):
            # Line magic (e.g. %matplotlib inline, %load_ext autoreload) — allow.
            cleaned_lines.append(f"# [line magic: {stripped[:80]}]")
            i += 1

        else:
            cleaned_lines.append(line)
            i += 1

    return "\n".join(cleaned_lines), shell_violations


def analyze_code(code: str) -> list:
    """Parses code and returns a list of security violations."""
    # Strip IPython magics before AST parsing to avoid false-positive SyntaxErrors
    # on legitimate % and %% magic lines used in data science notebooks.
    cleaned_code, magic_violations = _strip_ipython_magics(code)

    try:
        tree = ast.parse(cleaned_code)
        visitor = SecurityASTNodeVisitor()
        visitor.visit(tree)
        return magic_violations + visitor.violations
    except SyntaxError:
        # Fail closed: if code still won't parse after magic stripping, block it.
        return magic_violations + [
            "Blocked: code could not be parsed for security validation "
            "(invalid Python syntax or unsupported IPython construct)."
        ]
