import ast

# Define restricted modules for import and usage
RESTRICTED_MODULES = [
    'os', 'subprocess', 'socket', 'pty', 'importlib',
    'sys', 'shutil', 'urllib', 'http', 'requests'
]

# Define restricted builtins
RESTRICTED_BUILTINS = [
    'eval', 'exec', 'compile', 'open', 'globals', 'locals',
    '__import__', 'getattr', 'setattr', 'delattr'
]

class SecurityASTNodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.violations = []

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
        # If any bare name matches a restricted builtin, we flag it.
        # This handles cases where they might alias eval:
        # e = eval; e(...)
        # Wait, flagging just ast.Name eval would break variables named `eval`.
        # But `eval` shouldn't be overridden in a secure environment either.
        # Actually, let's just stick to Call and let it slide if they assign it?
        # No, assigning eval to something else: `a = eval` is caught if `node.id == 'eval'` here.
        if node.id in ['__builtins__', '__class__', '__subclasses__', '__bases__', '__mro__', 'eval', 'exec', 'compile', 'open', '__import__', 'globals', 'locals']:
            self.violations.append(f"Access to restricted builtin namespace blocked: {node.id}")
        self.generic_visit(node)


def analyze_code(code: str) -> list:
    """Parses code and returns a list of security violations."""
    try:
        tree = ast.parse(code)
        visitor = SecurityASTNodeVisitor()
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return ["SyntaxError: Unable to parse code for security validation."]
