"""Static analyzer: parses Python source with the AST. It NEVER executes the code."""
import ast
import re

# rule_id -> (title, severity, why it is dangerous, safer recommendation, ML feature category)
RULES = {
    "CRY001": ("MD5 hash used", "MEDIUM", "MD5 is collision-broken; attackers can forge colliding inputs.", "Use hashlib.sha256 / sha3_256 (or BLAKE2).", "weak_algorithm"),
    "CRY002": ("SHA-1 hash used", "MEDIUM", "SHA-1 has practical collision attacks and is deprecated.", "Use SHA-256 or stronger.", "weak_algorithm"),
    "CRY003": ("Broken/deprecated cipher (DES/3DES/RC4/Blowfish)", "HIGH", "Small key/block sizes or known biases make these ciphers breakable.", "Use AES-256-GCM or ChaCha20-Poly1305.", "weak_algorithm"),
    "CRY004": ("ECB cipher mode", "HIGH", "ECB encrypts identical blocks identically and leaks data patterns.", "Use an authenticated mode such as AES-GCM.", "weak_cipher_mode"),
    "CRY005": ("Predictable random generator", "HIGH", "The 'random' module is a PRNG that is predictable; unsafe for keys, tokens, nonces.", "Use the 'secrets' module or os.urandom().", "weak_random"),
    "CRY006": ("Hardcoded key/secret/password", "CRITICAL", "Secrets in source code leak through repositories and binaries.", "Load secrets from environment variables or a secrets manager.", "hardcoded_secret"),
    "CRY007": ("Hardcoded IV/nonce/salt", "HIGH", "Static IVs/nonces break semantic security and can reveal plaintext (GCM nonce reuse is catastrophic).", "Generate a fresh random IV/nonce per message with os.urandom().", "hardcoded_secret"),
    "CRY008": ("Short key size", "HIGH", "Keys below recommended length can be factored or brute-forced.", "Use RSA >= 2048 bits (3072 preferred) or EC P-256+.", "short_key"),
    "CRY009": ("Certificate/TLS verification disabled", "CRITICAL", "Disabling verification allows man-in-the-middle attacks.", "Keep verify=True / ssl.create_default_context().", "insecure_tls"),
    "CRY010": ("Insecure SSL/TLS protocol version", "HIGH", "SSLv2/SSLv3/TLS1.0/TLS1.1 have known protocol attacks.", "Require TLS 1.2+ (ssl.TLSVersion.TLSv1_2).", "insecure_tls"),
    "CRY011": ("Fast hash used for password storage", "HIGH", "MD5/SHA-family hashes are too fast; passwords are cracked offline quickly.", "Use bcrypt, scrypt, argon2 or hashlib.pbkdf2_hmac with a salt.", "password_hash_issue"),
    "CRY012": ("Deprecated cryptographic API", "MEDIUM", "PyCrypto is unmaintained with known vulnerabilities; ssl.wrap_socket is removed.", "Use 'cryptography' or 'pycryptodomex' and ssl.SSLContext.", "deprecated_api"),
}

RANDOM_FUNCS = {"random", "randint", "choice", "randrange", "getrandbits", "shuffle", "sample", "uniform", "randbytes"}
SECRET_NAME = re.compile(r"(^|_)(secret|key|passwd|password|pwd|token|apikey|api_key|private_key)($|_)", re.I)
IV_NAME = re.compile(r"(^|_)(iv|nonce|salt)($|_)", re.I)
NOT_SECRET = re.compile(r"(size|length|len|bits|path|file|name|type|id)", re.I)
BAD_PROTOCOLS = {"PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "SSLv3_METHOD", "TLSv1_METHOD"}
OLD_CIPHERS = {"DES", "DES3", "ARC4", "ARC2", "TripleDES", "Blowfish", "RC4"}


def _dotted(node):
    """Turn an AST node like hashlib.md5 into the string 'hashlib.md5'."""
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_str_const(node, min_len=4):
    return (isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))
            and len(node.value) >= min_len)


class _Visitor(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines, self.findings, self._seen = lines, [], set()

    def add(self, rule_id, node):
        line = getattr(node, "lineno", 1)
        if (rule_id, line) in self._seen:
            return
        self._seen.add((rule_id, line))
        title, sev, why, fix, _ = RULES[rule_id]
        evidence = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append({"rule_id": rule_id, "title": title, "severity": sev, "line": line,
                              "description": why, "evidence": evidence[:200], "recommendation": fix})

    # --- function calls -------------------------------------------------
    def visit_Call(self, node):
        name = _dotted(node.func)
        last = name.split(".")[-1]
        args_text = " ".join(ast.unparse(a) for a in node.args).lower()
        is_hash = False

        if last == "md5" or (last == "new" and "md5" in args_text and name.startswith("hashlib")):
            self.add("CRY001", node); is_hash = True
        if last == "sha1" or (last == "new" and "sha1" in args_text and name.startswith("hashlib")):
            self.add("CRY002", node); is_hash = True
        if last in ("sha256", "sha512", "sha224", "sha384"):
            is_hash = True
        if is_hash and "password" in args_text or (is_hash and "passwd" in args_text):
            self.add("CRY011", node)

        if (last == "new" and name.split(".")[0] in OLD_CIPHERS) or last in OLD_CIPHERS:
            self.add("CRY003", node)
        if last == "ECB" or name.endswith("modes.ECB"):
            self.add("CRY004", node)
        if name.startswith("random.") and last in RANDOM_FUNCS and "SystemRandom" not in name:
            self.add("CRY005", node)

        if last in ("generate_private_key", "generate", "generate_parameters"):
            for kw in node.keywords:
                if kw.arg in ("key_size", "bits") and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, int) and kw.value.value < 2048:
                    self.add("CRY008", node)
            if name.startswith("RSA.") and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, int) and node.args[0].value < 2048:
                self.add("CRY008", node)

        if name.endswith("_create_unverified_context"):
            self.add("CRY009", node)
        if name == "ssl.wrap_socket":
            self.add("CRY012", node)

        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.add("CRY009", node)
            if kw.arg in ("key", "iv", "nonce", "password", "secret") and _is_str_const(kw.value):
                self.add("CRY007" if kw.arg in ("iv", "nonce") else "CRY006", node)
        self.generic_visit(node)

    # --- attributes such as ssl.CERT_NONE, AES.MODE_ECB ----------------------
    def visit_Attribute(self, node):
        if node.attr == "MODE_ECB":
            self.add("CRY004", node)
        elif node.attr == "CERT_NONE":
            self.add("CRY009", node)
        elif node.attr in BAD_PROTOCOLS:
            self.add("CRY010", node)
        self.generic_visit(node)

    # --- assignments: hardcoded secrets, check_hostname = False ----------------
    def visit_Assign(self, node):
        for target in node.targets:
            tname = _dotted(target) if isinstance(target, (ast.Name, ast.Attribute)) else ""
            base = tname.split(".")[-1]
            if base == "check_hostname" and isinstance(node.value, ast.Constant) and node.value.value is False:
                self.add("CRY009", node)
            if base and _is_str_const(node.value) and not NOT_SECRET.search(base):
                if IV_NAME.search(base):
                    self.add("CRY007", node)
                elif SECRET_NAME.search(base):
                    self.add("CRY006", node)
        self.generic_visit(node)

    # --- imports: PyCrypto ------------------------------------------------
    def visit_ImportFrom(self, node):
        if node.module and node.module.split(".")[0] == "Crypto":
            self.add("CRY012", node)

    def visit_Import(self, node):
        if any(a.name.split(".")[0] == "Crypto" for a in node.names):
            self.add("CRY012", node)


def analyze_source(source):
    """Return a list of findings. Raises ValueError for empty or malformed code."""
    if not source or not source.strip():
        raise ValueError("Source code is empty.")
    try:
        tree = ast.parse(source)  # parse only; nothing is executed
    except SyntaxError as exc:
        raise ValueError(f"Malformed Python (line {exc.lineno}): {exc.msg}") from exc
    visitor = _Visitor(source.splitlines())
    visitor.visit(tree)
    return sorted(visitor.findings, key=lambda f: f["line"])
