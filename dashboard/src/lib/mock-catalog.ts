import type { EvidenceBlock, Finding } from "./types";

/**
 * Scripted demo data modelled on the real scan target: PyGoat (OWASP's intentionally vulnerable Django app),
 * GitHub fork sapoepsilon/tirith-demo-target (default branch master).
 * Paths, line numbers and snippets come from that tree. Secrets shown are redacted.
 */

export const MOCK_ASSET = {
  id: "ast_pygoat",
  kind: "github_repo" as const,
  ref: "sapoepsilon/tirith-demo-target",
  name: "pygoat",
  created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
};

type Seed = Omit<Finding, "scan_id" | "asset_id" | "status" | "validation" | "fix_id" | "ai_summary"> & {
  ai_summary: string;
};

const base = {
  cwe: null,
  cve: null,
  package: null,
  installed_version: null,
  fixed_version: null,
  url: null,
};

export const SEEDS: Seed[] = [
  {
    ...base,
    id: "fnd_secret_django",
    fingerprint: "77c2d1b9",
    tool: "gitleaks",
    rule_id: "generic-api-key",
    title: "Hard-coded Django SECRET_KEY",
    description:
      "The Django SECRET_KEY is committed in pygoat/settings.py. Anyone with repository read access can forge signed session cookies, password-reset tokens and other signed values.",
    severity: "critical",
    category: "secret",
    file: "pygoat/settings.py",
    line: 23,
    snippet: 'SECRET_KEY = "lr66%-a!$km5••••••••••••••••••REDACTED"',
    cwe: "CWE-798",
    confidence: 0.97,
    ai_summary:
      "SECRET_KEY is a literal in settings.py and is present in the git history. Load it from the environment and rotate it; every existing session is invalidated on rotation, which is acceptable.",
  },
  {
    ...base,
    id: "fnd_sqli_lab",
    fingerprint: "a91f0c2e",
    tool: "semgrep",
    rule_id: "python.flask.security.injection.tainted-sql-string",
    title: "SQL injection in SQL injection lab login",
    description:
      "`username` and `password` from the login form are interpolated into an f-string SQL query that is passed to `cursor.execute`. An attacker can alter the query structure and log in as any user without the password.",
    severity: "critical",
    category: "sast",
    file: "dockerized_labs/sql_injection_lab/app.py",
    line: 50,
    snippet:
      "sql_query = (\n    f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n)",
    cwe: "CWE-89",
    confidence: 0.95,
    ai_summary:
      "Tainted form fields flow from `request.form` into an f-string SQL statement with no parameter binding. Reachable unauthenticated via POST /lab; classic `admin'--` login bypass.",
  },
  {
    ...base,
    id: "fnd_pickle_deser",
    fingerprint: "d27b6f43",
    tool: "semgrep",
    rule_id: "python.lang.security.deserialization.pickle.avoid-pickle",
    title: "Insecure deserialization with pickle.loads",
    description:
      "Base64 data from the `serialized_data` form field is passed straight to `pickle.loads`. A crafted pickle payload runs arbitrary code in the server process.",
    severity: "critical",
    category: "sast",
    file: "dockerized_labs/insec_des_lab/main.py",
    line: 40,
    snippet: "decoded_data = base64.b64decode(serialized_data)\nuser = pickle.loads(decoded_data)",
    cwe: "CWE-502",
    confidence: 0.96,
    ai_summary:
      "Untrusted request data reaches `pickle.loads` unauthenticated via POST /deserialize, giving remote code execution. Replace with a JSON payload that is signed.",
  },
  {
    ...base,
    id: "fnd_cmd_injection",
    fingerprint: "58e1b0aa",
    tool: "semgrep",
    rule_id: "python.lang.security.audit.subprocess-shell-true",
    title: "OS command injection in nslookup lab",
    description:
      "The `domain` form field is formatted into a shell command that runs with `shell=True`. Shell metacharacters such as `;` or `&&` execute arbitrary commands.",
    severity: "high",
    category: "sast",
    file: "dockerized_labs/command_injection_lab/app.py",
    line: 29,
    snippet:
      "process = subprocess.Popen(\n    command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE\n)",
    cwe: "CWE-78",
    confidence: 0.93,
    ai_summary:
      "`command = f\"dig {domain}\"` is executed through a shell with unsanitised input. Use an argument list without `shell=True` and validate the hostname.",
  },
  {
    ...base,
    id: "fnd_yaml_load",
    fingerprint: "3be8a412",
    tool: "semgrep",
    rule_id: "python.lang.security.deserialization.avoid-pyyaml-load",
    title: "Unsafe yaml.load on uploaded file",
    description:
      "Uploaded YAML is parsed with `yaml.load(..., Loader=yaml.Loader)`, which constructs arbitrary Python objects. A `!!python/object/apply:` tag executes code on upload.",
    severity: "high",
    category: "sast",
    file: "dockerized_labs/a9_uckv_lab/app.py",
    line: 62,
    snippet: "data = yaml.load(file.stream, Loader=yaml.Loader)",
    cwe: "CWE-502",
    confidence: 0.91,
    ai_summary:
      "The lab pins PyYAML 5.1 as well, so the full-loader bypasses also apply. Switch to `yaml.safe_load`.",
  },
  {
    ...base,
    id: "fnd_xss_lab",
    fingerprint: "e4410c9d",
    tool: "semgrep",
    rule_id: "python.flask.security.xss.audit.template-unescaped-with-safe",
    title: "Reflected XSS in FAANG search lab",
    description:
      "The search term is rendered with the `|safe` filter, disabling Jinja2 autoescaping. A crafted link can run script in a victim's browser.",
    severity: "high",
    category: "sast",
    file: "dockerized_labs/xss_lab/templates/lab1.html",
    line: 30,
    snippet: "<h3>The company '{{ query|safe }}' You searched for is not Part of FAANG</h3>",
    cwe: "CWE-79",
    confidence: 0.88,
    ai_summary:
      "`q` from GET /lab1 is echoed into HTML with autoescape off. Drop the `|safe` filter.",
  },
  {
    ...base,
    id: "fnd_path_traversal",
    fingerprint: "c04d9e73",
    tool: "semgrep",
    rule_id: "python.flask.security.injection.path-traversal-open",
    title: "Path traversal in SSRF lab blog reader",
    description:
      "The `blog` form field is joined to the lab directory without normalisation and opened for reading, so `../` sequences can escape it.",
    severity: "high",
    category: "sast",
    file: "dockerized_labs/ssrf_lab/app.py",
    line: 21,
    snippet:
      "file_path = os.path.join(os.path.dirname(__file__), file)\nwith open(file_path, \"r\") as f:\n    blog_content = f.read()",
    cwe: "CWE-22",
    confidence: 0.71,
    ai_summary:
      "Pattern matches, but the lab runs as a non-root user in a slim container and a bare `except` hides errors. Needs dynamic validation before prioritising.",
  },
  {
    ...base,
    id: "fnd_dep_django",
    fingerprint: "e1a7f6d0",
    tool: "trivy",
    rule_id: "CVE-2024-42005",
    title: "Django 4.2: 7 CVEs (CVE-2024-42005, CVE-2024-53908, CVE-2023-31047, +4)",
    description:
      "Django==4.2 is affected by CVE-2024-42005 (SQL injection in QuerySet.values on JSONField), CVE-2024-53908 (SQL injection via HasKey on Oracle), CVE-2023-31047 (file upload validation bypass), CVE-2023-36053 (EmailValidator ReDoS), CVE-2023-43665 (Truncator DoS), CVE-2024-24680 (intcomma DoS) and CVE-2024-27351 (Truncator ReDoS). Upgrading to 4.2.26 in the same LTS line resolves all of them.",
    severity: "critical",
    category: "dependency",
    file: "requirements.txt",
    line: 12,
    snippet: "Django==4.2",
    cwe: "CWE-89",
    cve: "CVE-2024-42005",
    package: "Django",
    installed_version: "4.2",
    fixed_version: "4.2.26",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-42005",
    confidence: 0.98,
    ai_summary:
      "One patch-level bump within the 4.2 LTS line clears all 7 advisories with no API changes. Safe candidate for autonomous `dependency_bump`.",
  },
  {
    ...base,
    id: "fnd_dep_pyyaml",
    fingerprint: "5f2b8ac1",
    tool: "trivy",
    rule_id: "CVE-2020-14343",
    title: "PyYAML 5.1: 2 CVEs (CVE-2020-14343, CVE-2020-1747)",
    description:
      "PyYAML==5.1 is affected by CVE-2020-14343 and CVE-2020-1747, both arbitrary code execution through the full loader when parsing untrusted YAML. Version 6.0.2 resolves both.",
    severity: "critical",
    category: "dependency",
    file: "requirements.txt",
    line: 24,
    snippet: "PyYAML==5.1",
    cwe: "CWE-20",
    cve: "CVE-2020-14343",
    package: "PyYAML",
    installed_version: "5.1",
    fixed_version: "6.0.2",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
    confidence: 0.97,
    ai_summary: "Major-version bump, but `yaml.load` call sites already pass an explicit Loader. Low risk; the unsafe loader usage in the A9 lab still needs its own fix.",
  },
  {
    ...base,
    id: "fnd_dep_werkzeug",
    fingerprint: "9c0e7a35",
    tool: "trivy",
    rule_id: "CVE-2024-34069",
    title: "Werkzeug 2.1.2: 4 CVEs (CVE-2024-34069, CVE-2023-25577, CVE-2024-49767, +1)",
    description:
      "Werkzeug==2.1.2 is affected by CVE-2024-34069 (debugger code execution via a malicious domain), CVE-2023-25577 (multipart parser DoS), CVE-2024-49767 (multipart resource exhaustion) and CVE-2023-23934 (cookie parsing flaw). Version 3.0.6 resolves all four.",
    severity: "high",
    category: "dependency",
    file: "requirements.txt",
    line: 29,
    snippet: "Werkzeug==2.1.2",
    cwe: "CWE-94",
    cve: "CVE-2024-34069",
    package: "Werkzeug",
    installed_version: "2.1.2",
    fixed_version: "3.0.6",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-34069",
    confidence: 0.95,
    ai_summary: "Werkzeug is only used by the lab sub-apps and the debug server. Bump is safe and removes the debugger RCE path.",
  },
  {
    ...base,
    id: "fnd_debug_mode",
    fingerprint: "9ad3e5c7",
    tool: "semgrep",
    rule_id: "python.django.security.audit.django-debug-enabled",
    title: "Django DEBUG = True",
    description:
      "settings.py ships with `DEBUG = True`, exposing detailed error pages with settings, SQL queries and local variables to any visitor.",
    severity: "medium",
    category: "config",
    file: "pygoat/settings.py",
    line: 28,
    snippet: "DEBUG = True",
    cwe: "CWE-489",
    confidence: 0.92,
    ai_summary: "Debug pages leak configuration and stack frames. Read the flag from an environment variable, defaulting to off.",
  },
  {
    ...base,
    id: "fnd_md5_password",
    fingerprint: "1c6e0b58",
    tool: "semgrep",
    rule_id: "python.lang.security.audit.md5-used-as-password",
    title: "Passwords hashed with unsalted MD5",
    description: "The crypto failure lab stores and compares passwords as unsalted MD5 digests, which are trivially cracked.",
    severity: "medium",
    category: "sast",
    file: "dockerized_labs/crypto_failure_lab/app.py",
    line: 38,
    snippet: "password_hash = hashlib.md5(password.encode()).hexdigest()",
    cwe: "CWE-327",
    confidence: 0.92,
    ai_summary: "Lab code that is deliberately weak; replacing it needs a hash migration path, so escalate to a human.",
  },
  {
    ...base,
    id: "fnd_zap_csp",
    fingerprint: "b8e94f21",
    tool: "zap",
    rule_id: "zap-10038",
    title: "Content-Security-Policy header not set",
    description: "Responses do not include a CSP header, increasing the impact of any injection bug.",
    severity: "low",
    category: "dast",
    file: null,
    line: null,
    snippet: "GET http://pygoat.lab:8000/login/ → 200 (no Content-Security-Policy)",
    cwe: "CWE-693",
    url: "http://pygoat.lab:8000/login/",
    confidence: 0.8,
    ai_summary: "Add a restrictive default-src 'self' policy via Django middleware or django-csp.",
  },
  {
    ...base,
    id: "fnd_zap_cookie",
    fingerprint: "40a1c3de",
    tool: "zap",
    rule_id: "zap-10011",
    title: "Session cookie without Secure flag",
    description: "The `sessionid` cookie is sent without the Secure attribute because `SESSION_COOKIE_SECURE` is not set.",
    severity: "low",
    category: "dast",
    file: null,
    line: null,
    snippet: "Set-Cookie: sessionid=h3k••••••••; HttpOnly; Path=/; SameSite=Lax",
    cwe: "CWE-614",
    url: "http://pygoat.lab:8000/login/",
    confidence: 0.85,
    ai_summary: "Set SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE once the app is served over HTTPS.",
  },
  {
    ...base,
    id: "fnd_zap_server",
    fingerprint: "6d7f2e90",
    tool: "zap",
    rule_id: "zap-10036",
    title: "Server version disclosure",
    description: "The `Server` header leaks the WSGI server and Python versions.",
    severity: "info",
    category: "dast",
    file: null,
    line: null,
    snippet: "Server: gunicorn",
    url: "http://pygoat.lab:8000/",
    confidence: 0.99,
    ai_summary: "Informational; strip or override the Server header at the reverse proxy.",
  },
];

export const VALIDATIONS: Record<string, { check: string; steps: string[]; evidence: EvidenceBlock[] }> = {
  fnd_sqli_lab: {
    check: "cwe-89-sqli",
    steps: [
      "Building dockerized_labs/sql_injection_lab@a91f0c2 into isolated network tirith-lab (no egress)",
      "Seeding dummy users table (admin only)",
      "Baseline request: username=admin password=wrong → login rejected",
      "Probe request: username=admin'-- → logged in",
      "Comparing responses",
    ],
    evidence: [
      { kind: "note", label: "Template", content: "cwe-89-sqli · auth-bypass tautology, read-only, lab target only" },
      {
        kind: "request",
        label: "Baseline",
        content:
          "POST /lab HTTP/1.1\nHost: pygoat.lab:5012\nContent-Type: application/x-www-form-urlencoded\nUser-Agent: tirith-validator/1.0\n\nusername=admin&password=wrong",
      },
      {
        kind: "response",
        label: "Baseline response",
        content: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\n\n… Invalid username or password …",
      },
      {
        kind: "request",
        label: "Probe",
        content:
          "POST /lab HTTP/1.1\nHost: pygoat.lab:5012\nContent-Type: application/x-www-form-urlencoded\nUser-Agent: tirith-validator/1.0\n\nusername=admin%27--&password=x",
      },
      {
        kind: "response",
        label: "Probe response",
        content: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\n\n… Welcome admin …",
      },
      {
        kind: "log",
        label: "Verdict",
        content:
          "baseline=rejected probe=authenticated\ncomment terminator bypassed the password check → CONFIRMED (confidence 0.97)",
      },
    ],
  },
  fnd_xss_lab: {
    check: "cwe-79-reflected-xss",
    steps: [
      "Building dockerized_labs/xss_lab into tirith-lab",
      "Injecting inert canary <tirith-canary-7f3a> into q",
      "Checking response body for unescaped canary",
    ],
    evidence: [
      { kind: "request", label: "Probe", content: "GET /lab1?q=%3Ctirith-canary-7f3a%3E HTTP/1.1\nHost: pygoat.lab:5006" },
      {
        kind: "response",
        label: "Response excerpt",
        content: "HTTP/1.1 200 OK\n\n<h3>The company '<tirith-canary-7f3a>' You searched for is not Part of FAANG</h3>",
      },
      { kind: "log", label: "Verdict", content: "canary reflected unescaped in HTML context → CONFIRMED (0.93)" },
    ],
  },
  fnd_path_traversal: {
    check: "cwe-22-path-traversal",
    steps: [
      "Building dockerized_labs/ssrf_lab into tirith-lab",
      "Submitting blog=../../../../etc/hostname to /lab1",
      "Checking response for file contents",
    ],
    evidence: [
      {
        kind: "request",
        label: "Probe",
        content:
          "POST /lab1 HTTP/1.1\nHost: pygoat.lab:5010\nContent-Type: application/x-www-form-urlencoded\n\nblog=..%2F..%2F..%2F..%2Fetc%2Fhostname",
      },
      { kind: "response", label: "Response", content: "HTTP/1.1 200 OK\n\n… No blog found …" },
      {
        kind: "log",
        label: "Verdict",
        content: "traversal target not readable from the lab working directory, no file content returned → NOT REPRODUCED (0.82)",
      },
    ],
  },
};

export const DIFFS: Record<string, string> = {
  fnd_sqli_lab: `--- a/dockerized_labs/sql_injection_lab/app.py
+++ b/dockerized_labs/sql_injection_lab/app.py
@@ -47,11 +47,8 @@ def lab():
         password = request.form.get("password", "")

-        # Vulnerable SQL query construction (intentional)
-        sql_query = (
-            f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
-        )
+        sql_query = "SELECT * FROM users WHERE username=? AND password=?"

         try:
             conn = sqlite3.connect("database.db")
             c = conn.cursor()
-            result = c.execute(sql_query).fetchone()
+            result = c.execute(sql_query, (username, password)).fetchone()
`,
  fnd_secret_django: `--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -20,8 +20,8 @@
 # See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

 # SECURITY WARNING: keep the secret key used in production secret!
-SECRET_KEY = "lr66%-a!$km5••••••••••••••••••REDACTED"
+SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

 SENSITIVE_DATA = "FLAGTHATNEEDSTOBEFOUND"

`,
  fnd_pickle_deser: `--- a/dockerized_labs/insec_des_lab/main.py
+++ b/dockerized_labs/insec_des_lab/main.py
@@ -35,8 +35,8 @@ def serialize_data():
 @app.route("/deserialize", methods=["POST"])
 def deserialize_data():
     try:
         serialized_data = request.form.get("serialized_data", "")
         decoded_data = base64.b64decode(serialized_data)
-        # Intentionally vulnerable deserialization, matching PyGoat
-        user = pickle.loads(decoded_data)
+        payload = json.loads(decoded_data)
+        user = User(username=str(payload["username"]), is_admin=False)
`,
  fnd_cmd_injection: `--- a/dockerized_labs/command_injection_lab/app.py
+++ b/dockerized_labs/command_injection_lab/app.py
@@ -22,13 +22,14 @@ def lab1():
         if os_type == "win":
-            command = f"nslookup {domain}"
+            command = ["nslookup", domain]
         else:
-            command = f"dig {domain}"
+            command = ["dig", domain]

         try:
-            # Intentionally vulnerable command execution
+            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain):
+                raise ValueError("invalid hostname")
             process = subprocess.Popen(
-                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
+                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
             )
`,
  fnd_yaml_load: `--- a/dockerized_labs/a9_uckv_lab/app.py
+++ b/dockerized_labs/a9_uckv_lab/app.py
@@ -59,6 +59,5 @@ def upload_file():
     if file and allowed_file(file.filename):
         try:
-            # Intentionally vulnerable YAML loading
-            data = yaml.load(file.stream, Loader=yaml.Loader)
+            data = yaml.safe_load(file.stream)
             return render_template("result.html", content=data, filename=file.filename)
`,
  fnd_dep_django: `--- a/requirements.txt
+++ b/requirements.txt
@@ -10,7 +10,7 @@
 defusedxml==0.7.1
 dj-database-url==0.5.0
-Django==4.2
+Django==4.2.26
 django-allauth==0.52.0
 django-crispy-forms==2.3
 gunicorn==23.0.0
`,
  fnd_dep_pyyaml: `--- a/requirements.txt
+++ b/requirements.txt
@@ -22,7 +22,7 @@
 PyJWT==2.4.0
 python3-openid==3.2.0
 pytz==2020.1
-PyYAML==5.1
+PyYAML==6.0.2
 requests==2.28.2
 requests-oauthlib==1.3.1
 sqlparse==0.3.1
`,
  fnd_dep_werkzeug: `--- a/requirements.txt
+++ b/requirements.txt
@@ -27,6 +27,6 @@
 sqlparse==0.3.1
 urllib3==1.26.9
-Werkzeug==2.1.2
+Werkzeug==3.0.6
 whitenoise==6.2.0
 zipp==3.8.0
`,
  fnd_xss_lab: `--- a/dockerized_labs/xss_lab/templates/lab1.html
+++ b/dockerized_labs/xss_lab/templates/lab1.html
@@ -28,5 +28,5 @@
             <div class="search-result">
-                {# Vulnerable: Reflects unescaped user input #}
-                <h3>The company '{{ query|safe }}' You searched for is not Part of FAANG</h3>
+                <h3>The company '{{ query }}' You searched for is not Part of FAANG</h3>
             </div>
`,
  fnd_debug_mode: `--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -26,5 +26,5 @@

 # SECURITY WARNING: don't run with debug turned on in production!
-DEBUG = True
+DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"

 ALLOWED_HOSTS = ["pygoat.herokuapp.com", "0.0.0.0", "127.0.0.1", "localhost", "lvh.me", ".lvh.me", "web"]
`,
  fnd_zap_cookie: `--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -203,4 +203,6 @@
 SESSION_COOKIE_DOMAIN = os.environ.get("LAB_COOKIE_DOMAIN") or None
 CSRF_COOKIE_DOMAIN = SESSION_COOKIE_DOMAIN
 SESSION_COOKIE_SAMESITE = "Lax"
 CSRF_COOKIE_SAMESITE = "Lax"
+SESSION_COOKIE_SECURE = True
+CSRF_COOKIE_SECURE = True
`,
  fnd_zap_csp: `--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -61,3 +61,4 @@
     "django.contrib.messages.middleware.MessageMiddleware",
     "django.middleware.clickjacking.XFrameOptionsMiddleware",
+    "csp.middleware.CSPMiddleware",
 ]
`,
};

export const DEFAULT_DIFF = (f: Finding) => `--- a/${f.file ?? "pygoat/settings.py"}
+++ b/${f.file ?? "pygoat/settings.py"}
@@ -1,3 +1,4 @@
+# tirith: remediation for ${f.rule_id}
 ${(f.snippet ?? "").split("\n")[0]}
`;
