import type { FindingSource, Severity } from '@/types/contract'

/** One vulnerability pattern; each `site` becomes a finding in some scan. */
export interface Template {
  key: string
  title: string
  cwe_id: string
  owasp: string
  source: FindingSource
  rule_id: string | null
  severity: Severity
  /** Python code containing the bug. `fn` is the enclosing function name. */
  snippet: (fn: string) => string
  mitigation: string
  /** [file_path, start_line, function name]; prefixed "acme:" or "billing:" for the project. */
  sites: [string, number, string][]
}

const O = {
  A01: 'A01:2025 Broken Access Control',
  A02: 'A02:2025 Security Misconfiguration',
  A03: 'A03:2025 Software Supply Chain Failures',
  A04: 'A04:2025 Cryptographic Failures',
  A05: 'A05:2025 Injection',
  A06: 'A06:2025 Insecure Design',
  A07: 'A07:2025 Authentication Failures',
  A08: 'A08:2025 Software or Data Integrity Failures',
  A09: 'A09:2025 Security Logging and Alerting Failures',
  A10: 'A10:2025 Mishandling of Exceptional Conditions',
}

export const templates: Template[] = [
  {
    key: 'sqli-fstring',
    title: 'SQL query built with an f-string',
    cwe_id: 'CWE-89',
    owasp: O.A05,
    source: 'both',
    rule_id: 'B608',
    severity: 'critical',
    snippet: (fn) => `def ${fn}(value):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM records WHERE key = '{value}'")
    return cur.fetchone()`,
    mitigation: `User input is interpolated straight into SQL, so a value like \`' OR 1=1 --\` rewrites the query.

Use a parameterised query and let the driver escape the value:

\`\`\`python
cur.execute("SELECT * FROM records WHERE key = %s", (value,))
\`\`\``,
    sites: [
      ['acme:app/db/orders.py', 42, 'get_order'],
      ['acme:app/db/users.py', 77, 'find_user_by_email'],
      ['billing:billing_worker/db/invoices.py', 31, 'load_invoice'],
    ],
  },
  {
    key: 'sqli-format',
    title: 'SQL query built with % formatting',
    cwe_id: 'CWE-89',
    owasp: O.A05,
    source: 'rule',
    rule_id: 'B608',
    severity: 'high',
    snippet: (fn) => `def ${fn}(region, since):
    sql = "SELECT sku, SUM(total) FROM sales WHERE region = '%s' AND day > '%s'" % (region, since)
    return db.engine.execute(sql).fetchall()`,
    mitigation: `Bind values instead of formatting them into the SQL string:

\`\`\`python
sql = text("SELECT sku, SUM(total) FROM sales WHERE region = :region AND day > :since")
db.session.execute(sql, {"region": region, "since": since})
\`\`\``,
    sites: [['acme:app/reports/sales.py', 58, 'sales_by_region']],
  },
  {
    key: 'sqli-raw-orm',
    title: 'Search term concatenated into ORM raw() query',
    cwe_id: 'CWE-89',
    owasp: O.A05,
    source: 'ml',
    rule_id: null,
    severity: 'high',
    snippet: (fn) => `def ${fn}(request):
    term = request.args.get("q", "")
    clause = "name LIKE '%" + term + "%'"
    return Product.objects.raw("SELECT * FROM product WHERE " + clause)`,
    mitigation: `The query is assembled through string concatenation across two variables, which pattern rules miss.

Pass the term as a parameter:

\`\`\`python
Product.objects.raw("SELECT * FROM product WHERE name LIKE %s", [f"%{term}%"])
\`\`\``,
    sites: [['acme:app/catalog/search.py', 23, 'search_products']],
  },
  {
    key: 'os-system',
    title: 'Shell command built from a file name',
    cwe_id: 'CWE-78',
    owasp: O.A05,
    source: 'rule',
    rule_id: 'B605',
    severity: 'critical',
    snippet: (fn) => `def ${fn}(name):
    target = f"/tmp/out/{name}"
    os.system("convert uploads/" + name + " -resize 200x200 " + target)
    return target`,
    mitigation: `A file name such as \`x.png; rm -rf /\` runs extra commands.

Call the program with an argument list and no shell:

\`\`\`python
subprocess.run(["convert", f"uploads/{name}", "-resize", "200x200", target], check=True)
\`\`\``,
    sites: [
      ['acme:app/utils/thumbnails.py', 19, 'make_thumbnail'],
      ['billing:billing_worker/export/archive.py', 44, 'archive_month'],
    ],
  },
  {
    key: 'subprocess-shell',
    title: 'subprocess called with shell=True and user input',
    cwe_id: 'CWE-78',
    owasp: O.A05,
    source: 'both',
    rule_id: 'B602',
    severity: 'critical',
    snippet: (fn) => `def ${fn}(label):
    cmd = f"pg_dump shop > /backups/{label}.sql"
    subprocess.run(cmd, shell=True, check=True)`,
    mitigation: `Drop \`shell=True\`, pass an argument list and validate \`label\` against \`^[a-z0-9-]+$\`:

\`\`\`python
with open(f"/backups/{label}.sql", "wb") as out:
    subprocess.run(["pg_dump", "shop"], stdout=out, check=True)
\`\`\``,
    sites: [['acme:app/admin/backup.py', 31, 'run_backup']],
  },
  {
    key: 'eval',
    title: 'eval() on a stored discount rule',
    cwe_id: 'CWE-95',
    owasp: O.A05,
    source: 'rule',
    rule_id: 'B307',
    severity: 'critical',
    snippet: (fn) => `def ${fn}(cart, rule):
    # rule.expression is edited by staff in the admin panel
    if eval(rule.expression, {"cart": cart}):
        cart.total *= (1 - rule.percent / 100)`,
    mitigation: `\`eval\` runs arbitrary Python. Parse the rule into a small, fixed grammar instead, or use \`ast.literal_eval\` for literals only.`,
    sites: [['acme:app/pricing/rules.py', 66, 'apply_discount_rule']],
  },
  {
    key: 'ssti',
    title: 'User text rendered as a Jinja2 template',
    cwe_id: 'CWE-1336',
    owasp: O.A05,
    source: 'ml',
    rule_id: null,
    severity: 'high',
    snippet: (fn) => `def ${fn}(user, custom_footer):
    body = "Hi {{ user.name }},<br>" + custom_footer
    return render_template_string(body, user=user)`,
    mitigation: `\`custom_footer\` becomes part of the template, so \`{{ config.SECRET_KEY }}\` or worse is evaluated.

Pass user text as a variable, never as template source:

\`\`\`python
render_template_string("Hi {{ user.name }},<br>{{ footer }}", user=user, footer=custom_footer)
\`\`\``,
    sites: [['acme:app/emails/render.py', 14, 'render_email']],
  },
  {
    key: 'pickle',
    title: 'Untrusted data passed to pickle.loads',
    cwe_id: 'CWE-502',
    owasp: O.A08,
    source: 'both',
    rule_id: 'B301',
    severity: 'critical',
    snippet: (fn) => `def ${fn}(raw):
    data = base64.b64decode(raw)
    return pickle.loads(data)`,
    mitigation: `Unpickling attacker-controlled bytes executes code.

Store the data as signed JSON and verify the signature before use:

\`\`\`python
serializer = URLSafeSerializer(current_app.secret_key)
return serializer.loads(raw)
\`\`\``,
    sites: [
      ['acme:app/cache/session.py', 88, 'load_session'],
      ['billing:billing_worker/queue/consumer.py', 52, 'decode_job'],
    ],
  },
  {
    key: 'yaml-load',
    title: 'yaml.load without a safe loader',
    cwe_id: 'CWE-502',
    owasp: O.A08,
    source: 'rule',
    rule_id: 'B506',
    severity: 'high',
    snippet: (fn) => `def ${fn}(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.Loader)`,
    mitigation: `Use \`yaml.safe_load(fh)\`, which only builds plain Python types.`,
    sites: [
      ['acme:config/loader.py', 12, 'load_config'],
      ['billing:billing_worker/settings.py', 9, 'load_settings'],
    ],
  },
  {
    key: 'ssrf',
    title: 'Server fetches a user-supplied URL',
    cwe_id: 'CWE-918',
    owasp: O.A01,
    source: 'ml',
    rule_id: null,
    severity: 'high',
    snippet: (fn) => `def ${fn}(target):
    url = target.url  # set by the customer
    resp = requests.post(url, json=target.payload, timeout=5)
    return resp.status_code`,
    mitigation: `An attacker can point the URL at \`http://169.254.169.254/\` or internal services.

Resolve the host first and reject private, loopback and link-local addresses; keep an allow-list of domains where possible.`,
    sites: [
      ['acme:app/webhooks/dispatch.py', 31, 'deliver_webhook'],
      ['acme:app/media/import_url.py', 18, 'fetch_remote_image'],
    ],
  },
  {
    key: 'path-traversal',
    title: 'Path traversal in file download',
    cwe_id: 'CWE-22',
    owasp: O.A01,
    source: 'both',
    rule_id: 'python.flask.security.injection.path-traversal-open',
    severity: 'high',
    snippet: (fn) => `def ${fn}(name):
    path = os.path.join(INVOICE_DIR, name)
    return send_file(path)`,
    mitigation: `\`name = "../../etc/passwd"\` escapes the folder. Resolve the path and check it stays inside:

\`\`\`python
path = (INVOICE_DIR / name).resolve()
if not path.is_relative_to(INVOICE_DIR):
    abort(404)
\`\`\``,
    sites: [['acme:app/files/download.py', 23, 'download_invoice']],
  },
  {
    key: 'idor',
    title: 'Record lookup skips the ownership check',
    cwe_id: 'CWE-639',
    owasp: O.A01,
    source: 'ml',
    rule_id: null,
    severity: 'medium',
    snippet: (fn) => `@bp.get("/<int:record_id>")
@login_required
def ${fn}(record_id):
    return Record.query.get_or_404(record_id).to_dict()`,
    mitigation: `Any logged-in user can read any record by changing the id. Filter by owner:

\`\`\`python
Record.query.filter_by(id=record_id, owner_id=current_user.id).first_or_404()
\`\`\``,
    sites: [
      ['acme:app/api/orders.py', 61, 'get_order_api'],
      ['acme:app/api/invoices.py', 40, 'get_invoice_api'],
    ],
  },
  {
    key: 'missing-auth',
    title: 'Admin export route has no role check',
    cwe_id: 'CWE-862',
    owasp: O.A01,
    source: 'ml',
    rule_id: null,
    severity: 'high',
    snippet: (fn) => `@admin_bp.get("/customers.csv")
@login_required
def ${fn}():
    rows = Customer.query.all()
    return csv_response(rows)`,
    mitigation: `\`login_required\` only checks that someone is signed in. Add a role check such as \`@roles_required("admin")\` to every route in \`admin_bp\`.`,
    sites: [['acme:app/admin/views.py', 88, 'export_customers']],
  },
  {
    key: 'open-redirect',
    title: 'Open redirect after login',
    cwe_id: 'CWE-601',
    owasp: O.A01,
    source: 'rule',
    rule_id: 'python.flask.security.open-redirect.open-redirect',
    severity: 'medium',
    snippet: (fn) => `def ${fn}():
    login_user(user)
    return redirect(request.args.get("next", "/"))`,
    mitigation: `Only redirect to relative paths on this site:

\`\`\`python
target = request.args.get("next", "/")
if urlparse(target).netloc:
    target = "/"
\`\`\``,
    sites: [['acme:app/auth/login.py', 54, 'login_redirect']],
  },
  {
    key: 'hardcoded-secret',
    title: 'Hard-coded secret in source',
    cwe_id: 'CWE-798',
    owasp: O.A07,
    source: 'rule',
    rule_id: 'B105',
    severity: 'high',
    snippet: () => `SECRET_KEY = "zs-prod-7f3a9c1e5b"
STRIPE_API_KEY = "sk_live_51Hx9QeExampleExampleEx"
DEBUG = False`,
    mitigation: `Read secrets from the environment (\`os.environ["SECRET_KEY"]\`) or a secret manager, and rotate the values that were committed.`,
    sites: [
      ['acme:app/settings.py', 9, 'settings'],
      ['billing:billing_worker/stripe_client.py', 5, 'stripe_client'],
    ],
  },
  {
    key: 'md5-password',
    title: 'Passwords hashed with MD5',
    cwe_id: 'CWE-327',
    owasp: O.A04,
    source: 'rule',
    rule_id: 'B324',
    severity: 'medium',
    snippet: (fn) => `def ${fn}(password):
    return hashlib.md5(password.encode()).hexdigest()`,
    mitigation: `MD5 is fast and unsalted here. Use a password hash such as \`argon2-cffi\`:

\`\`\`python
from argon2 import PasswordHasher
return PasswordHasher().hash(password)
\`\`\``,
    sites: [['acme:app/auth/passwords.py', 7, 'hash_password']],
  },
  {
    key: 'random-token',
    title: 'Reset token generated with random',
    cwe_id: 'CWE-330',
    owasp: O.A04,
    source: 'rule',
    rule_id: 'B311',
    severity: 'medium',
    snippet: (fn) => `def ${fn}():
    return "".join(random.choice(ALPHABET) for _ in range(16))`,
    mitigation: `\`random\` is predictable. Use \`secrets.token_urlsafe(32)\` for security tokens.`,
    sites: [['acme:app/auth/reset.py', 15, 'make_reset_token']],
  },
  {
    key: 'verify-false',
    title: 'TLS certificate verification disabled',
    cwe_id: 'CWE-295',
    owasp: O.A04,
    source: 'rule',
    rule_id: 'B501',
    severity: 'medium',
    snippet: (fn) => `def ${fn}(payload):
    resp = requests.post(GATEWAY_URL, json=payload, verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()`,
    mitigation: `Remove \`verify=False\`. If the gateway uses a private CA, pass its bundle: \`verify="/etc/ssl/gateway-ca.pem"\`.`,
    sites: [
      ['acme:app/payments/gateway.py', 47, 'charge_card'],
      ['billing:billing_worker/banking/sync.py', 28, 'pull_statements'],
    ],
  },
  {
    key: 'jwt-noverify',
    title: 'JWT decoded without signature verification',
    cwe_id: 'CWE-347',
    owasp: O.A07,
    source: 'both',
    rule_id: 'python.jwt.security.unverified-jwt-decode',
    severity: 'high',
    snippet: (fn) => `def ${fn}(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return User.query.get(claims["sub"])`,
    mitigation: `Anyone can forge a token. Verify with the key and pin the algorithm:

\`\`\`python
claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience="acme-shop")
\`\`\``,
    sites: [['acme:app/auth/tokens.py', 33, 'decode_token']],
  },
  {
    key: 'flask-debug',
    title: 'Flask app runs with debug=True',
    cwe_id: 'CWE-489',
    owasp: O.A02,
    source: 'rule',
    rule_id: 'B201',
    severity: 'medium',
    snippet: () => `if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)`,
    mitigation: `The Werkzeug debugger allows code execution. Drive debug from configuration: \`debug=os.getenv("FLASK_DEBUG") == "1"\`.`,
    sites: [['acme:app/main.py', 54, 'main']],
  },
  {
    key: 'cors-wildcard',
    title: 'CORS allows any origin with credentials',
    cwe_id: 'CWE-942',
    owasp: O.A02,
    source: 'ml',
    rule_id: null,
    severity: 'medium',
    snippet: (fn) => `def ${fn}():
    app = Flask(__name__)
    CORS(app, origins="*", supports_credentials=True)
    return app`,
    mitigation: `List the allowed origins explicitly, e.g. \`CORS(app, origins=["https://shop.acme.test"], supports_credentials=True)\`.`,
    sites: [['acme:app/main.py', 21, 'create_app']],
  },
  {
    key: 'bind-all',
    title: 'Service binds to all interfaces',
    cwe_id: 'CWE-605',
    owasp: O.A02,
    source: 'rule',
    rule_id: 'B104',
    severity: 'low',
    snippet: (fn) => `def ${fn}():
    server = HTTPServer(("0.0.0.0", 9100), HealthHandler)
    server.serve_forever()`,
    mitigation: `Bind to \`127.0.0.1\` or the container network interface unless the port must be public.`,
    sites: [['billing:billing_worker/health.py', 12, 'serve_health']],
  },
  {
    key: 'xxe',
    title: 'XML parsed with external entities enabled',
    cwe_id: 'CWE-611',
    owasp: O.A02,
    source: 'rule',
    rule_id: 'B320',
    severity: 'high',
    snippet: (fn) => `def ${fn}(xml_bytes):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_bytes, parser)`,
    mitigation: `Use \`defusedxml\`: \`from defusedxml.lxml import fromstring\`, or set \`resolve_entities=False, no_network=True\`.`,
    sites: [['acme:app/integrations/supplier_feed.py', 26, 'parse_feed']],
  },
  {
    key: 'tar-extract',
    title: 'tarfile.extractall on an uploaded archive',
    cwe_id: 'CWE-22',
    owasp: O.A01,
    source: 'rule',
    rule_id: 'B202',
    severity: 'high',
    snippet: (fn) => `def ${fn}(upload):
    with tarfile.open(fileobj=upload) as tar:
        tar.extractall(IMPORT_DIR)`,
    mitigation: `Members named \`../../app.py\` overwrite files. On Python 3.12+ use \`tar.extractall(IMPORT_DIR, filter="data")\`; otherwise check every member path first.`,
    sites: [['acme:app/imports/bulk.py', 39, 'import_archive']],
  },
  {
    key: 'bare-except',
    title: 'Exception silently swallowed',
    cwe_id: 'CWE-703',
    owasp: O.A10,
    source: 'rule',
    rule_id: 'B110',
    severity: 'low',
    snippet: (fn) => `def ${fn}(job):
    try:
        job.run()
    except Exception:
        pass`,
    mitigation: `Catch the exceptions you expect and log the rest with \`logger.exception("job %s failed", job.id)\`.`,
    sites: [
      ['acme:app/jobs/worker.py', 40, 'process_job'],
      ['billing:billing_worker/retry.py', 17, 'retry_failed'],
    ],
  },
  {
    key: 'assert-auth',
    title: 'assert used for an authorisation check',
    cwe_id: 'CWE-703',
    owasp: O.A10,
    source: 'both',
    rule_id: 'B101',
    severity: 'medium',
    snippet: (fn) => `def ${fn}(user, product_id):
    assert user.is_admin, "admins only"
    Product.query.filter_by(id=product_id).delete()`,
    mitigation: `Asserts are removed under \`python -O\`, so the check disappears. Raise explicitly: \`if not user.is_admin: abort(403)\`.`,
    sites: [['acme:app/api/admin.py', 22, 'delete_product']],
  },
  {
    key: 'log-secrets',
    title: 'Password written to the application log',
    cwe_id: 'CWE-532',
    owasp: O.A09,
    source: 'ml',
    rule_id: null,
    severity: 'medium',
    snippet: (fn) => `def ${fn}(email, password):
    logger.info("login attempt %s / %s", email, password)
    return check_credentials(email, password)`,
    mitigation: `Never log credentials. Log the email and the outcome only, and scrub existing logs.`,
    sites: [['acme:app/auth/login.py', 71, 'authenticate']],
  },
  {
    key: 'redos',
    title: 'Regular expression vulnerable to catastrophic backtracking',
    cwe_id: 'CWE-1333',
    owasp: O.A06,
    source: 'ml',
    rule_id: null,
    severity: 'medium',
    snippet: (fn) => `EMAIL_RE = re.compile(r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$")

def ${fn}(value):
    return EMAIL_RE.match(value) is not None`,
    mitigation: `The nested \`(...)+)*\` group backtracks exponentially on long input. Limit input length first and use a linear pattern, or the \`email-validator\` package.`,
    sites: [['acme:app/validators.py', 12, 'is_valid_email']],
  },
  {
    key: 'dynamic-import',
    title: 'Module imported from a request parameter',
    cwe_id: 'CWE-829',
    owasp: O.A03,
    source: 'ml',
    rule_id: null,
    severity: 'high',
    snippet: (fn) => `def ${fn}(request):
    name = request.args["plugin"]
    module = importlib.import_module(f"plugins.{name}")
    return module.run(request.json)`,
    mitigation: `Map allowed plugin names to modules explicitly:

\`\`\`python
PLUGINS = {"csv": plugins.csv_export, "pdf": plugins.pdf_export}
module = PLUGINS.get(name) or abort(404)
\`\`\``,
    sites: [['acme:app/plugins/loader.py', 18, 'load_plugin']],
  },
  {
    key: 'toctou',
    title: 'Balance check and debit are not atomic',
    cwe_id: 'CWE-367',
    owasp: O.A06,
    source: 'ml',
    rule_id: null,
    severity: 'high',
    snippet: (fn) => `def ${fn}(sender, receiver, amount):
    if sender.balance >= amount:
        sender.balance -= amount
        receiver.balance += amount
        db.session.commit()`,
    mitigation: `Two concurrent requests can both pass the check. Do it in one locked transaction:

\`\`\`python
sender = Wallet.query.with_for_update().get(sender.id)
\`\`\`

or a single \`UPDATE ... WHERE balance >= :amount\`.`,
    sites: [['acme:app/wallet/transfer.py', 29, 'transfer_credit']],
  },
  {
    key: 'mass-assignment',
    title: 'Request body copied onto the user model',
    cwe_id: 'CWE-915',
    owasp: O.A06,
    source: 'ml',
    rule_id: null,
    severity: 'medium',
    snippet: (fn) => `def ${fn}():
    for key, value in request.json.items():
        setattr(current_user, key, value)
    db.session.commit()`,
    mitigation: `A client can set \`is_admin\` or \`balance\`. Copy only allowed fields:

\`\`\`python
for key in ("display_name", "phone"):
    if key in request.json:
        setattr(current_user, key, request.json[key])
\`\`\``,
    sites: [['acme:app/api/users.py', 47, 'update_profile']],
  },
  {
    key: 'stack-trace',
    title: 'Exception details returned to the client',
    cwe_id: 'CWE-209',
    owasp: O.A10,
    source: 'rule',
    rule_id: 'python.flask.security.audit.debug-template',
    severity: 'low',
    snippet: (fn) => `@app.errorhandler(Exception)
def ${fn}(exc):
    return {"error": str(exc), "trace": traceback.format_exc()}, 500`,
    mitigation: `Log the trace server-side and return a generic message with a request id.`,
    sites: [['acme:app/api/errors.py', 8, 'handle_error']],
  },
]
