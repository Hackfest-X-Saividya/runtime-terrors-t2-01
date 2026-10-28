// Small vulnerable Flask app posted by "Run demo scan". It is only sent to the
// scanner as text; nothing here is ever executed.

export const DEMO_FILENAME = 'demo_shop.py'

export const DEMO_CODE = `import base64, hashlib, os, pickle, subprocess
import requests
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)
SECRET_KEY = "demo-secret-do-not-ship"


@app.get("/order")
def get_order():
    order_id = request.args["id"]
    cur = db.cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")
    return cur.fetchone()


@app.post("/backup")
def run_backup():
    label = request.form["label"]
    subprocess.run(f"pg_dump shop > /backups/{label}.sql", shell=True)
    return "ok"


@app.get("/session")
def load_session():
    return pickle.loads(base64.b64decode(request.cookies["s"]))


@app.post("/webhook-test")
def deliver_webhook():
    return str(requests.post(request.json["url"], json={}).status_code)


@app.get("/hello")
def hello():
    return render_template_string("Hi " + request.args.get("name", ""))


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


@app.get("/login")
def login_redirect():
    return redirect(request.args.get("next", "/"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
`
