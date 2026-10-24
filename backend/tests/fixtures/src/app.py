import sqlite3
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/cfg", methods=["POST"])
def cfg():
    return str(yaml.load(request.data))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
