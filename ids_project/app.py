from flask import Flask, jsonify, render_template
import json
import os

app = Flask(__name__)

ALERT_FILE = "alerts.json"

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/api/alerts")
def get_alerts():
    if not os.path.exists(ALERT_FILE):
        return jsonify([])
    with open(ALERT_FILE) as f:
        return jsonify(json.load(f))

if __name__ == "__main__":
    app.run(debug=True)

