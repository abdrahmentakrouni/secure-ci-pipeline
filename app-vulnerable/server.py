"""Same inventory service as app/server.py.

The vulnerability here is not the application code — it is everything
around it: an end-of-life base image, dependency versions with known
CVEs, and a container that runs as root. The pipeline is expected to
BLOCK this build.
"""

from flask import Flask, jsonify

APP_VERSION = "0.1.0"

app = Flask(__name__)

ITEMS = {
    "hk-001": {"name": "helmet", "stock": 42},
    "gl-002": {"name": "gloves", "stock": 128},
}


@app.route("/health", methods=["GET"])
def health():
    return jsonify(status="ok", version=APP_VERSION)


@app.route("/items", methods=["GET"])
def list_items():
    return jsonify(items=ITEMS)


@app.route("/items/<item_id>", methods=["GET"])
def get_item(item_id):
    if item_id not in ITEMS:
        return jsonify(error="not found"), 404
    return jsonify(ITEMS[item_id])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
