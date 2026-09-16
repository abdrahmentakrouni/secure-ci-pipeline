"""Minimal inventory service used as the pipeline's release candidate.

Deliberately tiny on purpose: the interesting part of this repository is
the security gate around the image, not the application inside it.
"""

from flask import Flask, jsonify

APP_VERSION = "1.0.0"

app = Flask(__name__)

ITEMS = {
    "hk-001": {"name": "helmet", "stock": 42},
    "gl-002": {"name": "gloves", "stock": 128},
}


@app.route("/health", methods=["GET"])
def health():
    """Liveness probe used by the container HEALTHCHECK."""
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
    app.run(host="127.0.0.1", port=8080)
