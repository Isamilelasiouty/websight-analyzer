"""
WebSight Analyzer — by Ismail El Asiouty
Flask web application for website performance & security analysis
"""

import asyncio
import json
import os
import threading
import uuid
from flask import Flask, render_template, request, jsonify
from analyzer import WebsiteAnalyzer

app = Flask(__name__)

# In-memory job store
jobs = {}

# Use system Chromium installed via nixpacks on Railway
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")


def run_analysis(job_id: str, url: str):
    """Run analyzer in background thread."""
    try:
        jobs[job_id]["status"] = "running"

        async def _analyze():
            analyzer = WebsiteAnalyzer(url)
            return await analyzer.run()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(_analyze())
        loop.close()

        jobs[job_id]["status"] = "done"
        jobs[job_id]["results"] = results
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL مطلوب"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "pending", "results": None, "error": None}

    thread = threading.Thread(target=run_analysis, args=(job_id, url), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/status/<job_id>")
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status": job["status"],
        "results": job["results"] if job["status"] == "done" else None,
        "error": job.get("error")
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)


@app.route("/report", methods=["POST"])
def report():
    """Return the HTML report for a completed job."""
    from analyzer import generate_dashboard
    import tempfile
    data = request.get_json()
    job_id = data.get("job_id")
    job = jobs.get(job_id)
    if not job or job["status"] != "done":
        return "التقرير غير متاح", 404
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        tmp_path = f.name
    generate_dashboard(job["results"], tmp_path)
    with open(tmp_path, encoding="utf-8") as f:
        html_content = f.read()
    os.unlink(tmp_path)
    return html_content, 200, {"Content-Type": "text/html; charset=utf-8"}
