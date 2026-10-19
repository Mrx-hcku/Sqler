import os
import subprocess
import sqlite3
import urllib.parse
from datetime import datetime
import numpy as np
from flask import Flask, request, jsonify, render_template_string
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from groq import Groq

app = Flask(__name__)

DB_FILE = "autonomous_scan_history.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                url TEXT,
                extracted_param TEXT,
                status TEXT,
                sqlmap_output TEXT,
                groq_analysis TEXT
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Init Error: {e}")

init_db()

# Load TensorFlow Model (agar file na ho toh error ignore karega)
try:
    model = tf.keras.models.load_model('sql_injection_model.h5')
except Exception as e:
    model = None

# Groq API Setup (Environment variable ya fallback)
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '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')
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autonomous AI Security Scanner</title>
    <style>
        :root { --primary: #0284c7; --bg: #0f172a; --card-bg: #1e293b; --text: #f8fafc; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: var(--bg); color: var(--text); }
        .navbar { background: #090d16; color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
        .container { max-width: 900px; margin: 40px auto; background: var(--card-bg); padding: 35px; border-radius: 14px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); border: 1px solid #334155; }
        .tabs { display: flex; gap: 15px; margin-bottom: 25px; border-bottom: 2px solid #334155; padding-bottom: 12px; }
        .tab-btn { background: none; border: none; font-size: 16px; font-weight: 600; cursor: pointer; padding: 8px 18px; border-radius: 6px; color: #94a3b8; }
        .tab-btn.active { background: #0284c7; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        label { display: block; margin-top: 15px; font-weight: 600; font-size: 14px; color: #cbd5e1; }
        input { width: 100%; padding: 14px; margin-top: 8px; background: #0f172a; border: 1px solid #475569; border-radius: 8px; color: white; font-size: 15px; box-sizing: border-box; }
        button.submit-btn { background: #0284c7; color: white; border: none; padding: 14px; width: 100%; margin-top: 25px; font-size: 16px; font-weight: bold; border-radius: 8px; cursor: pointer; transition: background 0.2s; }
        button.submit-btn:hover { background: #0369a1; }
        pre { background: #090d16; color: #38bdf8; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 13px; white-space: pre-wrap; border: 1px solid #334155; }
        .history-card { background: #0f172a; border: 1px solid #334155; padding: 15px; border-radius: 8px; margin-bottom: 12px; }
        .badge { display: inline-block; padding: 4px 10px; font-size: 12px; font-weight: bold; border-radius: 4px; background: #0284c7; color: white; }
        .loading { text-align: center; font-weight: bold; color: #38bdf8; margin: 25px 0; display: none; font-size: 16px; }
    </style>
</head>
<body>
    <div class="navbar">
        <h2>🤖 Render Autonomous Security Suite</h2>
        <span>Dockerized Cloud Mode</span>
    </div>
    <div class="container">
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('scanner', event)">Autonomous Scanner</button>
            <button class="tab-btn" onclick="switchTab('history', event)">Scan Intelligence History</button>
        </div>
        
        <div id="scanner" class="tab-content active">
            <form id="autoForm">
                <label for="url">Target URL (AI will auto-extract parameters & handle execution):</label>
                <input type="text" id="url" name="url" placeholder="http://127.0.0.1/vulnerable.php?id=1" required>
                <button type="submit" class="submit-btn">Run Autonomous AI Assessment</button>
            </form>

            <div id="loading" class="loading">🧠 AI is analyzing target structure, executing containerized SQLMap pipeline...</div>
            <div id="result" style="margin-top: 25px;"></div>
        </div>

        <div id="history" class="tab-content">
            <h3>Past Autonomous Scans</h3>
            <div id="historyList">Loading history...</div>
        </div>
    </div>

    <script>
        function switchTab(tabId, event) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.currentTarget.classList.add('active');
            if(tabId === 'history') fetchHistory();
        }

        document.getElementById('autoForm').addEventListener('submit', function(event) {
            event.preventDefault();
            const url = document.getElementById('url').value;
            const resultDiv = document.getElementById('result');
            const loadingDiv = document.getElementById('loading');
            resultDiv.innerHTML = "";
            loadingDiv.style.display = "block";

            fetch('/autonomous-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            })
            .then(res => res.json())
            .then(data => {
                loadingDiv.style.display = "none";
                let html = `<p><strong>Extracted Parameter:</strong> <code>${data.extracted_param}</code></p>`;
                html += `<p><strong>Status:</strong> <span class="badge">${data.message}</span></p>`;
                if (data.sqlmap_output) html += `<h4>Live Execution Logs:</h4><pre>${data.sqlmap_output}</pre>`;
                if (data.groq_analysis) html += `<h4>AI Security Analysis & Remediation:</h4><div style="background:#090d16; padding:15px; border-radius:8px; border:1px solid #334155; margin-top:10px;">${data.groq_analysis}</div>`;
                resultDiv.innerHTML = html;
            })
            .catch(err => {
                loadingDiv.style.display = "none";
                resultDiv.innerHTML = "<p style='color:red;'>Request timed out or encountered an error.</p>";
            });
        });

        function fetchHistory() {
            fetch('/history').then(res => res.json()).then(data => {
                let hDiv = document.getElementById('historyList');
                if(!data || data.length === 0) { hDiv.innerHTML = "<p>No history records found.</p>"; return; }
                let html = "";
                data.forEach(item => {
                    html += `<div class="history-card"><h4>Target: ${item[2]}</h4><small>Time: ${item[1]} | Param: ${item[3]}</small><p><strong>Status:</strong> ${item[4]}</p></div>`;
                });
                hDiv.innerHTML = html;
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/autonomous-scan', methods=['POST'])
def autonomous_scan():
    data = request.json
    raw_url = data.get('url')
    
    if not raw_url:
        return jsonify({'error': 'URL is required'}), 400
        
    parsed_url = urllib.parse.urlparse(raw_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    clean_base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    extracted_param = ""
    if query_params:
        first_key = list(query_params.keys())[0]
        first_val = query_params[first_key][0]
        extracted_param = f"{first_key}={first_val}"
    else:
        extracted_param = "id=1"
        clean_base_url = raw_url

    # TensorFlow prediction validation
    max_length = 100
    tokenizer = Tokenizer(num_words=5000)
    tokenizer.fit_on_texts([extracted_param])
    sequence = tokenizer.texts_to_sequences([extracted_param])
    input_data = pad_sequences(sequence, maxlen=max_length, padding='post')
    
    if model is not None:
        prediction = model.predict(input_data)
        is_vulnerable = float(prediction[0][0]) > 0.5
    else:
        is_vulnerable = True 
        
    sqlmap_output = ""
    groq_analysis = "Groq client not initialized."
    status_msg = "Autonomous Execution Completed"
    
    if is_vulnerable:
        try:
            cmd = [
                'sqlmap', '-u', clean_base_url,
                '--data', extracted_param,
                '--level', '3',
                '--risk', '2',
                '--batch', '--random-agent',
                '--output-dir=/tmp/sqlmap_output'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            sqlmap_output = result.stdout
        except Exception as e:
            sqlmap_output = f"Execution engine error or timeout: {str(e)}"
            status_msg = "Execution Interrupted / Timeout"
            
        if groq_client:
            try:
                completion = groq_client.chat.completions.create(
                    messages=[{"role": "user", "content": f"Autonomous audit on target URL: {clean_base_url} with parameter {extracted_param}. Logs snippet: {sqlmap_output[:1000]}. Provide remediation and secure code patch."}],
                    model="llama3-70b-8192"
                )
                groq_analysis = completion.choices[0].message.content
            except Exception as e:
                groq_analysis = f"AI error: {str(e)}"
    else:
        status_msg = "AI Filter: Low Vulnerability Signature"
        sqlmap_output = "Model evaluation determined target parameter is secure."

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (timestamp, url, extracted_param, status, sqlmap_output, groq_analysis) VALUES (?, ?, ?, ?, ?, ?)",
                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), clean_base_url, extracted_param, status_msg, sqlmap_output, groq_analysis))
        conn.commit()
        conn.close()
    except Exception:
        pass

    return jsonify({
        'extracted_param': extracted_param,
        'message': status_msg,
        'sqlmap_output': sqlmap_output,
        'groq_analysis': groq_analysis
    })

@app.route('/history', methods=['GET'])
def get_history():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, url, extracted_param, status FROM scans ORDER BY id DESC LIMIT 20")
        rows = cursor.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception:
        return jsonify([])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
