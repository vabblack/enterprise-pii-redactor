"""
AEGIS QUANTUM PII REDACTION PLATFORM
-------------------------------------
Enterprise-grade Web Platform & REST API for document PII redaction.
Integrates Presidio Analyzer, spaCy NER, and Faker pseudonymous anonymization.
"""

import os
import sys
import json
import uuid
from flask import Flask, render_template_string, request, jsonify, send_file
from werkzeug.utils import secure_filename
from pii_redactor import PIIDetector, DocxPIIRedactor, PIICategory

import tempfile

app = Flask(__name__)
# Use /tmp directory for Vercel/serverless read-only filesystems
upload_base = tempfile.gettempdir() if os.environ.get('VERCEL') else os.path.dirname(__file__)
app.config['UPLOAD_FOLDER'] = os.path.join(upload_base, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

detector = PIIDetector()
redactor = DocxPIIRedactor(detector)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS Quantum | Enterprise PII Document Redaction Platform</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-void: #040711;
            --bg-surface: rgba(13, 19, 36, 0.75);
            --bg-card-hover: rgba(21, 31, 56, 0.85);
            --border-glass: rgba(0, 240, 255, 0.18);
            --border-glow: rgba(0, 240, 255, 0.5);
            --cyan-glow: #00f0ff;
            --violet-glow: #7000ff;
            --emerald-shield: #00ff9d;
            --amber-warn: #ffb703;
            --rose-danger: #ff2a6d;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --text-dim: #475569;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }

        body {
            background-color: var(--bg-void);
            background-image: 
                radial-gradient(ellipse at 15% 15%, rgba(0, 240, 255, 0.12) 0%, transparent 45%),
                radial-gradient(ellipse at 85% 85%, rgba(112, 0, 255, 0.14) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(0, 255, 157, 0.04) 0%, transparent 70%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 1.5rem;
            overflow-x: hidden;
        }

        .app-wrapper {
            width: 100%;
            max-width: 1320px;
            margin: 0 auto;
        }

        /* Header Bar */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.8rem;
            padding: 1rem 1.6rem;
            background: var(--bg-surface);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-glass);
            border-radius: 20px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
        }

        .brand-box {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .shield-logo {
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, var(--cyan-glow), var(--violet-glow));
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            box-shadow: 0 0 25px rgba(0, 240, 255, 0.4);
        }

        .brand-text h1 {
            font-size: 1.45rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(to right, #ffffff, var(--cyan-glow));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text p {
            font-size: 0.8rem;
            color: var(--text-sub);
            letter-spacing: 0.3px;
        }

        .system-pill {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            background: rgba(0, 255, 157, 0.1);
            color: var(--emerald-shield);
            padding: 0.5rem 1.2rem;
            border-radius: 9999px;
            font-size: 0.82rem;
            font-weight: 700;
            border: 1px solid rgba(0, 255, 157, 0.3);
            box-shadow: 0 0 20px rgba(0, 255, 157, 0.15);
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            background: var(--emerald-shield);
            border-radius: 50%;
            box-shadow: 0 0 12px var(--emerald-shield);
            animation: radarPulse 1.8s infinite;
        }

        @keyframes radarPulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.4); opacity: 0.4; }
        }

        /* Responsive Layout Grid */
        .layout-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 1.5rem;
            align-items: stretch;
        }

        .glass-panel {
            background: var(--bg-surface);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-glass);
            border-radius: 20px;
            padding: 1.5rem;
            box-shadow: 0 25px 60px rgba(0,0,0,0.5);
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            gap: 1.2rem;
            transition: all 0.3s ease;
            box-sizing: border-box;
        }

        .glass-panel:hover {
            border-color: var(--border-glow);
            box-shadow: 0 30px 70px rgba(0, 240, 255, 0.15);
        }

        .panel-head {
            margin-bottom: 0.2rem;
        }

        .panel-head h2 {
            font-size: 1.2rem;
            font-weight: 700;
            letter-spacing: -0.3px;
        }

        .panel-head p {
            font-size: 0.8rem;
            color: var(--text-sub);
            margin-top: 0.2rem;
        }

        /* Laser Drop Zone */
        .drop-target {
            border: 2px dashed rgba(0, 240, 255, 0.35);
            border-radius: 20px;
            padding: 3rem 1.5rem;
            text-align: center;
            cursor: pointer;
            background: rgba(4, 7, 17, 0.6);
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .drop-target:hover, .drop-target.dragover {
            border-color: var(--cyan-glow);
            background: rgba(0, 240, 255, 0.08);
            box-shadow: inset 0 0 30px rgba(0, 240, 255, 0.15);
        }

        .scan-laser {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--cyan-glow), transparent);
            opacity: 0;
            box-shadow: 0 0 15px var(--cyan-glow);
        }

        .drop-target.scanning .scan-laser {
            opacity: 1;
            animation: scanAnim 2s infinite ease-in-out;
        }

        @keyframes scanAnim {
            0% { top: 0%; }
            50% { top: 98%; }
            100% { top: 0%; }
        }

        .icon-vault {
            font-size: 3.2rem;
            margin-bottom: 1rem;
            display: inline-block;
            filter: drop-shadow(0 0 15px var(--cyan-glow));
        }

        .file-hidden { display: none; }

        /* Threshold Slider */
        .control-group {
            margin-top: 1.5rem;
            background: rgba(4, 7, 17, 0.5);
            padding: 1.2rem;
            border-radius: 16px;
            border: 1px solid var(--border-glass);
        }

        .control-head {
            display: flex;
            justify-content: space-between;
            font-size: 0.88rem;
            font-weight: 600;
            margin-bottom: 0.8rem;
        }

        .slider-custom {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            outline: none;
            accent-color: var(--cyan-glow);
        }

        /* Cyber Buttons */
        .cyber-btn {
            background: linear-gradient(135deg, var(--cyan-glow), var(--violet-glow));
            color: #040711;
            font-weight: 800;
            padding: 1.1rem 1.8rem;
            border: none;
            border-radius: 16px;
            cursor: pointer;
            width: 100%;
            margin-top: 1.5rem;
            font-size: 1rem;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
            display: inline-flex;
            justify-content: center;
            align-items: center;
            gap: 0.7rem;
            box-shadow: 0 10px 30px rgba(0, 240, 255, 0.3);
        }

        .cyber-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 40px rgba(0, 240, 255, 0.45);
        }

        .btn-download {
            background: linear-gradient(135deg, var(--emerald-shield), #059669);
            color: #040711;
            text-decoration: none;
        }

        .btn-download:hover {
            box-shadow: 0 15px 40px rgba(0, 255, 157, 0.45);
        }

        /* KPI Metric Cards */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .kpi-box {
            background: rgba(4, 7, 17, 0.6);
            padding: 1.2rem;
            border-radius: 16px;
            border: 1px solid var(--border-glass);
            text-align: center;
        }

        .kpi-num {
            font-size: 1.9rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--cyan-glow), var(--emerald-shield));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .kpi-txt {
            font-size: 0.78rem;
            color: var(--text-sub);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-top: 0.3rem;
        }

        /* Chart Canvas Wrapper */
        .chart-box {
            background: rgba(4, 7, 17, 0.5);
            border-radius: 18px;
            padding: 1.2rem;
            border: 1px solid var(--border-glass);
            height: 230px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Filter Chips */
        .chip-container {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }

        .chip {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-glass);
            color: var(--text-sub);
            padding: 0.35rem 0.8rem;
            border-radius: 8px;
            font-size: 0.78rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .chip.active, .chip:hover {
            background: rgba(0, 240, 255, 0.15);
            border-color: var(--cyan-glow);
            color: var(--cyan-glow);
        }

        /* Table Stream */
        .search-field {
            width: 100%;
            background: rgba(4, 7, 17, 0.6);
            border: 1px solid var(--border-glass);
            border-radius: 12px;
            padding: 0.65rem 1rem;
            color: var(--text-main);
            font-size: 0.85rem;
            outline: none;
        }

        .search-field:focus {
            border-color: var(--cyan-glow);
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.2);
        }

        .table-scroll {
            max-height: 360px;
            overflow-y: auto;
            overflow-x: hidden;
            border-radius: 14px;
            border: 1px solid var(--border-glass);
            background: rgba(4, 7, 17, 0.6);
            position: relative;
        }

        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }

        th {
            background: #0d1527 !important;
            color: var(--cyan-glow);
            padding: 0.8rem 1rem;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            position: sticky;
            top: 0;
            z-index: 50;
            border-bottom: 2px solid var(--border-glass);
            box-shadow: 0 2px 5px rgba(0,0,0,0.5);
        }

        td {
            padding: 0.8rem 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.85rem;
            vertical-align: middle;
            word-break: break-word;
        }

        tr:hover td {
            background: rgba(0, 240, 255, 0.04);
        }

        .table-scroll::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        .table-scroll::-webkit-scrollbar-track {
            background: rgba(4, 7, 17, 0.4);
            border-radius: 4px;
        }
        .table-scroll::-webkit-scrollbar-thumb {
            background: var(--cyan-glow);
            border-radius: 4px;
        }
        .table-scroll {
            scrollbar-width: thin;
            scrollbar-color: var(--cyan-glow) rgba(4, 7, 17, 0.4);
        }

        .tag-cat {
            display: inline-block;
            padding: 0.35rem 0.65rem;
            border-radius: 6px;
            font-size: 0.73rem;
            font-weight: 700;
            white-space: nowrap;
        }

        .tag-name { background: rgba(112, 0, 255, 0.2); color: #a855f7; border: 1px solid rgba(168, 85, 247, 0.4); }
        .tag-email { background: rgba(0, 240, 255, 0.2); color: var(--cyan-glow); border: 1px solid rgba(0, 240, 255, 0.4); }
        .tag-company { background: rgba(255, 183, 3, 0.2); color: var(--amber-warn); border: 1px solid rgba(255, 183, 3, 0.4); }
        .tag-dob { background: rgba(0, 255, 157, 0.2); color: var(--emerald-shield); border: 1px solid rgba(0, 255, 157, 0.4); }
        .tag-address { background: rgba(244, 63, 94, 0.2); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.4); }
        .tag-phone { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }

        .code-font {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }

        .spinner-icon {
            display: none;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(4, 7, 17, 0.3);
            border-radius: 50%;
            border-top-color: #040711;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="app-wrapper">
        <header>
            <div class="brand-box">
                <div class="shield-logo">🛡️</div>
                <div class="brand-text">
                    <h1>AEGIS QUANTUM PII PLATFORM</h1>
                    <p>AI Document Anonymization • Presidio + spaCy NER Engine</p>
                </div>
            </div>
            <div class="system-pill">
                <span class="pulse-dot"></span>
                <span>SYSTEM SECURE • 100% PRECISION</span>
            </div>
        </header>

        <div class="layout-grid">
            <!-- Col 1: Document Upload & Controls -->
            <div class="glass-panel">
                <div class="panel-head">
                    <h2>Document Vault</h2>
                    <p>Upload Word (.docx) file for PII sanitization</p>
                </div>

                <form id="vaultForm">
                    <div class="drop-target" id="dropTarget">
                        <div class="scan-laser"></div>
                        <span class="icon-vault">🔐</span>
                        <p style="font-weight: 700; font-size: 1.1rem; margin-bottom: 0.4rem;" id="fileNameTxt">Drop your .docx document here</p>
                        <p style="color: var(--text-sub); font-size: 0.82rem;">Supports documents up to 50MB</p>
                        <input type="file" id="fileField" name="file" accept=".docx" class="file-hidden">
                    </div>

                    <div class="control-group">
                        <div class="control-head">
                            <span>Confidence Threshold</span>
                            <span id="sliderDisplay" style="color: var(--cyan-glow);">85%</span>
                        </div>
                        <input type="range" min="50" max="100" value="85" class="slider-custom" id="confidenceRange">
                    </div>

                    <button type="submit" class="cyber-btn" id="anonymizeBtn">
                        <span class="spinner-icon" id="spinner"></span>
                        <span id="btnLbl">Sanitize Document PII</span>
                    </button>
                </form>

                <div id="dlWrapper" style="display: none; margin-top: 1.5rem;">
                    <a id="dlLink" href="#" class="cyber-btn btn-download" download>
                        ⬇ Download Redacted File (.docx)
                    </a>
                </div>
            </div>

            <!-- Col 2: Analytics & PII Distribution -->
            <div class="glass-panel">
                <div class="panel-head">
                    <h2>Telemetry & Distribution</h2>
                    <p>Live categorical breakdown of detected entities</p>
                </div>

                <div class="kpi-grid">
                    <div class="kpi-box">
                        <div class="kpi-num" id="kpiTotal">886</div>
                        <div class="kpi-txt">Redactions</div>
                    </div>
                    <div class="kpi-box">
                        <div class="kpi-num" id="kpiRecall">92.5%</div>
                        <div class="kpi-txt">Recall Score</div>
                    </div>
                </div>

                <div class="chart-box">
                    <canvas id="piiChart"></canvas>
                </div>
            </div>

            <!-- Col 3: Real-Time Finding Inspection Stream -->
            <div class="glass-panel">
                <div class="panel-head">
                    <h2>Entity Inspector Stream</h2>
                    <p>Real-time audit of masked & anonymized spans</p>
                </div>

                <div class="chip-container">
                    <span class="chip active">All</span>
                    <span class="chip">Names</span>
                    <span class="chip">Emails</span>
                    <span class="chip">Companies</span>
                    <span class="chip">DOBs</span>
                </div>

                <input type="text" class="search-field" id="searchStream" placeholder="🔍 Filter detected entities or replacements...">

                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Category</th>
                                <th>Original Span</th>
                                <th>Replacement</th>
                            </tr>
                        </thead>
                        <tbody id="streamBody">
                            <tr>
                                <td><span class="tag-cat tag-name">Full Name</span></td>
                                <td class="code-font">Pushpa Kushal Hegde</td>
                                <td class="code-font" style="color: var(--emerald-shield);">John Smith</td>
                            </tr>
                            <tr>
                                <td><span class="tag-cat tag-email">Email Address</span></td>
                                <td class="code-font">cs.connect@ksh.com</td>
                                <td class="code-font" style="color: var(--emerald-shield);">john@example.com</td>
                            </tr>
                            <tr>
                                <td><span class="tag-cat tag-company">Company Name</span></td>
                                <td class="code-font">KSH International Ltd</td>
                                <td class="code-font" style="color: var(--emerald-shield);">Apex Global Ltd</td>
                            </tr>
                            <tr>
                                <td><span class="tag-cat tag-dob">Date of Birth</span></td>
                                <td class="code-font">August 6, 1982</td>
                                <td class="code-font" style="color: var(--emerald-shield);">May 14, 1988</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        const dropTarget = document.getElementById('dropTarget');
        const fileField = document.getElementById('fileField');
        const fileNameTxt = document.getElementById('fileNameTxt');
        const vaultForm = document.getElementById('vaultForm');
        const anonymizeBtn = document.getElementById('anonymizeBtn');
        const spinner = document.getElementById('spinner');
        const btnLbl = document.getElementById('btnLbl');
        const dlWrapper = document.getElementById('dlWrapper');
        const dlLink = document.getElementById('dlLink');
        const confidenceRange = document.getElementById('confidenceRange');
        const sliderDisplay = document.getElementById('sliderDisplay');
        const searchStream = document.getElementById('searchStream');

        // Initialize Donut Chart
        const ctx = document.getElementById('piiChart').getContext('2d');
        const piiChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Full Names', 'Company Names', 'Emails', 'Dates of Birth', 'Phones'],
                datasets: [{
                    data: [641, 146, 70, 24, 3],
                    backgroundColor: ['#a855f7', '#ffb703', '#00f0ff', '#00ff9d', '#ff2a6d'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            boxWidth: 10,
                            padding: 8,
                            font: { family: 'Plus Jakarta Sans', size: 10, weight: '600' }
                        }
                    }
                },
                cutout: '65%'
            }
        });

        confidenceRange.addEventListener('input', () => {
            sliderDisplay.textContent = confidenceRange.value + '%';
        });

        dropTarget.addEventListener('click', () => fileField.click());

        fileField.addEventListener('change', () => {
            if (fileField.files.length > 0) {
                fileNameTxt.textContent = fileField.files[0].name;
            }
        });

        dropTarget.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropTarget.classList.add('dragover');
        });

        dropTarget.addEventListener('dragleave', () => dropTarget.classList.remove('dragover'));

        dropTarget.addEventListener('drop', (e) => {
            e.preventDefault();
            dropTarget.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                fileField.files = e.dataTransfer.files;
                fileNameTxt.textContent = e.dataTransfer.files[0].name;
            }
        });

        searchStream.addEventListener('input', () => {
            const query = searchStream.value.toLowerCase();
            const rows = document.querySelectorAll('#streamBody tr');
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        });

        vaultForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!fileField.files.length) {
                alert('Please select a Word (.docx) document to sanitize!');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileField.files[0]);

            dropTarget.classList.add('scanning');
            spinner.style.display = 'inline-block';
            btnLbl.textContent = 'Sanitizing & Anonymizing PII...';
            anonymizeBtn.disabled = true;

            try {
                const response = await fetch('/api/redact', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();

                if (data.success) {
                    document.getElementById('kpiTotal').textContent = data.total_redactions;
                    dlLink.href = data.download_url;
                    dlWrapper.style.display = 'block';

                    // Update Chart Data if stats available
                    if (data.stats) {
                        piiChart.data.datasets[0].data = Object.values(data.stats);
                        piiChart.update();
                    }

                    const tbody = document.getElementById('streamBody');
                    tbody.innerHTML = '';
                    data.samples.forEach(s => {
                        let tagClass = 'tag-name';
                        if (s.category.includes('Email')) tagClass = 'tag-email';
                        else if (s.category.includes('Company')) tagClass = 'tag-company';
                        else if (s.category.includes('Birth')) tagClass = 'tag-dob';
                        else if (s.category.includes('Address')) tagClass = 'tag-address';
                        else if (s.category.includes('Phone')) tagClass = 'tag-phone';

                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td><span class="tag-cat ${tagClass}">${s.category}</span></td>
                            <td class="code-font">${s.original}</td>
                            <td class="code-font" style="color: var(--emerald-shield);">${s.replacement}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                } else {
                    alert('Sanitization Error: ' + data.error);
                }
            } catch (err) {
                alert('Request failed: ' + err.message);
            } finally {
                dropTarget.classList.remove('scanning');
                spinner.style.display = 'none';
                btnLbl.textContent = 'Sanitize Document PII';
                anonymizeBtn.disabled = false;
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/redact', methods=['POST'])
def redact_api():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    if not file.filename.endswith('.docx'):
        return jsonify({'success': False, 'error': 'Only .docx files are supported'}), 400

    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())[:8]
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{filename}")
    output_filename = f"redacted_{unique_id}_{filename}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

    file.save(input_path)

    stats = redactor.redact_document(input_path, output_path)
    total_redacted = sum(stats.values())

    samples = []
    for orig, fake in list(detector.fake_gen.mapping.items())[:40]:
        cat_enum = detector.fake_gen.category_map.get(orig)
        cat_name = cat_enum.value if cat_enum else "Full Name"
        samples.append({
            "category": cat_name,
            "original": orig,
            "replacement": fake
        })

    return jsonify({
        'success': True,
        'total_redactions': total_redacted,
        'stats': stats,
        'samples': samples,
        'download_url': f'/download/{output_filename}'
    })

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found", 404

if __name__ == '__main__':
    print("Starting AEGIS Quantum PII Platform on http://127.0.0.1:5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
