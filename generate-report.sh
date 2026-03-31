#!/usr/bin/env bash
set -euo pipefail

# HTML Report Generator for VPS Security Scanner

RESULTS_DIR="$1"
REPORT_FILE="${RESULTS_DIR}/report.html"

if [ ! -f "${RESULTS_DIR}/summary.json" ]; then
  echo "Error: summary.json not found in ${RESULTS_DIR}"
  exit 1
fi

# Read summary
SUMMARY=$(cat "${RESULTS_DIR}/summary.json")
TIMESTAMP=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['timestamp'])")
CRITICAL=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['critical'])")
HIGH=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['high'])")
MEDIUM=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['medium'])")
LOW=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['low'])")
INFO=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['info'])")
TOTAL=$(echo "${SUMMARY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_findings'])")

# Determine overall status
if [ "${CRITICAL}" -gt 0 ]; then
  STATUS="CRITICAL"
  STATUS_COLOR="#dc2626"
  STATUS_ICON="&#x26A0;"
elif [ "${HIGH}" -gt 0 ]; then
  STATUS="AT RISK"
  STATUS_COLOR="#ea580c"
  STATUS_ICON="&#x26A0;"
elif [ "${MEDIUM}" -gt 0 ]; then
  STATUS="FAIR"
  STATUS_COLOR="#ca8a04"
  STATUS_ICON="&#x25CF;"
else
  STATUS="SECURE"
  STATUS_COLOR="#16a34a"
  STATUS_ICON="&#x2713;"
fi

# Collect all findings
ALL_FINDINGS=""
for f in "${RESULTS_DIR}"/*.jsonl; do
  [ -f "$f" ] || continue
  ALL_FINDINGS="${ALL_FINDINGS}$(cat "$f")
"
done

# Generate findings HTML via Python for proper JSON handling
FINDINGS_HTML=$(echo "${ALL_FINDINGS}" | python3 -c "
import sys, json, html

severity_colors = {
    'CRITICAL': '#dc2626',
    'HIGH': '#ea580c',
    'MEDIUM': '#ca8a04',
    'LOW': '#2563eb',
    'INFO': '#6b7280'
}

severity_icons = {
    'CRITICAL': '&#x1F534;',
    'HIGH': '&#x1F7E0;',
    'MEDIUM': '&#x1F7E1;',
    'LOW': '&#x1F535;',
    'INFO': '&#x26AA;'
}

severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

findings = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        findings.append(json.loads(line))
    except:
        pass

# Sort by severity
findings.sort(key=lambda f: severity_order.get(f.get('severity', 'INFO'), 5))

if not findings:
    print('<p style=\"color:#16a34a;font-size:1.2em;\">No findings. VPS is clean!</p>')
    sys.exit(0)

for f in findings:
    sev = f.get('severity', 'INFO')
    color = severity_colors.get(sev, '#6b7280')
    icon = severity_icons.get(sev, '')
    cat = html.escape(f.get('category', ''))
    title = html.escape(f.get('title', ''))
    detail = html.escape(f.get('detail', '')).replace('\\\\n', '<br>')

    print(f'''<div class=\"finding\" style=\"border-left:4px solid {color};\">
  <div class=\"finding-header\">
    <span class=\"severity\" style=\"background:{color};\">{sev}</span>
    <span class=\"category\">{cat}</span>
    <span class=\"title\">{title}</span>
  </div>
  <div class=\"finding-detail\">{detail}</div>
</div>''')
")

cat > "${REPORT_FILE}" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VPS Security Report - ${TIMESTAMP}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;
      background: #0a0a0a;
      color: #e5e5e5;
      padding: 2rem;
      line-height: 1.6;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    h1 {
      font-size: 1.5rem;
      color: #fff;
      margin-bottom: 0.25rem;
    }
    .subtitle {
      color: #737373;
      font-size: 0.85rem;
      margin-bottom: 2rem;
    }
    .status-banner {
      background: #171717;
      border: 1px solid #262626;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      gap: 1.5rem;
    }
    .status-icon {
      font-size: 2.5rem;
      line-height: 1;
    }
    .status-label {
      font-size: 1.3rem;
      font-weight: bold;
    }
    .counters {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 0.75rem;
      margin-bottom: 2rem;
    }
    .counter {
      background: #171717;
      border: 1px solid #262626;
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }
    .counter .count {
      font-size: 1.8rem;
      font-weight: bold;
      display: block;
    }
    .counter .label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #737373;
    }
    .findings-section {
      background: #171717;
      border: 1px solid #262626;
      border-radius: 8px;
      padding: 1.5rem;
    }
    .findings-title {
      font-size: 1rem;
      color: #a3a3a3;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid #262626;
    }
    .finding {
      background: #0a0a0a;
      border-radius: 6px;
      padding: 1rem;
      margin-bottom: 0.75rem;
    }
    .finding-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
      flex-wrap: wrap;
    }
    .severity {
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.65rem;
      font-weight: bold;
      color: #fff;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .category {
      color: #737373;
      font-size: 0.75rem;
      text-transform: uppercase;
    }
    .title {
      color: #e5e5e5;
      font-size: 0.85rem;
      font-weight: 600;
    }
    .finding-detail {
      color: #a3a3a3;
      font-size: 0.8rem;
      padding-left: 0.5rem;
    }
    .footer {
      margin-top: 2rem;
      text-align: center;
      color: #525252;
      font-size: 0.75rem;
    }
    @media (max-width: 640px) {
      body { padding: 1rem; }
      .counters { grid-template-columns: repeat(3, 1fr); }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>VPS Security Report</h1>
    <p class="subtitle">Scan: ${TIMESTAMP} // $(hostname)</p>

    <div class="status-banner">
      <span class="status-icon">${STATUS_ICON}</span>
      <div>
        <div class="status-label" style="color:${STATUS_COLOR};">${STATUS}</div>
        <div style="color:#737373;font-size:0.85rem;">${TOTAL} finding(s) across all checks</div>
      </div>
    </div>

    <div class="counters">
      <div class="counter">
        <span class="count" style="color:#dc2626;">${CRITICAL}</span>
        <span class="label">Critical</span>
      </div>
      <div class="counter">
        <span class="count" style="color:#ea580c;">${HIGH}</span>
        <span class="label">High</span>
      </div>
      <div class="counter">
        <span class="count" style="color:#ca8a04;">${MEDIUM}</span>
        <span class="label">Medium</span>
      </div>
      <div class="counter">
        <span class="count" style="color:#2563eb;">${LOW}</span>
        <span class="label">Low</span>
      </div>
      <div class="counter">
        <span class="count" style="color:#6b7280;">${INFO}</span>
        <span class="label">Info</span>
      </div>
    </div>

    <div class="findings-section">
      <h2 class="findings-title">Findings</h2>
      ${FINDINGS_HTML}
    </div>

    <p class="footer">vps-security-scanner // auto-generated report</p>
  </div>
</body>
</html>
HTMLEOF

echo "Report generated: ${REPORT_FILE}"
