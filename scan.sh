#!/usr/bin/env bash
set -euo pipefail

# VPS Security Scanner
# Runs comprehensive security audits across all projects and VPS config
# Output: JSON results consumed by the report generator

SCANNER_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORTS_DIR="${SCANNER_DIR}/reports"
TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
RESULTS_DIR="${REPORTS_DIR}/${TIMESTAMP}"
PROJECTS_ROOT="/opt"
LOG_FILE="${RESULTS_DIR}/scan.log"

# Severity counters
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
INFO=0

mkdir -p "${RESULTS_DIR}"

log() {
  local level="$1"; shift
  echo "[$(date '+%H:%M:%S')] [${level}] $*" | tee -a "${LOG_FILE}"
}

write_finding() {
  local file="$1" severity="$2" category="$3" title="$4" detail="$5"
  # Increment counters
  case "${severity}" in
    CRITICAL) CRITICAL=$((CRITICAL + 1)) ;;
    HIGH)     HIGH=$((HIGH + 1)) ;;
    MEDIUM)   MEDIUM=$((MEDIUM + 1)) ;;
    LOW)      LOW=$((LOW + 1)) ;;
    INFO)     INFO=$((INFO + 1)) ;;
  esac
  # Escape JSON strings
  detail_escaped=$(echo "$detail" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().strip()))')
  title_escaped=$(echo "$title" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().strip()))')
  cat >> "${file}" <<JSONL
{"severity":"${severity}","category":"${category}","title":${title_escaped},"detail":${detail_escaped}}
JSONL
}

# ============================================================
# 1. SECRET SCANNING (gitleaks)
# ============================================================
scan_secrets() {
  log "INFO" "=== Secret Scanning ==="
  local findings_file="${RESULTS_DIR}/secrets.jsonl"
  : > "${findings_file}"

  for project_dir in "${PROJECTS_ROOT}"/*/; do
    local name
    name=$(basename "${project_dir}")
    [ ! -d "${project_dir}/.git" ] && continue

    log "INFO" "Scanning secrets in ${name}..."
    local gl_out="${RESULTS_DIR}/gitleaks_${name}.json"
    if gitleaks detect --source="${project_dir}" --report-format=json --report-path="${gl_out}" --no-banner 2>/dev/null; then
      log "INFO" "${name}: no secrets found"
    else
      if [ -f "${gl_out}" ] && [ -s "${gl_out}" ]; then
        local count
        count=$(python3 -c "import json; d=json.load(open('${gl_out}')); print(len(d))" 2>/dev/null || echo "?")
        log "WARN" "${name}: ${count} potential secret(s) found"
        write_finding "${findings_file}" "CRITICAL" "secrets" \
          "Secrets leaked in ${name}" \
          "${count} potential secret(s) detected by gitleaks. Run: gitleaks detect --source=${project_dir} -v"
      fi
    fi
  done

  # Check for .env files committed to git
  for project_dir in "${PROJECTS_ROOT}"/*/; do
    local name
    name=$(basename "${project_dir}")
    [ ! -d "${project_dir}/.git" ] && continue
    if git -C "${project_dir}" ls-files --error-unmatch .env &>/dev/null; then
      write_finding "${findings_file}" "HIGH" "secrets" \
        ".env tracked in git: ${name}" \
        "The .env file is committed to git in ${project_dir}. Add it to .gitignore and remove from tracking."
    fi
  done
}

# ============================================================
# 2. DEPENDENCY VULNERABILITIES
# ============================================================
scan_dependencies() {
  log "INFO" "=== Dependency Scanning ==="
  local findings_file="${RESULTS_DIR}/dependencies.jsonl"
  : > "${findings_file}"

  for project_dir in "${PROJECTS_ROOT}"/*/; do
    local name
    name=$(basename "${project_dir}")

    # Node.js projects
    if [ -f "${project_dir}/package.json" ] && [ -f "${project_dir}/package-lock.json" ]; then
      log "INFO" "npm audit: ${name}..."
      local audit_out
      audit_out=$(cd "${project_dir}" && npm audit --json 2>/dev/null || true)
      local vuln_count
      vuln_count=$(echo "${audit_out}" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    v=d.get('metadata',{}).get('vulnerabilities',{})
    print(v.get('critical',0) + v.get('high',0) + v.get('moderate',0))
except: print(0)
" 2>/dev/null)
      if [ "${vuln_count}" -gt 0 ] 2>/dev/null; then
        local summary
        summary=$(echo "${audit_out}" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    v=d.get('metadata',{}).get('vulnerabilities',{})
    print(f\"critical={v.get('critical',0)} high={v.get('high',0)} moderate={v.get('moderate',0)} low={v.get('low',0)}\")
except: print('error parsing')
" 2>/dev/null)
        write_finding "${findings_file}" "HIGH" "dependencies" \
          "npm vulnerabilities in ${name}" \
          "${vuln_count} vulnerabilities found. Breakdown: ${summary}. Run: cd ${project_dir} && npm audit"
      else
        log "INFO" "${name}: npm audit clean"
      fi
    fi

    # Python projects
    if [ -f "${project_dir}/requirements.txt" ]; then
      log "INFO" "pip-audit: ${name}..."
      local pa_out
      pa_out=$(pip-audit -r "${project_dir}/requirements.txt" --format=json 2>/dev/null || true)
      local py_vulns
      py_vulns=$(echo "${pa_out}" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    deps=d.get('dependencies',[])
    vulns=[dep for dep in deps if dep.get('vulns')]
    print(len(vulns))
except: print(0)
" 2>/dev/null)
      if [ "${py_vulns}" -gt 0 ] 2>/dev/null; then
        write_finding "${findings_file}" "HIGH" "dependencies" \
          "Python vulnerabilities in ${name}" \
          "${py_vulns} vulnerable package(s). Run: pip-audit -r ${project_dir}/requirements.txt"
      else
        log "INFO" "${name}: pip-audit clean"
      fi
    fi
  done
}

# ============================================================
# 3. VPS HARDENING
# ============================================================
scan_vps_hardening() {
  log "INFO" "=== VPS Hardening Check ==="
  local findings_file="${RESULTS_DIR}/hardening.jsonl"
  : > "${findings_file}"

  # SSH config
  local sshd_config="/etc/ssh/sshd_config"
  if [ -f "${sshd_config}" ]; then
    if grep -qiE '^\s*PermitRootLogin\s+yes' "${sshd_config}" 2>/dev/null; then
      write_finding "${findings_file}" "CRITICAL" "ssh" \
        "Root login enabled via SSH" \
        "PermitRootLogin is set to yes in ${sshd_config}. Disable it and use key-based auth with a non-root user."
    fi
    if grep -qiE '^\s*PasswordAuthentication\s+yes' "${sshd_config}" 2>/dev/null; then
      write_finding "${findings_file}" "HIGH" "ssh" \
        "Password authentication enabled" \
        "PasswordAuthentication is yes in ${sshd_config}. Use key-based auth only."
    fi
    if ! grep -qiE '^\s*MaxAuthTries\s+[1-5]$' "${sshd_config}" 2>/dev/null; then
      write_finding "${findings_file}" "MEDIUM" "ssh" \
        "MaxAuthTries not restricted" \
        "Set MaxAuthTries to 3-5 in ${sshd_config} to limit brute-force attempts."
    fi
  fi

  # Firewall
  if ! ufw status | grep -q "Status: active" 2>/dev/null; then
    write_finding "${findings_file}" "CRITICAL" "firewall" \
      "UFW firewall is not active" \
      "Enable UFW immediately: ufw enable"
  fi

  # Check for unexpected open ports (not 22, 80, 443, 2222)
  local unexpected_ports
  unexpected_ports=$(ss -tlnp | grep -E '0\.0\.0\.0:|:::' | grep -v '127\.' | awk '{print $4}' | grep -oE '[0-9]+$' | sort -u | while read -r port; do
    case "${port}" in
      22|80|443|2222|53) ;; # expected
      *) echo "${port}" ;;
    esac
  done)
  if [ -n "${unexpected_ports}" ]; then
    write_finding "${findings_file}" "MEDIUM" "network" \
      "Unexpected ports open to public" \
      "These ports are listening on 0.0.0.0 (public): $(echo ${unexpected_ports} | tr '\n' ', '). Verify each is intentional and firewall-protected."
  fi

  # fail2ban status
  if ! systemctl is-active fail2ban &>/dev/null; then
    write_finding "${findings_file}" "HIGH" "intrusion" \
      "fail2ban is not running" \
      "Start fail2ban: systemctl start fail2ban && systemctl enable fail2ban"
  else
    local banned
    banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")
    write_finding "${findings_file}" "INFO" "intrusion" \
      "fail2ban active" \
      "fail2ban is running. Currently banned IPs (sshd): ${banned}"
  fi

  # Unattended upgrades
  if ! dpkg -l | grep -q unattended-upgrades 2>/dev/null; then
    write_finding "${findings_file}" "MEDIUM" "updates" \
      "Unattended upgrades not installed" \
      "Install unattended-upgrades for automatic security patches: apt install unattended-upgrades"
  fi

  # Check for world-writable files in /opt
  local world_writable
  world_writable=$(find /opt -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -20)
  if [ -n "${world_writable}" ]; then
    write_finding "${findings_file}" "MEDIUM" "permissions" \
      "World-writable files in /opt" \
      "Found world-writable files:\n$(echo "${world_writable}" | head -10)"
  fi

  # Kernel updates
  local running_kernel installed_kernel
  running_kernel=$(uname -r)
  installed_kernel=$(dpkg -l | grep 'linux-image-[0-9]' | sort -V | tail -1 | awk '{print $3}' | cut -d. -f1-4 2>/dev/null || echo "unknown")
  write_finding "${findings_file}" "INFO" "system" \
    "Kernel info" \
    "Running: ${running_kernel}. Latest installed package version: ${installed_kernel}. Reboot if they differ."
}

# ============================================================
# 4. NGINX / TLS AUDIT
# ============================================================
scan_nginx() {
  log "INFO" "=== Nginx/TLS Audit ==="
  local findings_file="${RESULTS_DIR}/nginx.jsonl"
  : > "${findings_file}"

  # Test nginx config
  if ! nginx -t 2>/dev/null; then
    write_finding "${findings_file}" "HIGH" "nginx" \
      "Nginx config test fails" \
      "nginx -t returns errors. Fix config before next reload."
  fi

  # Check for missing security headers in main config
  local nginx_conf="/etc/nginx"
  if ! grep -rq "X-Frame-Options" "${nginx_conf}" 2>/dev/null; then
    write_finding "${findings_file}" "MEDIUM" "headers" \
      "Missing X-Frame-Options header" \
      "Add 'add_header X-Frame-Options SAMEORIGIN;' to nginx config to prevent clickjacking."
  fi
  if ! grep -rq "X-Content-Type-Options" "${nginx_conf}" 2>/dev/null; then
    write_finding "${findings_file}" "MEDIUM" "headers" \
      "Missing X-Content-Type-Options header" \
      "Add 'add_header X-Content-Type-Options nosniff;' to prevent MIME-type sniffing."
  fi
  if ! grep -rq "Content-Security-Policy" "${nginx_conf}" 2>/dev/null; then
    write_finding "${findings_file}" "MEDIUM" "headers" \
      "Missing Content-Security-Policy header" \
      "Add a Content-Security-Policy header to prevent XSS and data injection."
  fi
  if ! grep -rq "Strict-Transport-Security" "${nginx_conf}" 2>/dev/null; then
    write_finding "${findings_file}" "HIGH" "headers" \
      "Missing HSTS header" \
      "Add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' for HSTS."
  fi

  # Check TLS config
  if grep -rqE 'ssl_protocols.*TLSv1[^.]|ssl_protocols.*TLSv1\.0|ssl_protocols.*SSLv' "${nginx_conf}" 2>/dev/null; then
    write_finding "${findings_file}" "HIGH" "tls" \
      "Deprecated TLS protocols enabled" \
      "Disable TLSv1.0 and TLSv1.1. Use only TLSv1.2 and TLSv1.3."
  fi

  # Check SSL certificate expiry
  for cert in /etc/letsencrypt/live/*/fullchain.pem; do
    [ -f "${cert}" ] || continue
    local domain days_left
    domain=$(basename "$(dirname "${cert}")")
    days_left=$(( ( $(date -d "$(openssl x509 -enddate -noout -in "${cert}" | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
    if [ "${days_left}" -lt 7 ]; then
      write_finding "${findings_file}" "CRITICAL" "tls" \
        "SSL cert expiring soon: ${domain}" \
        "Certificate expires in ${days_left} day(s). Run: certbot renew"
    elif [ "${days_left}" -lt 30 ]; then
      write_finding "${findings_file}" "MEDIUM" "tls" \
        "SSL cert renewal due: ${domain}" \
        "Certificate expires in ${days_left} day(s). Verify certbot auto-renewal is working."
    else
      write_finding "${findings_file}" "INFO" "tls" \
        "SSL cert OK: ${domain}" \
        "Certificate valid for ${days_left} more day(s)."
    fi
  done
}

# ============================================================
# 5. DOCKER SECURITY
# ============================================================
scan_docker() {
  log "INFO" "=== Docker Security ==="
  local findings_file="${RESULTS_DIR}/docker.jsonl"
  : > "${findings_file}"

  if ! command -v docker &>/dev/null; then
    log "INFO" "Docker not installed, skipping"
    return
  fi

  # Check containers running as root
  docker ps --format '{{.Names}}' | while read -r container; do
    local user
    user=$(docker inspect --format '{{.Config.User}}' "${container}" 2>/dev/null)
    if [ -z "${user}" ] || [ "${user}" = "root" ] || [ "${user}" = "0" ]; then
      write_finding "${findings_file}" "MEDIUM" "docker" \
        "Container running as root: ${container}" \
        "Container '${container}' runs as root. Set a non-root USER in the Dockerfile."
    fi
  done

  # Check for containers with host network
  docker ps --format '{{.Names}}' | while read -r container; do
    local netmode
    netmode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "${container}" 2>/dev/null)
    if [ "${netmode}" = "host" ]; then
      write_finding "${findings_file}" "HIGH" "docker" \
        "Container uses host network: ${container}" \
        "Container '${container}' uses host networking, bypassing network isolation."
    fi
  done

  # Check for privileged containers
  docker ps --format '{{.Names}}' | while read -r container; do
    local privileged
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "${container}" 2>/dev/null)
    if [ "${privileged}" = "true" ]; then
      write_finding "${findings_file}" "CRITICAL" "docker" \
        "Privileged container: ${container}" \
        "Container '${container}' runs in privileged mode. This is a major security risk."
    fi
  done

  # Dangling images
  local dangling
  dangling=$(docker images -f "dangling=true" -q | wc -l)
  if [ "${dangling}" -gt 0 ]; then
    write_finding "${findings_file}" "LOW" "docker" \
      "${dangling} dangling Docker images" \
      "Clean up with: docker image prune"
  fi
}

# ============================================================
# 6. FILE PERMISSIONS & SENSITIVE DATA
# ============================================================
scan_permissions() {
  log "INFO" "=== Permission & Sensitive Data Check ==="
  local findings_file="${RESULTS_DIR}/permissions.jsonl"
  : > "${findings_file}"

  # .env files with loose permissions
  find /opt -maxdepth 3 -name '.env' -type f 2>/dev/null | while read -r envfile; do
    local perms
    perms=$(stat -c '%a' "${envfile}" 2>/dev/null)
    if [ "${perms}" != "600" ] && [ "${perms}" != "400" ]; then
      write_finding "${findings_file}" "HIGH" "permissions" \
        "Loose .env permissions: ${envfile}" \
        "File has permissions ${perms}. Set to 600: chmod 600 ${envfile}"
    fi
  done

  # Private keys with loose permissions
  find /opt /root -maxdepth 4 -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null | while read -r keyfile; do
    local perms
    perms=$(stat -c '%a' "${keyfile}" 2>/dev/null)
    if [ "${perms}" != "600" ] && [ "${perms}" != "400" ]; then
      write_finding "${findings_file}" "CRITICAL" "permissions" \
        "Loose private key permissions: ${keyfile}" \
        "Key file has permissions ${perms}. Set to 600: chmod 600 ${keyfile}"
    fi
  done
}

# ============================================================
# MAIN
# ============================================================
main() {
  log "INFO" "=============================="
  log "INFO" "VPS Security Scan - ${TIMESTAMP}"
  log "INFO" "=============================="

  scan_secrets
  scan_dependencies
  scan_vps_hardening
  scan_nginx
  scan_docker
  scan_permissions

  # Write summary
  cat > "${RESULTS_DIR}/summary.json" <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "critical": ${CRITICAL},
  "high": ${HIGH},
  "medium": ${MEDIUM},
  "low": ${LOW},
  "info": ${INFO},
  "total_findings": $((CRITICAL + HIGH + MEDIUM + LOW + INFO))
}
EOF

  log "INFO" "=============================="
  log "INFO" "Scan complete!"
  log "INFO" "CRITICAL: ${CRITICAL} | HIGH: ${HIGH} | MEDIUM: ${MEDIUM} | LOW: ${LOW} | INFO: ${INFO}"
  log "INFO" "Results: ${RESULTS_DIR}"
  log "INFO" "=============================="

  # Generate HTML report
  "${SCANNER_DIR}/generate-report.sh" "${RESULTS_DIR}"

  # Symlink latest
  ln -sfn "${RESULTS_DIR}" "${REPORTS_DIR}/latest"

  # Cleanup old reports (keep last 30)
  ls -dt "${REPORTS_DIR}"/20* 2>/dev/null | tail -n +31 | xargs rm -rf 2>/dev/null || true
}

main "$@"
