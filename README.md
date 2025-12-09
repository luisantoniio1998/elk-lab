# 🛡️ ELK Security Lab - OWASP Threat Detection

A complete Elasticsearch-Kibana-Filebeat (ELK) stack for security monitoring and OWASP Top 10 threat detection using OWASP Juice Shop as a vulnerable web application target.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![ELK](https://img.shields.io/badge/ELK-8.x-orange.svg)
![Security](https://img.shields.io/badge/security-OWASP%20Top%2010-red.svg)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [What's Inside](#whats-inside)
- [Security Detection](#security-detection)
- [Dashboards & Visualizations](#dashboards--visualizations)
- [Learning Resources](#learning-resources)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This project demonstrates how to build a **Security Operations Center (SOC) monitoring system** using the ELK stack. It captures HTTP traffic from a vulnerable web application (OWASP Juice Shop), parses logs with Grok patterns, detects OWASP Top 10 threats using Painless scripts, and visualizes security events in Kibana.

**Perfect for:**
- Learning ELK stack fundamentals
- Understanding Grok pattern parsing
- Building security detection rules
- Practicing OWASP Top 10 vulnerability identification
- Creating SOC dashboards
- Cybersecurity training and labs

---

## ✨ Features

### 🔍 Security Detection
- **SQL Injection** (OWASP A03:2021 - Injection)
- **Cross-Site Scripting (XSS)** (OWASP A03:2021 - Injection)
- **Path Traversal** (OWASP A01:2021 - Broken Access Control)
- **Command Injection** (OWASP A03:2021 - Injection)
- **Authentication Failures** (OWASP A07:2021 - Authentication Failures)
- **Security Scanner Detection** (SQLMap, Nikto, Burp, etc.)
- **Suspicious HTTP Methods** (PUT, DELETE, TRACE)
- **Backend Attack Indicators** (Upstream errors)
- **Resource Exhaustion** (DoS indicators)
- **Unauthorized Access Attempts**

### 📊 Data Processing
- **Grok Patterns** - Parse Nginx access and error logs
- **Painless Scripts** - Real-time threat detection and scoring
- **Field Extraction** - Client IP, HTTP methods, URLs, status codes
- **Threat Severity Scoring** - Critical, High, Medium, Low
- **OWASP Category Mapping** - Automatic classification

### 🎨 Visualization Ready
- Pre-configured for Kibana dashboards
- Real-time security event monitoring
- Threat trend analysis
- Attack source tracking
- Failed login monitoring

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Client/Attacker                       │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP Requests
                     ↓
┌─────────────────────────────────────────────────────────┐
│              Nginx Reverse Proxy (Port 8080)             │
│  • Captures HTTP traffic                                 │
│  • Logs: access.log (detailed format)                    │
│  • Logs: error.log (upstream errors)                     │
└────────────────────┬────────────────────────────────────┘
                     │ Proxy to backend
                     ↓
┌─────────────────────────────────────────────────────────┐
│          OWASP Juice Shop (Vulnerable App)               │
│  • Intentionally insecure web application                │
│  • For testing security detection                        │
└──────────────────────────────────────────────────────────┘

         ↓ Logs written to shared volume

┌─────────────────────────────────────────────────────────┐
│                     Filebeat                             │
│  • Reads: /var/log/nginx/access.log                     │
│  • Reads: /var/log/nginx/error.log                      │
│  • Ships to Elasticsearch with pipeline references       │
└────────────────────┬────────────────────────────────────┘
                     │ JSON Events
                     ↓
┌─────────────────────────────────────────────────────────┐
│                  Elasticsearch                           │
│  Pipeline: nginx-access-parser                           │
│    1. Grok - Parse log format                            │
│    2. Date - Convert timestamp                           │
│    3. Scripts - Detect threats (SQL, XSS, etc.)          │
│    4. Scripts - Calculate severity scores                │
│                                                           │
│  Pipeline: nginx-error-parser                            │
│    1. Grok - Parse error log format                      │
│    2. Scripts - Detect upstream attacks                  │
│    3. Scripts - Classify error types                     │
│                                                           │
│  Indexes: filebeat-*                                     │
└────────────────────┬────────────────────────────────────┘
                     │ Query API
                     ↓
┌─────────────────────────────────────────────────────────┐
│                     Kibana (Port 5601)                   │
│  • Discover - Search and filter logs                     │
│  • Dashboards - SOC visualizations                       │
│  • Alerts - Threat notifications                         │
└──────────────────────────────────────────────────────────┘
```

---

## 📦 Prerequisites

- **Docker** 20.10+
- **Docker Compose** 2.x
- **8GB RAM** minimum (16GB recommended)
- **10GB disk space**
- **Ports available:** 5601 (Kibana), 8080 (Nginx), 9200 (Elasticsearch)

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/luisantoniio1998/elk-lab.git
cd elk-lab
```

### 2. Start the Stack

```bash
docker-compose up -d
```

**Services will start:**
- Elasticsearch (localhost:9200)
- Kibana (localhost:5601)
- Nginx Proxy (localhost:8080)
- OWASP Juice Shop
- Filebeat
- Traffic Generator

### 3. Install Grok Pipelines

```bash
# Wait for Elasticsearch to be ready (30-60 seconds)
sleep 60

# Install pipelines
./setup-pipeline.sh
```

**Or manually:**
```bash
curl -X PUT 'http://localhost:9200/_ingest/pipeline/nginx-access-parser' \
  -u elastic:changeme \
  -H 'Content-Type: application/json' \
  -d @nginx-pipeline.json

curl -X PUT 'http://localhost:9200/_ingest/pipeline/nginx-error-parser' \
  -u elastic:changeme \
  -H 'Content-Type: application/json' \
  -d @nginx-error-pipeline.json
```

### 4. Access Kibana

```bash
# Open in browser
open http://localhost:5601
```

**Login credentials:**
- Username: `elastic`
- Password: `changeme`

### 5. Create Index Pattern

1. Go to **Stack Management → Index Patterns**
2. Click **Create Index Pattern**
3. Enter: `filebeat-*`
4. Select time field: `@timestamp`
5. Click **Create**

### 6. View Security Events

1. Go to **Analytics → Discover**
2. Select index: `filebeat-*`
3. Search: `security.threat_detected: true`

🎉 **You're now monitoring security threats!**

---

## 📂 What's Inside

```
elk-lab/
├── docker-compose.yml           # Stack definition
├── .env                         # Environment variables
├── README.md                    # This file
├── START-HERE.md                # Detailed setup guide
├── SECURITY-TESTING-GUIDE.md    # Attack testing scenarios
│
├── nginx/
│   ├── nginx.conf               # Nginx configuration
│   └── entrypoint.sh            # Log file setup script
│
├── filebeat/
│   └── filebeat.yml             # Log shipping configuration
│
├── nginx-pipeline.json          # Access log parser + security detection
├── nginx-error-pipeline.json    # Error log parser + threat detection
└── setup-pipeline.sh            # Pipeline installation script
```

---

## 🔒 Security Detection

### Access Log Detection (nginx-pipeline.json)

The access log pipeline detects threats in HTTP requests:

| Threat | Pattern Examples | OWASP Category | Severity |
|--------|-----------------|----------------|----------|
| **SQL Injection** | `' OR '1'='1`, `UNION SELECT`, `DROP TABLE` | A03:2021 - Injection | Critical (10) |
| **XSS** | `<script>`, `onerror=`, `javascript:` | A03:2021 - Injection | High (8) |
| **Path Traversal** | `../`, `..\\`, `/etc/passwd` | A01:2021 - Broken Access Control | High (9) |
| **Command Injection** | `; whoami`, `\| cat`, `$(cmd)` | A03:2021 - Injection | Critical (10) |
| **Auth Failures** | HTTP 401, 403 responses | A07:2021 - Authentication | Low (3) |
| **Security Scanners** | SQLMap, Nikto, Burp user agents | Detection | Medium (5) |

### Error Log Detection (nginx-error-pipeline.json)

The error log pipeline detects attack indicators:

| Indicator | Pattern | Description | Severity |
|-----------|---------|-------------|----------|
| **Upstream Errors** | `upstream prematurely closed` | Backend crash/DoS | High (7) |
| **Unauthorized Access** | `permission denied`, `forbidden` | Access control bypass attempts | Medium (6) |
| **Connection Attacks** | `connection refused`, `reset` | Port scanning, network attacks | Medium (5) |
| **Resource Exhaustion** | `too many`, `limit exceeded` | DoS attacks | High (8) |

### Fields Added by Pipelines

**Security Fields:**
```json
{
  "security": {
    "threats": ["sql_injection", "xss"],
    "threat_detected": true,
    "owasp_category": "A03:2021-Injection",
    "severity": "critical",
    "severity_score": 18,
    "description": "Multiple injection attacks detected"
  },
  "event_type": "security"
}
```

**Parsed Fields:**
```json
{
  "client": {"ip": "192.168.1.100"},
  "http": {
    "method": "GET",
    "version": "1.1",
    "response": {"status_code": 200}
  },
  "url": {"path": "/api/Products?id=1' OR '1'='1"},
  "user_agent": {"original": "Mozilla/5.0..."},
  "nginx": {
    "request_time": 0.052,
    "upstream_response_time": 0.051
  }
}
```

---

## 📊 Dashboards & Visualizations

### Recommended Visualizations

#### 1. **Security Threat Overview**
- **Type:** Metric
- **Query:** `security.threat_detected: true`
- **Shows:** Total threats detected

#### 2. **Threat Severity Breakdown**
- **Type:** Pie Chart
- **Field:** `security.severity.keyword`
- **Shows:** Critical, High, Medium, Low distribution

#### 3. **OWASP Top 10 Categories**
- **Type:** Bar Chart
- **Field:** `security.owasp_category.keyword`
- **Shows:** Which OWASP categories are being attacked

#### 4. **Threat Types**
- **Type:** Pie Chart
- **Field:** `security.threats.keyword`
- **Shows:** SQL injection, XSS, path traversal counts

#### 5. **Top Attacking IPs**
- **Type:** Table
- **Rows:** `client.ip.keyword`
- **Metrics:** Count, Unique threats
- **Shows:** Which IPs are attacking most

#### 6. **Failed Login Attempts**
- **Type:** Line Chart
- **Field:** `security.failed_login: true`
- **Shows:** Brute force patterns over time

#### 7. **HTTP Methods Distribution**
- **Type:** Pie Chart
- **Field:** `http.method.keyword`
- **Shows:** GET, POST, PUT, DELETE usage

#### 8. **Status Code Timeline**
- **Type:** Area Chart
- **Field:** `http.response.status_code`
- **Split by:** Status code ranges (2xx, 4xx, 5xx)

#### 9. **Response Time Performance**
- **Type:** Line Chart
- **Field:** `nginx.request_time` (average)
- **Shows:** Application performance trends

#### 10. **Security Scanner Detection**
- **Type:** Table
- **Field:** `user_agent.original.keyword`
- **Filter:** `security.scanner_type: "automated_scanner"`

### Sample KQL Queries

```kql
# All security threats
security.threat_detected: true

# Critical threats only
security.severity: "critical"

# SQL injection attempts
security.threats: "sql_injection"

# Failed logins from specific IP
security.failed_login: true AND client.ip: "192.168.1.100"

# Multiple threat types in single request
security.threats: ("sql_injection" AND "xss")

# High or critical severity
security.severity: ("high" OR "critical")

# Access log security events
log_type: "http_access" AND event_type: "security"

# Error log security events
log_type: "http_error" AND security.threat_detected: true

# Upstream attack indicators
security.threats: "suspicious_upstream_error"

# Attacks on specific endpoint
security.threat_detected: true AND url.path: "/api/Users"
```

---

## 📚 Learning Resources

### Included Documentation

- **[START-HERE.md](START-HERE.md)** - Detailed setup and configuration guide
- **[SECURITY-TESTING-GUIDE.md](SECURITY-TESTING-GUIDE.md)** - How to test threat detection

### Key Concepts Covered

1. **ELK Stack Architecture** - How Elasticsearch, Filebeat, and Kibana work together
2. **Grok Patterns** - Pattern matching for log parsing
3. **Painless Scripting** - Elasticsearch's scripting language for data enrichment
4. **Ingest Pipelines** - Processing data before indexing
5. **OWASP Top 10** - Common web application vulnerabilities
6. **Security Detection Engineering** - Building detection rules
7. **Log Analysis** - Parsing and analyzing access/error logs
8. **Threat Scoring** - Risk-based prioritization

### External Resources

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Grok Patterns Reference](https://github.com/elastic/logstash/blob/main/patterns/grok-patterns)
- [Painless Scripting](https://www.elastic.co/guide/en/elasticsearch/painless/current/index.html)
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

---

## 🐛 Troubleshooting

### Elasticsearch won't start
```bash
# Check logs
docker logs elasticsearch

# Common issue: Not enough memory
# Solution: Increase Docker memory to 8GB+
```

### No logs in Kibana
```bash
# 1. Check Filebeat is running
docker logs filebeat

# 2. Verify Nginx logs are being written
docker exec nginx_proxy ls -lh /var/log/nginx/

# 3. Check pipelines are installed
curl -u elastic:changeme http://localhost:9200/_ingest/pipeline | jq 'keys'

# 4. Test pipeline manually
curl -u elastic:changeme http://localhost:9200/_ingest/pipeline/nginx-access-parser | jq '.'
```

### Nginx logs not visible
```bash
# Check if logs are symlinks (should be files)
docker exec nginx_proxy ls -lh /var/log/nginx/

# If symlinks, recreate container
docker-compose stop nginx_proxy
docker-compose rm -f nginx_proxy
docker-compose up -d nginx_proxy
```

### Pipelines not detecting threats
```bash
# Test with a known attack
curl "http://localhost:8080/api/Products?id=1%27%20OR%20%271%27=%271"

# Wait 10 seconds, then check
curl -s -u elastic:changeme \
  "http://localhost:9200/filebeat-*/_search?q=security.threat_detected:true&size=1" \
  | jq '.hits.hits[0]._source.security'
```

### Can't access Kibana
```bash
# Check Kibana is running
docker ps | grep kibana

# Check Kibana logs
docker logs kibana

# Verify elasticsearch connection
curl -u elastic:changeme http://localhost:9200/_cluster/health
```

---

## 🧪 Testing Security Detection

### Quick Test Script

```bash
#!/bin/bash

echo "🧪 Testing Security Detection..."

# SQL Injection
curl -s "http://localhost:8080/api/Products?id=1%27%20OR%20%271%27=%271" > /dev/null
echo "✅ SQL Injection test sent"

# XSS
curl -s "http://localhost:8080/search?q=%3Cscript%3Ealert(1)%3C/script%3E" > /dev/null
echo "✅ XSS test sent"

# Path Traversal
curl -s "http://localhost:8080/ftp/../../etc/passwd" > /dev/null
echo "✅ Path Traversal test sent"

# Failed Login
curl -s -X POST http://localhost:8080/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@test.com","password":"wrong"}' > /dev/null
echo "✅ Failed login test sent"

echo ""
echo "⏳ Waiting 10 seconds for logs to be processed..."
sleep 10

echo ""
echo "📊 Checking detected threats:"
curl -s -u elastic:changeme \
  "http://localhost:9200/filebeat-*/_search?size=5&q=security.threat_detected:true" \
  | jq '.hits.hits[] | {
      time: ._source["@timestamp"],
      url: ._source.url.path,
      threats: ._source.security.threats,
      severity: ._source.security.severity
    }'
```

See **[SECURITY-TESTING-GUIDE.md](SECURITY-TESTING-GUIDE.md)** for detailed testing scenarios.

---

## 🎓 What You'll Learn

By working with this project, you'll gain hands-on experience with:

✅ **ELK Stack Fundamentals**
- Setting up Elasticsearch, Kibana, Filebeat
- Understanding data flow and architecture
- Index patterns and mappings

✅ **Log Analysis & Parsing**
- Writing Grok patterns for custom log formats
- Field extraction and data transformation
- Multi-line log parsing

✅ **Security Detection Engineering**
- Building detection rules for OWASP threats
- Threat severity scoring
- False positive reduction

✅ **Painless Scripting**
- Data enrichment with scripts
- Conditional logic in pipelines
- Performance optimization

✅ **SOC Operations**
- Creating security dashboards
- Threat hunting with KQL
- Alert configuration

✅ **DevSecOps**
- Infrastructure as Code with Docker Compose
- Pipeline automation
- Security monitoring integration

---

## 🤝 Contributing

Contributions are welcome! Here are some ways to contribute:

- 🐛 Report bugs or issues
- 💡 Suggest new security detections
- 📖 Improve documentation
- 🎨 Add dashboard templates
- 🧪 Create test scenarios

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-detection`)
3. Commit your changes (`git commit -m 'Add SQL injection variant detection'`)
4. Push to the branch (`git push origin feature/amazing-detection`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP** - For Juice Shop and security guidance
- **Elastic** - For the amazing ELK stack
- **Community** - For Grok patterns and detection rules

---

## 🔗 Links

- **GitHub Repository:** https://github.com/luisantoniio1998/elk-lab
- **Issues:** https://github.com/luisantoniio1998/elk-lab/issues
- **Documentation:** [START-HERE.md](START-HERE.md)

---

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**⭐ If you find this project helpful, please star it on GitHub!**

Made with ❤️ for the security community
