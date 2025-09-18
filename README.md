# Vulnerable
# 🔎 SQL Injection Scanner (`sql-scan.py`)

A simple Python-based **SQL Injection detection tool** that scans URLs and HTML forms for possible SQLi vulnerabilities.  
Built using `requests` and `BeautifulSoup4`, this tool is lightweight and beginner-friendly.

---

## ✨ Features
- ✅ Tests URLs with common SQL injection payloads (`'` and `"`)
- ✅ Crawls forms on a target page and tests input fields
- ✅ Detects SQL error messages in responses
- ✅ Supports both **GET** and **POST** forms
- ✅ Easy to use from the command line

---

## 📦 Requirements
Make sure you have **Python 3** installed. Then install the dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests beautifulsoup4

usage:-
python3 sql-scan.py "https://testphp.vulnweb.com/artists.php?artist=1"

[*] Starting SQLi scan on https://testphp.vulnweb.com/artists.php?artist=1
[!] Testing URL: https://testphp.vulnweb.com/artists.php?artist=1'
[+] SQL Injection vulnerability detected, link: https://testphp.vulnweb.com/artists.php?artist=1'


