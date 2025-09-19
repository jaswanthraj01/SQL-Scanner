import pyfiglet
import datetime

def print_header():
    # ASCII banner
    ascii_banner = pyfiglet.figlet_format("SQL Injection Scanner")
    print(ascii_banner)
    
    # Extra info under the banner
    print("=" * 60)
    print(" Author    : Jaswanth")
    print(" Tool      : SQL Injection Scanner")
    print(" Date/Time : ",("2025-10-19 12:15:20"))
    print("=" * 60)
    print("\n")

if __name__ == "__main__":
    print_header()
    # your scanner code (like running sqlmap or custom logic) goes here

#!/usr/bin/env python3
"""
Simple SQL Injection Scanner
Author: Jaswanth
Description:
    A Python tool to detect basic SQL Injection vulnerabilities
    by testing URLs and HTML forms for common SQL error patterns.
"""
import requests
import time

# Common test payloads
payloads = {
    "boolean_based": [
        "' AND 1=1-- -",   # True
        "' AND 1=2-- -"    # False
    ],
    "time_based": [
        "' AND SLEEP(3)-- -",   # Delay injection
    ],
    "union_based": [
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -"
    ]
}

def test_boolean_based(url):
    print("[*] Testing Boolean-based SQLi...")
    r1 = requests.get(url + payloads["boolean_based"][0])
    r2 = requests.get(url + payloads["boolean_based"][1])
    if len(r1.text) != len(r2.text):
        print("[+] Possible Boolean-based SQLi detected!")
    else:
        print("[-] Boolean-based SQLi not detected.")

def test_time_based(url):
    print("[*] Testing Time-based SQLi...")
    start = time.time()
    requests.get(url + payloads["time_based"][0])
    end = time.time()
    if end - start >= 3:
        print("[+] Possible Time-based SQLi detected!")
    else:
        print("[-] Time-based SQLi not detected.")

def test_union_based(url):
    print("[*] Testing UNION-based SQLi...")
    for payload in payloads["union_based"]:
        r = requests.get(url + payload)
        if "error" not in r.text.lower() and r.status_code == 200:
            print(f"[+] Possible UNION-based SQLi with payload: {payload}")
            return
    print("[-] UNION-based SQLi not detected.")

if __name__ == "__main__":
    print("=== SQL Injection Scanner ===")
    target = input("Enter target URL with vulnerable parameter (e.g. http://site.com/page.php?id=1): ")
    test_boolean_based(target)
    test_time_based(target)
    test_union_based(target)

import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from pprint import pprint

# Use a session to keep cookies/headers
s = requests.Session()
s.headers["User-Agent"] = "SQLi-Scanner/1.0"

# Common SQL error messages to look for
SQL_ERRORS = {
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error",
}


def is_vulnerable(response):
    """Check if response contains SQL error patterns"""
    for error in SQL_ERRORS:
        if error.lower() in response.text.lower():
            return True
    return False


def get_all_forms(url):
    """Extract all forms from a webpage"""
    try:
        res = s.get(url, timeout=10)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error fetching forms from {url}: {e}")
        return []


def get_form_details(form):
    """Extract details from an HTML form"""
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action if action else ""
    details["method"] = method
    details["inputs"] = inputs
    return details


def scan_sql_injection(url):
    """Main function to test URL and forms for SQL injection"""
    print(f"[*] Starting SQLi scan on {url}")

    # --- Test URL directly ---
    for c in ["'", '"']:
        new_url = f"{url}{c}"
        print(f"[!] Testing URL: {new_url}")
        try:
            res = s.get(new_url, timeout=10)
            if is_vulnerable(res):
                print(f"[+] SQL Injection vulnerability detected in URL: {new_url}")
                return True
        except Exception as e:
            print(f"[!] Error requesting {new_url}: {e}")

    # --- Test forms on the page ---
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}")

    for form in forms:
        form_details = get_form_details(form)
        target_url = urljoin(url, form_details["action"])
        for c in ["'", '"']:
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["name"]:
                    if input_tag["value"] or input_tag["type"] == "hidden":
                        data[input_tag["name"]] = input_tag["value"] + c
                    elif input_tag["type"] != "submit":
                        data[input_tag["name"]] = f"test{c}"
            try:
                if form_details["method"] == "post":
                    res = s.post(target_url, data=data, timeout=10)
                else:
                    res = s.get(target_url, params=data, timeout=10)
                if is_vulnerable(res):
                    print(f"[+] SQL Injection vulnerability detected in form at {target_url}")
                    print("[+] Form details:")
                    pprint(form_details)
                    return True
            except Exception as e:
                print(f"[!] Error submitting form at {target_url}: {e}")
    print("[-] No SQL Injection vulnerabilities detected.")
    return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scan_sql_injection(target_url)
