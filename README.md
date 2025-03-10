### **Server-Side Request Forgery (SSRF)**

**Server-Side Request Forgery (SSRF)** is a vulnerability that occurs when an attacker is able to make the server initiate requests to unintended locations, often by manipulating the server to send HTTP or other types of requests to internal services or external systems. SSRF attacks can be exploited to gain unauthorized access to internal resources, perform denial-of-service (DoS) attacks, or even exfiltrate sensitive information.

In an SSRF attack, the attacker controls a request that the vulnerable server sends to other servers, usually to internal systems or services that would not otherwise be accessible. These requests can target local services, internal APIs, or even external services that are not exposed to the public.

### **How SSRF Works**

1. **Vulnerable Web Application**: The web application accepts user input (usually via a URL or request) that the server then uses to make an HTTP request to another service or internal resource.
   
2. **Manipulation**: The attacker manipulates the input (e.g., URL) to make the server send requests to unauthorized or internal services, which the attacker cannot access directly.

3. **Exploitation**: By manipulating the server’s request, the attacker may be able to:
   - Access internal systems and services (e.g., internal databases, metadata endpoints).
   - Bypass firewalls or network protections.
   - Exfiltrate sensitive data, such as credentials, session information, or private keys.

### **Types of SSRF Attacks**

1. **Internal SSRF**: The attacker targets internal services that are not exposed to the public, such as the application’s internal API or metadata endpoints.
2. **External SSRF**: The attacker targets external services, such as third-party APIs or websites that are not directly exposed to the public.
3. **Blind SSRF**: The attacker does not directly see the results of the SSRF request but can infer information based on side effects (e.g., timing differences or application behavior).

---

### **Real-Life Example of SSRF Attack**

Let's imagine a vulnerable web application that allows a user to fetch an image by submitting a URL. The server will fetch the image and display it to the user.

#### **Vulnerable Code Example:**

```python
# Flask example (Python)

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch_image', methods=['GET'])
def fetch_image():
    url = request.args.get('url')  # The user provides the URL
    response = requests.get(url)  # Server fetches the URL and returns the image
    return response.content

if __name__ == '__main__':
    app.run(debug=True)
```

Here, the web application simply accepts a URL as a parameter and fetches the content of that URL via an HTTP request. This makes it vulnerable to SSRF.

#### **How an Attacker Exploits This:**

An attacker could manipulate the `url` parameter to make the server request internal resources:

```
http://vulnerable-website.com/fetch_image?url=http://localhost:8080
```

The attacker might exploit this to access sensitive internal services, such as an internal admin interface, a database, or an internal metadata service (e.g., AWS EC2 metadata).

For example, on an **AWS EC2 instance**, the metadata endpoint can be accessed at `http://169.254.169.254`. This endpoint provides sensitive information, such as instance metadata, IAM credentials, and more.

```
http://vulnerable-website.com/fetch_image?url=http://169.254.169.254/latest/meta-data/
```

This request can return sensitive data, such as IAM credentials for the server, which the attacker can then use to escalate their access privileges.

#### **Example of Exploiting Metadata Services (AWS EC2):**

When an attacker sends the following URL to the vulnerable application:

```
http://vulnerable-website.com/fetch_image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```

The attacker could obtain temporary AWS IAM credentials for the EC2 instance and potentially gain unauthorized access to AWS services.

---

### **Types of Data an Attacker Can Exfiltrate via SSRF**

1. **Internal Application Services**: If internal services are accessible via HTTP, the attacker can send SSRF requests to those services to obtain sensitive data or execute commands.
2. **Metadata Services**: On cloud platforms like AWS, Google Cloud, and Azure, SSRF can be used to access instance metadata that can contain sensitive information like API keys, IAM roles, and credentials.
3. **Databases**: If there are database endpoints exposed to the internal network, the attacker can try to enumerate and query them using SSRF.
4. **File Server Access**: Some servers might accept requests to local file systems or internal file servers that can be exploited by SSRF.

---

### **How to Prevent SSRF Vulnerabilities**

1. **Input Validation and Sanitization**:
   - **Restrict the allowed URLs**: If the user input involves URLs, restrict the request to trusted domains or whitelist known, safe services.
   - **Input sanitization**: Ensure that the URLs provided do not include dangerous or unauthorized schemes (e.g., `file://`, `ftp://`, `http://localhost`).

2. **Use Allowlisting and Block Private IPs**:
   - **Restrict requests to local and internal addresses** (e.g., `127.0.0.1`, `169.254.169.254` for metadata).
   - Block any attempts to access private IP addresses or internal services.

3. **Network Segmentation and Firewalls**:
   - Ensure that services exposed externally are properly segmented from internal systems, with strong network controls in place.
   - Use firewalls to prevent the server from accessing internal resources that are not intended to be publicly reachable.

4. **Timeouts and Rate-Limiting**:
   - Set appropriate timeouts for requests to external servers, and consider rate-limiting to prevent abuse.
   - This will help mitigate the impact of SSRF attacks by limiting the number of requests the attacker can make.

5. **Use Metadata Service Protection**:
   - For cloud environments, such as AWS or GCP, consider using **IMDSv2 (Instance Metadata Service v2)**, which requires the use of a session-based token to access metadata, making SSRF attacks harder to exploit.
   - Ensure that metadata services are not accessible from public-facing instances or restrict their access through IAM roles and policies.

---

### **Example of Fixing SSRF in the Code**

To prevent SSRF in the previous Flask code example, you can restrict the URLs that the server is allowed to request:

#### **Fixed Code:**

```python
# Flask example (Python) with SSRF Mitigation

from flask import Flask, request, jsonify
import requests
import urllib.parse

app = Flask(__name__)

# Allowed domains (e.g., only external URLs)
ALLOWED_DOMAINS = ["https://trusted-site.com", "https://images.com"]

def is_safe_url(url):
    # Check if the URL is from an allowed domain
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.netloc in ALLOWED_DOMAINS

@app.route('/fetch_image', methods=['GET'])
def fetch_image():
    url = request.args.get('url')  # The user provides the URL
    if not url or not is_safe_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    try:
        response = requests.get(url)  # Server fetches the URL and returns the image
        return response.content
    except requests.exceptions.RequestException:
        return jsonify({"error": "Failed to fetch the image"}), 500

if __name__ == '__main__':
    app.run(debug=True)
```

### **Explanation of Fix**:
1. **Allowed Domains**: We define a list of allowed domains (`ALLOWED_DOMAINS`) that the server is permitted to make requests to.
2. **URL Validation**: We use the `urllib.parse.urlparse()` function to parse the user-provided URL and ensure it belongs to a trusted domain before making the request.
3. **Response Handling**: We handle exceptions when fetching the URL, returning appropriate error messages.

---

### **Conclusion**

Server-Side Request Forgery (SSRF) is a dangerous vulnerability that allows attackers to make the server send unauthorized requests, potentially exposing sensitive internal resources or external services. It can be mitigated by input validation, restricting network access, and using security measures such as firewalls and metadata service protections. Properly validating and sanitizing user input is critical to preventing SSRF attacks in web applications.
