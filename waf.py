from flask import Flask, request, Response
import requests
import re

app = Flask(__name__)

# Backend server URL (change this to your actual backend)
BACKEND_URL = 'http://localhost:5001'

# Patterns for detecting common attacks
SQL_INJECTION_PATTERNS = [
    r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
    r"(\bor\b\s+\d+\s*=\s*\d+)",
    r"(\bscript\b)",
    r"(\b--\b)",
    r"(\#)",
    r"(\')",
    r"(\")",
    r"(\;)"
]

XSS_PATTERNS = [
    r"(<script[^>]*>.*?</script>)",
    r"(<iframe[^>]*>.*?</iframe>)",
    r"(<object[^>]*>.*?</object>)",
    r"(<embed[^>]*>.*?</embed>)",
    r"(javascript:)",
    r"(vbscript:)",
    r"(onload=)",
    r"(onerror=)",
    r"(onclick=)",
    r"(<img[^>]*src\s*=\s*[\"']?javascript:)",
    r"(<link[^>]*href\s*=\s*[\"']?javascript:)"
]

def detect_attack(text):
    """
    Detects SQL injection and XSS attacks in the given text.
    Returns True if an attack is detected, False otherwise.
    """
    if not text:
        return False

    # Check for SQL injection
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # Check for XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def proxy(path):
    """
    Main proxy function that inspects incoming requests and forwards them if safe.
    """
    # Collect all parts of the request to inspect
    inspection_text = ''

    # Inspect query parameters
    for key, value in request.args.items():
        inspection_text += f"{key}={value}&"

    # Inspect form data
    for key, value in request.form.items():
        inspection_text += f"{key}={value}&"

    # Inspect JSON data if present
    if request.is_json:
        inspection_text += str(request.get_json())

    # Inspect headers (some headers might contain malicious data)
    for header, value in request.headers.items():
        inspection_text += f"{header}:{value}\n"

    # Inspect URL path
    inspection_text += request.path

    # Check for attacks
    if detect_attack(inspection_text):
        # Block the request
        return Response("Forbidden: Potential security threat detected", status=403, mimetype='text/plain')

    # If safe, forward the request to the backend
    try:
        # Prepare the backend URL
        backend_url = f"{BACKEND_URL}/{path}"
        if request.query_string:
            backend_url += f"?{request.query_string.decode()}"

        # Forward the request
        resp = requests.request(
            method=request.method,
            url=backend_url,
            headers={key: value for key, value in request.headers.items() if key.lower() not in ['host', 'content-length']},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )

        # Return the response from backend
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    except requests.RequestException as e:
        # If backend is unreachable, return 502 Bad Gateway
        return Response(f"Bad Gateway: {str(e)}", status=502, mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
