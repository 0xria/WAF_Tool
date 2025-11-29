Overview:

WAF_Tool is a lightweight, configurable Web Application Firewall (WAF) designed to protect web applications from common attacks, including SQL injection, XSS, CSRF, and more. It’s easy to deploy and integrates seamlessly with your existing server stack.

See it as your web app’s personal bodyguard — watching, learning, and blocking attacks in real-time.

Features:

Real-time monitoring of HTTP requests

Rule-based blocking and whitelisting

Logging and alerting for suspicious activity

Configurable thresholds for automated blocking

Lightweight and low-latency

Install
git clone https://github.com/0xria/WAF_Tool.git
cd Web_Application_Firewall
pip install -r requirements.txt

Run:

Use a virtual environment from the start(On your terminal)

Even if it’s just one package, venv keeps things isolated:

python3 -m venv venv
source venv/bin/activate
pip install flask  # for example

Track your dependencies in a requirements.txt as you go:

pip freeze > requirements.txt
python3 waf.py


License

MIT © 2025 Ria


Contributing

Contributions are welcome! Feel free to submit issues or pull requests. Please follow the code style guidelines in CONTRIBUTING.md.

License

MIT License. See LICENSE file for details.
