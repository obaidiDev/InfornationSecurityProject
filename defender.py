from flask import Flask, request, redirect, abort, Response, make_response, render_template_string
import re
import subprocess
from threading import Thread
import requests
app_main = Flask(__name__)
app_honeypot = Flask(__name__)

attack_patterns = [
	re.compile(r"select|union|insert|update|delete|drop|alter|sleep|or|and", re.IGNORECASE),
	re.compile(r"<script.*?", re.IGNORECASE),
	re.compile(r"[;&|`]|(\|\|)|(\&\&)", re.IGNORECASE),
	re.compile(r"(\||;|&&|\$|`|>|<|\\|\b(cat|ls|wget|curl|bash|sh|python|perl|ruby|powershell|exec|system|passthru|shell_exec_popen|eval|os\.\w+|subprocess\.\w+)\b)", re.IGNORECASE)
]

blocked_ips = set()
sus_ips = {}
def is_sql_injection(ip, data):
	if ip not in sus_ips:
		sus_ips[ip] = {"sql":0, "xss":0, "dir": 0, "cmd": 0}
	elif sus_ips[ip]["sql"] >= 2:
		blocked_ips.add(ip)
		return True
	if attack_patterns[0].search(data):
		print(f"SQL injection detected from {ip}")
		sus_ips[ip]["sql"]+=1
		return True
	return False

def is_xss_attack(ip, data):
	if ip not in sus_ips:
		sus_ips[ip] = {"sql":0, "xss":0, "dir": 0, "cmd": 0}
	elif sus_ips[ip]["xss"] > 2:
		blocked_ips.add(ip)
		return True
	if attack_patterns[1].search(data):
		print(f"XSS attempt detected from {ip}")
		sus_ips[ip]["xss"]+=1
		return True
	return False


def is_cmd_injection(ip, data):
	if ip not in sus_ips:
		sus_ips[ip] = {"sql":0, "xss":0, "dir": 0, "cmd": 0}
	elif sus_ips[ip]["cmd"] >= 2:
		blocked_ips.add(ip)
		return True
	if attack_patterns[3].search(data) and not attack_patterns[1].search(data):
		print(f"CMD injection detected from {ip}")
		sus_ips[ip]["cmd"]+=1
		return True
	return False

def is_dir_listing(ip, data):
	if ip not in sus_ips:
		sus_ips[ip] = {"sql":0, "xss":0, "dir": 0, "cmd": 0}
	elif sus_ips[ip]["dir"] >= 2:
		blocked_ips.add(ip)
		return True
	if attack_patterns[2].search(data):
		print(f"dir listing attempt detected from {ip}")
		sus_ips[ip]["dir"]+=1
		return True
	return False

def sanitize(data):
	return re.sub(r"<script.*?","",data,flags=re.IGNORECASE)

def is_attack_detected(data):
	for pattern in attack_patterns:
		if pattern.search(data):
			return True
	return False
# I do not want to use it for testing porpuses but you can call this function on the IP you want to block it permenantily.
def block_ip(ip):
	try:
		subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
		print(f"Blocked IP: {ip}")
	except Exception as e:
		print(f"Failed to block IP {ip}: {e}")

@app_main.route("/DVWA/<path:subpath>",methods=["GET", "POST"])
def main_server(subpath):
	client_ip = request.remote_addr
	if client_ip in blocked_ips:
		abort(403)

	if request.method == "GET":
		for key, value in request.args.items():
			if is_sql_injection(client_ip, f"{key}={value}") or is_cmd_injection(client_ip, f"{key}={value}") or is_dir_listing(client_ip, f"{key}={value}"):
				print(f"Attack detected from {client_ip}. Redirecting to honeypot.")
				return redirect(f"http://10.84.10.120:5001/DVWA-honeypot/{subpath}")

			elif is_xss_attack(client_ip, f"{key}={value}"):
				alert = f"""
				<script>
					alert('You just clicked a malicious URL please be careful next time or otherwise we will block you from the server!');
					window.location.href = 'http://10.84.10.120:5000/DVWA/login.php
				</script>"""
				return render_template_string(alert)

	elif request.method == "POST":
		for key, value in request.args.items():
			if is_sql_injection(client_ip, f"{key}={value}") or is_cmd_injection(client_ip, f"{key}={value}") or is_dir_listing(client_ip, f"{key}={value}"):
				print(f"Attack detected from {client_ip}. Redirecting to honeypot.")
				return redirect(f"http://10.84.10.120:5001/DVWA-honeypot/{subpath}")

			elif is_xss_attack(client_ip, f"{key}={value}"):
				alert = f"""
				<script>
					alert('You just clicked a malicious URL please be careful next time or otherwise we will block you from the server!');
					window.location.href = 'http://10.84.10.120:5000/DVWA/login.php
				</script>"""
				return render_template_string(alert)
	try:

		with requests.Session() as session:

			cookies = request.cookies
			headers = {key: value for key, value, in request.headers}
			if request.method == "GET":
				response = session.get(f"http://10.84.10.120:8080/DVWA/{subpath}", params=request.args, headers=headers, cookies=cookies,allow_redirects=False)
			else:
				print(request.form)
				response = session.post(f"http://10.84.10.120:8080/DVWA/{subpath}", data=request.form, headers=headers, cookies=cookies, allow_redirects=False)

			if 300 <= response.status_code < 400:
				redirect_url = response.headers.get("Location")
				print(redirect_url)
				if redirect_url:
					if not redirect_url.startswith("http"):
						redirect_url = f"http://10.84.10.120:5000/DVWA/{redirect_url.replace('DVWA/','')}"
					return redirect(redirect_url, code=response.status_code)


			flask_response = make_response(response.content, response.status_code)


			for key, value in response.headers.items():
				if key.lower() not in ["content-encoding", "transfer-encoding", "content-length"]:
					flask_response.headers[key] = value

			#set_cookie_headers = response.raw._original_response.msg.get_all("Set-Cookie")
			#print(set_cookie_headers)
			#if set_cookie_headers:
			#	for value in set_cookie_headers:
			#		flask_response.headers.add("Set-Cookie", value)

			for key, value in response.cookies.items():
				print(f"{key}={value}")
				flask_response.set_cookie(key, value)

			return flask_response

	except requests.exceptions.RequestException as e:
		print(f"Error proxying request to DVWA: {e}")
		abort(500)


@app_honeypot.route("/DVWA-honeypot/<path:subpath>",methods=["GET", "POST"])
def honeypot_server(subpath):
	client_ip = request.remote_addr

#	if request.method == "GET":
#		for key, value in request.args.items():
#			if is_attack_detected(f"{key}={value}"):
#				print(f"Attack detected from {client_ip} in honeypot. Blocking IP.")
#				blocked_ips.add(client_ip)
#				block_ip(client_ip)
#				abort(403)
#			else:
#				return redirect(f"http://10.84.10.120:8080/DVWA/{subpath}?{key}={value}")
#
#
#	elif request.method == "POST":
#		for key, value in request.args.items():
#			if is_attack_detected(f"{key}={value}"):
#				print(f"Attack detected from {client_ip} in honeypot. Blocking IP.")
#				blocked_ips.add(client_ip)
#				block_ip(client_ip)
#				abort(403)
#
#			else:
#				return redirect(f"http://10.84.10.120:8080/DVWA/{subpath}?{key}={value}")

	if request.method == "GET":
		for key, value in request.args.items():
			if is_sql_injection(client_ip, f"{key}={value}") or is_cmd_injection(client_ip, f"{key}={value}") or is_dir_listing(client_ip, f"{key}={value}"):
				print(f"Attack detected from {client_ip}. Redirecting to honeypot.")
				return redirect(f"http://10.84.10.120:5001/DVWA-honeypot/{subpath}")

			elif is_xss_attack(client_ip, f"{key}={value}"):
				alert = f"""
				<script>
					alert('You just clicked a malicious URL please be careful next time or otherwise we will block you from the server!');
					window.location.href = 'http://10.84.10.120:5001/DVWA-honeypot/login.php
				</script>"""
				return render_template_string(alert)

			else:
				return redirect(f"http://10.84.10.120:5000/DVWA/{subpath}?{key}={value}")

	elif request.method == "POST":
		for key, value in request.args.items():
			if is_sql_injection(client_ip, f"{key}={value}") or is_cmd_injection(client_ip, f"{key}={value}") or is_dir_listing(client_ip, f"{key}={value}"):
				print(f"Attack detected from {client_ip}. Redirecting to honeypot.")
				return redirect(f"http://10.84.10.120:5001/DVWA-honeypot/{subpath}")

			elif is_xss_attack(client_ip, f"{key}={value}"):
				alert = f"""
				<script>
					alert('You just clicked a malicious URL please be careful next time or otherwise we will block you from the server!');
					window.location.href = 'http://10.84.10.120:5001/DVWA-honeypot/login.php
				</script>"""
				return render_template_string(alert)
			else:
				return redirect(f"http://10.84.10.120:5000/DVWA/{subpath}?{key}={value}")

	try:

		with requests.Session() as session:
			cookies = request.cookies
			headers = {key: value for key, value, in request.headers if key != "Host"}

			if request.method == "GET":
				response = session.get(f"http://10.84.10.120:8081/DVWA-honeypot/{subpath}", params=request.args, headers=headers, cookies=cookies, allow_redirects=False)
			else:
				response = session.post(f"http://10.84.10.120:8081/DVWA-honeypot/{subpath}", data=request.form, headers=headers, cookies=cookies, allow_redirects=False)

			if 300 <= response.status_code < 400:
				redirect_url = response.headers.get("Location")
				if redirect_url:
					if not redirect_url.startswith("http"):
						redirect_url = f"http://10.84.10.120:5001/DVWA-honeypot/{redirect_url.replace('DVWA-honeypot/','')}"
					print(redirect_url)
					return redirect(redirect_url, code=response.status_code)

			flask_response = make_response(response.content, response.status_code)
			for key, value in response.headers.items():
				if key.lower() not in ["content-encoding", "transfer-encoding", "content-length"]:
					flask_response.headers[key] = value

			for cookie in response.cookies:
				flask_response.set_cookie(cookie.name, cookie.value)

			return flask_response

	except requests.exceptions.RequestException as e:
		print(f"Error proxying request to DVWA Honeypot: {e}")
		abort(500)

if __name__ == "__main__":
	Thread(target=lambda: app_main.run(host="0.0.0.0", port=5000)).start()
	Thread(target=lambda: app_honeypot.run(host="0.0.0.0", port=5001)).start()
