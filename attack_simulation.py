import requests
import time

BASE = 'http://127.0.0.1:5000'


def brute_force_test(username, password_list):
    print('\n[+] Brute force simulation starting')
    for pwd in password_list:
        r = requests.post(f"{BASE}/login", data={'username': username, 'password': pwd})
        print(f"trying {pwd} -> {r.status_code} {r.url}")
        if 'Login successful' in r.text:
            print('Password found:', pwd)
            break
        time.sleep(0.2)
    print('Finished brute force test (rate limiting should block after threshold)')


def sql_injection_test():
    print('\n[+] SQL Injection test on vulnerable endpoint')
    payload = "' OR '1'='1"
    r = requests.get(f"{BASE}/vuln_login", params={'username': payload, 'password': 'foo'})
    print('Payload:', payload, 'Response:', r.text)
    print('Now trying same payload against fixed endpoint')
    r = requests.get(f"{BASE}/vuln_login_fixed", params={'username': payload, 'password': 'foo'})
    print('Fixed response:', r.text)


def xss_test():
    print('\n[+] XSS test')
    script = '<script>alert("XSS")</script>'
    for endpoint in ['/echo', '/vuln_echo']:
        r = requests.get(f"{BASE}{endpoint}", params={'text': script})
        print(f"{endpoint} response body:\n", r.text[:200])


def header_inspection():
    print('\n[+] Header inspection')
    r = requests.get(f"{BASE}/login")
    for k, v in r.headers.items():
        if k.lower().startswith(('content-security-policy','x-frame-options','x-content-type-options','strict-transport-security')):
            print(f"{k}: {v}")


def tls_explanation():
    print('\n[+] TLS explanation')
    print('In production the application would be served via HTTPS (e.g. nginx, gunicorn with certs, Let\'s Encrypt). TLS encrypts traffic between client and server, preventing eavesdropping and tampering.')


def network_surface_analysis():
    print('\n[+] Network surface analysis')
    print('Use nmap to scan open ports: `nmap -sV -p- 127.0.0.1`')
    print('Exposed services increase attack surface; ensure only necessary ports are open (e.g., 80/443).')


if __name__ == '__main__':
    brute_force_test('admin', ['password','123456','secret','admin','letmein'])
    sql_injection_test()
    xss_test()
    header_inspection()
    tls_explanation()
    network_surface_analysis()
