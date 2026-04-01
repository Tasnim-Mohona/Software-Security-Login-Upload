import requests
import json

try:
    url = "http://localhost:8000/auth/login"
    payload = "username=admin%40securenet.local&password=SuperSecurePassword123%21"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url, headers=headers, data=payload)
    print("STATUS CODE:", response.status_code)
    print("TEXT:", response.text)
except Exception as e:
    print("ERROR:", e)
