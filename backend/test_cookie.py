import requests

URL = "http://localhost:8000/auth"
session = requests.Session()

print("--- Testing HttpOnly Cookie Lifecycle ---")

print("\n1. Logging in...")
res1 = session.post(f"{URL}/login", data={"username": "admin@securenet.local", "password": "SuperSecurePassword123!"})
print(f"Status: {res1.status_code}")
print(f"Cookies Received: {session.cookies.get_dict()}")

print("\n2. Accessing Protected Dashboard Data (/users/me)...")
res2 = session.get(f"{URL}/users/me")
print(f"Status: {res2.status_code}")
print(f"Response: {res2.json()['email']}")

print("\n3. Testing Explicit Backend Logout...")
res3 = session.post(f"{URL}/logout")
print(f"Status: {res3.status_code}")

print("\n4. Accessing Protected Data After Logout...")
res4 = session.get(f"{URL}/users/me")
print(f"Status: {res4.status_code}")
print("If status is 401, test passed perfectly!")
