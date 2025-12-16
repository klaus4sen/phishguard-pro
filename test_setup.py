print("✅ Python is working!")
print("✅ Flask can be imported:")
try:
    from flask import Flask
    print("✅ Flask imported successfully!")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n✅ Testing requests:")
import requests
try:
    response = requests.get("https://httpbin.org/get", timeout=5)
    print(f"✅ Requests working! Status: {response.status_code}")
except Exception as e:
    print(f"❌ Requests failed: {e}")
