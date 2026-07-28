import requests

try:
    res = requests.get("http://127.0.0.1:8000/status")
    print("Status:", res.status_code, res.text)
    res2 = requests.get("http://127.0.0.1:8000/digest/preview")
    print("Digest Preview:", res2.status_code, res2.text[:100])
except Exception as e:
    print(e)
