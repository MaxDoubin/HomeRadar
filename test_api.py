import asyncio
from backend.main import app
from fastapi.testclient import TestClient

client = TestClient(app)
response = client.get("/threat-intel/cisa-kev?query=apple")
print("CISA:", response.json())
response = client.get("/blocklists")
print("Blocklists:", response.json())
response = client.get("/digest/preview")
print("Digest:", response.json())
