from http.server import BaseHTTPRequestHandler
import json
import hashlib
import base64
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SECRET_SEED = "APIMPDS$9712Q"
IV_STR = "AP4123IMPDS@12768F"
API_URL = "http://impds.nic.in/impdsmobileapi/api/getrationcard"
TOKEN = "91f01a0a96c526d28e4d0c1189e80459"
ACCESS_KEY = "vniox"
USER_AGENT = "Dalvik/2.1.0"

def get_md5_hex(s): return hashlib.md5(s.encode("iso-8859-1")).hexdigest()
def generate_session_id(): return "28" + datetime.now().strftime("%Y%m%d%H%M%S")
def derive_aes_key(s): return hashlib.sha256(s.encode()).digest()[:16]

def encrypt_aadhaar(aadhaar, session_id):
    key_material = get_md5_hex(get_md5_hex(SECRET_SEED) + session_id)
    aes_key = derive_aes_key(key_material)
    iv = IV_STR.encode()[:16]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(aadhaar.encode(), AES.block_size))
    return base64.b64encode(base64.b64encode(encrypted)).decode()

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        params = parse_qs(urlparse(self.path).query)

        key = params.get("key", [""])[0]
        aadhaar = params.get("aadhaar", [""])[0]
        state = params.get("state", ["09"])[0]

        if key != ACCESS_KEY:
            self.respond({"error": "Invalid API key"}, 401)
            return

        if len(aadhaar) != 12 or not aadhaar.isdigit():
            self.respond({"error": "Invalid Aadhaar"}, 400)
            return

        session_id = generate_session_id()
        encrypted = encrypt_aadhaar(aadhaar, session_id)

        payload = {
            "id": encrypted,
            "idType": "U",
            "userName": "IMPDS",
            "token": TOKEN,
            "sessionId": session_id,
            "stateCode": state
        }
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}

        resp = requests.post(API_URL, json=payload, headers=headers)
        try:
            result = resp.json()
        except:
            result = {"error": "Invalid backend response"}

        self.respond(result, 200)

    def respond(self, data, status):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
