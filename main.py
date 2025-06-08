import base58
import requests
import random
import time
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

# --- Masukkan private key base58 (harus 32/64 byte base58, BUKAN mnemonic) ---
PRIVATE_KEY = "YOUR_PKEY_HERE"

def get_headers():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0'
    ]
    randomUA = random.choice(user_agents)
    return {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9,id;q=0.8',
        'content-type': 'application/json',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"' if 'Chrome' in randomUA else '"Firefox";v="132", "Not A(Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"' if 'Windows' in randomUA else ('"macOS"' if 'Mac' in randomUA else '"Linux"'),
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'sec-gpc': '1',
        'user-agent': randomUA,
        'origin': 'https://www.bitquant.io',
        'referer': 'https://www.bitquant.io/',
        'referrer-policy': 'strict-origin-when-cross-origin'
    }

if not PRIVATE_KEY:
    print("Private key belum diisi.")
    raise SystemExit

print("Length private key base58:", len(PRIVATE_KEY.strip()))

try:
    secret = base58.b58decode(PRIVATE_KEY.strip())
    print("Length decoded secret:", len(secret))
    if len(secret) == 64:
        keypair = SigningKey(secret[:32])  # 64 bytes: pakai 32 pertama
    elif len(secret) == 32:
        keypair = SigningKey(secret)
    else:
        print(f"Format private key salah: {len(secret)} bytes (harus 32/64)")
        raise SystemExit
    public_key = base58.b58encode(keypair.verify_key.encode()).decode()
    print("Public key yang digunakan script:", public_key)
except Exception as e:
    print(f"Private key tidak valid: {e}")
    raise SystemExit

# --- CHECK WHITELIST DENGAN DEBUG ---
r = requests.get(
    f"https://quant-api.opengradient.ai/api/whitelisted?address={public_key}",
    headers=get_headers()
)
print("Raw API response:", repr(r.text))
try:
    data = r.json()
except Exception as e:
    print("JSON decode error:", e)
    data = None
print("Parsed JSON:", data)
print("Allowed status:", data.get("allowed") if data else "Tidak ada data")
if not r.ok or not (data and data.get("allowed")):
    print("Wallet TIDAK whitelisted.")
    raise SystemExit
print("Wallet whitelisted.")

# --- SIWS sign-in ---
nonce = str(int(time.time() * 1000))
issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
message = f"""bitquant.io wants you to sign in with your **blockchain** account:
{public_key}

URI: https://bitquant.io
Version: 1
Chain ID: solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
Nonce: {nonce}
Issued At: {issued_at}"""

try:
    signature = keypair.sign(message.encode("utf-8"), encoder=RawEncoder).signature
    signature_b58 = base58.b58encode(signature).decode()
except Exception as e:
    print(f"Sign gagal: {e}")
    raise SystemExit

r = requests.post(
    "https://quant-api.opengradient.ai/api/verify/solana",
    headers=get_headers(),
    json={"address": public_key, "message": message, "signature": signature_b58}
)
if not r.ok or "token" not in r.json():
    print("Verifikasi gagal.")
    raise SystemExit
token = r.json()["token"]
print("Verifikasi sukses. Token didapat.")

firebase_key = "AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM"
r = requests.post(
    f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={firebase_key}",
    headers=get_headers(),
    json={"token": token, "returnSecureToken": True}
)
if not r.ok or "idToken" not in r.json():
    print("Sign in gagal.")
    raise SystemExit
id_token = r.json()["idToken"]
print("Sign in sukses.")

stats = requests.get(
    f"https://quant-api.opengradient.ai/api/activity/stats?address={public_key}",
    headers={**get_headers(), "authorization": f"Bearer {id_token}"}
)
if not stats.ok:
    print("Gagal ambil stats.")
    raise SystemExit
js = stats.json()
remain = js["daily_message_limit"] - js["daily_message_count"]
print(f"Sisa chat hari ini: {remain}")

chat_prompts = [
    "Analyze my portfolio risk and value",
    "Suggest ways to diversify my crypto holdings",
    "Provide insights on the Solana market trends",
    "What are the top performing tokens this week?",
    "Evaluate my portfolio's performance over the last 30 days",
    "Suggest a low-risk investment strategy",
    "What is the current market sentiment for DeFi tokens?",
    "Analyze the volatility of my assets",
    "Recommend tokens to add to my portfolio",
    "How does my portfolio compare to the market average?",
    "Provide a risk assessment for my current holdings",
    "What are the latest trends in Solana-based projects?",
    "Suggest a rebalancing strategy for my portfolio",
    "Analyze the performance of meme coins in my wallet",
    "What are the risks of holding concentrated assets?",
    "Provide a market outlook for the next quarter",
    "Evaluate my portfolio's exposure to stablecoins",
    "Suggest trading strategies for high-volatility tokens",
    "What are the top DeFi pools on Solana?",
    "Analyze my portfolio's performance against Bitcoin"
]

headers = {**get_headers(), "Authorization": f"Bearer {id_token}", "Content-Type": "application/json"}
for i in range(min(remain, 20)):
    prompt = random.choice(chat_prompts)
    data = {
        "context": {
            "conversationHistory": [{"type": "user", "message": prompt}],
            "address": public_key,
            "poolPositions": [],
            "availablePools": []
        },
        "message": {"type": "user", "message": prompt}
    }
    try:
        r = requests.post(
            "https://quant-api.opengradient.ai/api/agent/run",
            headers=headers,
            json=data
        )
        print(f"Chat {i+1}: {prompt} - {'OK' if r.ok else 'FAIL'}")
        time.sleep(1)
    except Exception as e:
        print(f"Error chat {i+1}: {e}")

print("SELESAI.")
