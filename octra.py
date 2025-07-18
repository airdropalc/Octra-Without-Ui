#!/usr/bin/env python3
import json, base64, hashlib, time, sys, re, os, shutil, asyncio, aiohttp, threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import nacl.signing
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import ssl
import signal

# Configuration
priv, addr, rpc = None, None, None
sk, pub = None, None
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
μ = 1_000_000
h = []
cb, cn, lu, lh = None, None, 0, 0
session = None
executor = ThreadPoolExecutor(max_workers=1)
stop_flag = threading.Event()

def load_wallet():
    global priv, addr, rpc, sk, pub
    try:
        wallet_path = os.path.expanduser("~/.octra/wallet.json")
        if not os.path.exists(wallet_path):
            wallet_path = "wallet.json"
        
        with open(wallet_path, 'r') as f:
            d = json.load(f)
        
        priv = d.get('priv')
        addr = d.get('addr')
        rpc = d.get('rpc', 'https://octra.network')
        
        if not priv or not addr:
            return False
            
        if not rpc.startswith('https://') and 'localhost' not in rpc:
            print(f"⚠️  WARNING: Using insecure HTTP connection!")
            time.sleep(1)
            
        sk = nacl.signing.SigningKey(base64.b64decode(priv))
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        return True
    except Exception as e:
        print(f"Error loading wallet: {e}")
        return False

async def req(method, path, data=None, timeout=10):
    global session
    if not session:
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context, force_close=True)
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            connector=connector,
            json_serialize=json.dumps
        )
    try:
        url = f"{rpc}{path}"
        
        kwargs = {}
        if method == 'POST' and data:
            kwargs['json'] = data
        
        async with getattr(session, method.lower())(url, **kwargs) as resp:
            text = await resp.text()
            
            try:
                j = json.loads(text) if text.strip() else None
            except:
                j = None
            
            return resp.status, text, j
    except asyncio.TimeoutError:
        return 0, "timeout", None
    except Exception as e:
        return 0, str(e), None

async def req_private(path, method='GET', data=None):
    headers = {"X-Private-Key": priv}
    try:
        url = f"{rpc}{path}"
        
        kwargs = {'headers': headers}
        if method == 'POST' and data:
            kwargs['json'] = data
            
        async with getattr(session, method.lower())(url, **kwargs) as resp:
            text = await resp.text()
            
            if resp.status == 200:
                try:
                    return True, json.loads(text) if text.strip() else {}
                except:
                    return False, {"error": "Invalid JSON response"}
            else:
                return False, {"error": f"HTTP {resp.status}"}
                
    except Exception as e:
        return False, {"error": str(e)}

async def get_state():
    global cb, cn, lu
    now = time.time()
    if cb is not None and (now - lu) < 30:
        return cn, cb
    
    try:
        results = await asyncio.gather(
            req('GET', f'/balance/{addr}'),
            req('GET', '/staging', 5),
            return_exceptions=True
        )
        
        s, t, j = results[0] if not isinstance(results[0], Exception) else (0, str(results[0]), None)
        s2, _, j2 = results[1] if not isinstance(results[1], Exception) else (0, None, None)
        
        if s == 200 and j:
            cn = int(j.get('nonce', 0))
            cb = float(j.get('balance', 0))
            lu = now
            if s2 == 200 and j2:
                our = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == addr]
                if our:
                    cn = max([cn] + [int(tx.get('nonce', 0)) for tx in our])
        elif s == 404:
            cn, cb, lu = 0, 0.0, now
        elif s == 200 and t and not j:
            try:
                parts = t.strip().split()
                if len(parts) >= 2:
                    cb = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                    cn = int(parts[1]) if parts[1].isdigit() else 0
                    lu = now
            except:
                pass
        
        return cn, cb
    except Exception as e:
        print(f"Error getting state: {e}")
        return None, None

async def get_history():
    global h, lh
    now = time.time()
    if now - lh < 60 and h:
        return
    
    try:
        s, t, j = await req('GET', f'/address/{addr}?limit=20')
        if s != 200 or (not j and not t):
            return
        
        if j and 'recent_transactions' in j:
            tx_hashes = [ref["hash"] for ref in j.get('recent_transactions', [])]
            tx_results = await asyncio.gather(*[req('GET', f'/tx/{hash}', 5) for hash in tx_hashes], return_exceptions=True)
            
            existing_hashes = {tx['hash'] for tx in h}
            new_history = []
            
            for i, (ref, result) in enumerate(zip(j.get('recent_transactions', []), tx_results)):
                if isinstance(result, Exception):
                    continue
                s2, _, j2 = result
                if s2 == 200 and j2 and 'parsed_tx' in j2:
                    p = j2['parsed_tx']
                    tx_hash = ref['hash']
                    
                    if tx_hash in existing_hashes:
                        continue
                    
                    is_incoming = p.get('to') == addr
                    amount_raw = p.get('amount_raw', p.get('amount', '0'))
                    amount = float(amount_raw) if '.' in str(amount_raw) else int(amount_raw) / μ
                    message = None
                    if 'data' in j2:
                        try:
                            data = json.loads(j2['data'])
                            message = data.get('message')
                        except:
                            pass
                    new_history.append({
                        'time': datetime.fromtimestamp(p.get('timestamp', 0)),
                        'hash': tx_hash,
                        'amt': amount,
                        'to': p.get('to') if not is_incoming else p.get('from'),
                        'type': 'in' if is_incoming else 'out',
                        'ok': True,
                        'nonce': p.get('nonce', 0),
                        'epoch': ref.get('epoch', 0),
                        'msg': message
                    })
            
            one_hour_ago = datetime.now() - timedelta(hours=1)
            h[:] = sorted(new_history + [tx for tx in h if tx.get('time', datetime.now()) > one_hour_ago], 
                          key=lambda x: x['time'], reverse=True)[:50]
            lh = now
        elif s == 404 or (s == 200 and t and 'no transactions' in t.lower()):
            h.clear()
            lh = now
    except Exception as e:
        print(f"Error getting history: {e}")

def derive_encryption_key(privkey_b64):
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance, privkey_b64):
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def decrypt_client_balance(encrypted_data, privkey_b64):
    if encrypted_data == "0" or not encrypted_data:
        return 0
    
    if not encrypted_data.startswith("v2|"):
        privkey_bytes = base64.b64decode(privkey_b64)
        salt = b"octra_encrypted_balance_v1"
        key = hashlib.sha256(salt + privkey_bytes).digest() + hashlib.sha256(privkey_bytes + salt).digest()
        key = key[:32]
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < 32:
                return 0
            
            nonce = data[:16]
            tag = data[16:32]
            encrypted = data[32:]
            
            expected_tag = hashlib.sha256(nonce + encrypted + key).digest()[:16]
            if not hmac.compare_digest(tag, expected_tag):
                return 0
            
            decrypted = bytearray()
            key_hash = hashlib.sha256(key + nonce).digest()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_hash[i % 32])
            
            return int(decrypted.decode())
        except:
            return 0
    
    try:
        b64_data = encrypted_data[3:]
        raw = base64.b64decode(b64_data)
        
        if len(raw) < 28:
            return 0
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        key = derive_encryption_key(privkey_b64)
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return 0

def derive_shared_secret_for_claim(my_privkey_b64, ephemeral_pubkey_b64):
    sk = nacl.signing.SigningKey(base64.b64decode(my_privkey_b64))
    my_pubkey_bytes = sk.verify_key.encode()
    eph_pub_bytes = base64.b64decode(ephemeral_pubkey_b64)
    
    if eph_pub_bytes < my_pubkey_bytes:
        smaller, larger = eph_pub_bytes, my_pubkey_bytes
    else:
        smaller, larger = my_pubkey_bytes, eph_pub_bytes
    
    combined = smaller + larger
    round1 = hashlib.sha256(combined).digest()
    round2 = hashlib.sha256(round1 + b"OCTRA_SYMMETRIC_V1").digest()
    return round2[:32]

def decrypt_private_amount(encrypted_data, shared_secret):
    if not encrypted_data or not encrypted_data.startswith("v2|"):
        return None
    
    try:
        raw = base64.b64decode(encrypted_data[3:])
        if len(raw) < 28:
            return None
        
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return None

async def get_encrypted_balance():
    ok, result = await req_private(f"/view_encrypted_balance/{addr}")
    
    if ok:
        try:
            return {
                "public": float(result.get("public_balance", "0").split()[0]),
                "public_raw": int(result.get("public_balance_raw", "0")),
                "encrypted": float(result.get("encrypted_balance", "0").split()[0]),
                "encrypted_raw": int(result.get("encrypted_balance_raw", "0")),
                "total": float(result.get("total_balance", "0").split()[0])
            }
        except:
            return None
    else:
        return None

async def encrypt_balance(amount):
    enc_data = await get_encrypted_balance()
    if not enc_data:
        return False, {"error": "cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    new_encrypted_raw = current_encrypted_raw + int(amount * μ)
    
    encrypted_value = encrypt_client_balance(new_encrypted_raw, priv)
    
    data = {
        "address": addr,
        "amount": str(int(amount * μ)),
        "private_key": priv,
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req('POST', '/encrypt_balance', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def decrypt_balance(amount):
    enc_data = await get_encrypted_balance()
    if not enc_data:
        return False, {"error": "cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    if current_encrypted_raw < int(amount * μ):
        return False, {"error": "insufficient encrypted balance"}
    
    new_encrypted_raw = current_encrypted_raw - int(amount * μ)
    
    encrypted_value = encrypt_client_balance(new_encrypted_raw, priv)
    
    data = {
        "address": addr,
        "amount": str(int(amount * μ)),
        "private_key": priv,
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req('POST', '/decrypt_balance', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def get_address_info(address):
    s, t, j = await req('GET', f'/address/{address}')
    if s == 200:
        return j
    return None

async def get_public_key(address):
    s, t, j = await req('GET', f'/public_key/{address}')
    if s == 200:
        return j.get("public_key")
    return None

async def create_private_transfer(to_addr, amount):
    addr_info = await get_address_info(to_addr)
    if not addr_info or not addr_info.get("has_public_key"):
        return False, {"error": "Recipient has no public key"}
    
    to_public_key = await get_public_key(to_addr)
    if not to_public_key:
        return False, {"error": "Cannot get recipient public key"}
    
    data = {
        "from": addr,
        "to": to_addr,
        "amount": str(int(amount * μ)),
        "from_private_key": priv,
        "to_public_key": to_public_key
    }
    
    s, t, j = await req('POST', '/private_transfer', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def get_pending_transfers():
    ok, result = await req_private(f"/pending_private_transfers?address={addr}")
    
    if ok:
        transfers = result.get("pending_transfers", [])
        return transfers
    else:
        return []

async def claim_private_transfer(transfer_id):
    data = {
        "recipient_address": addr,
        "private_key": priv,
        "transfer_id": transfer_id
    }
    
    s, t, j = await req('POST', '/claim_private_transfer', data)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

def make_tx(to, amount, nonce, message=None):
    tx = {
        "from": addr,
        "to_": to,
        "amount": str(int(amount * μ)),
        "nonce": int(nonce),
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time()
    }
    if message:
        tx["message"] = message
    bl = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))
    sig = base64.b64encode(sk.sign(bl.encode()).signature).decode()
    tx.update(signature=sig, public_key=pub)
    return tx, hashlib.sha256(bl.encode()).hexdigest()

async def send_tx(tx):
    t0 = time.time()
    s, t, j = await req('POST', '/send-tx', tx)
    dt = time.time() - t0
    if s == 200:
        if j and j.get('status') == 'accepted':
            return True, j.get('tx_hash', ''), dt, j
        elif t.lower().startswith('ok'):
            return True, t.split()[-1], dt, None
    return False, json.dumps(j) if j else t, dt, j

async def show_wallet_info():
    try:
        nonce, balance = await get_state()
        enc_data = await get_encrypted_balance()
        
        print("\nWallet Information:")
        print(f"Address: {addr}")
        print(f"Public Key: {pub[:40]}...")
        print(f"Balance: {balance:.6f} OCT" if balance is not None else "Balance: ---")
        print(f"Nonce: {nonce}" if nonce is not None else "Nonce: ---")
        
        if enc_data:
            print(f"\nEncrypted Balances:")
            print(f"Public: {enc_data['public']:.6f} OCT")
            print(f"Encrypted: {enc_data['encrypted']:.6f} OCT")
            print(f"Total: {enc_data['total']:.6f} OCT")
        
        pending = await get_pending_transfers()
        if pending:
            print(f"\nPending Transfers to Claim: {len(pending)}")
    except Exception as e:
        print(f"\nError getting wallet info: {e}")

async def show_transaction_history():
    try:
        await get_history()
        if not h:
            print("\nNo transactions yet")
            return
        
        print("\nRecent Transactions:")
        print("Time     Type  Amount       Address")
        print("----------------------------------")
        
        for tx in sorted(h, key=lambda x: x['time'], reverse=True)[:10]:
            time_str = tx['time'].strftime('%H:%M:%S')
            direction = "IN " if tx['type'] == 'in' else "OUT"
            amount = f"{float(tx['amt']):>10.6f}"
            address = str(tx.get('to', '---'))[:20]
            status = "PEN" if not tx.get('epoch') else f"E{tx.get('epoch', 0)}"
            
            print(f"{time_str} {direction} {amount} {address} {status}")
    except Exception as e:
        print(f"\nError getting transaction history: {e}")

async def send_transaction():
    try:
        print("\nSend Transaction")
        to = input("Recipient address (or 'cancel'): ").strip()
        if to.lower() == 'cancel':
            return
        if not b58.match(to):
            print("Invalid address format!")
            return
        
        amount = input("Amount (OCT): ").strip()
        if not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
            print("Invalid amount!")
            return
        amount = float(amount)
        
        message = input("Message (optional, enter to skip): ").strip()
        if not message:
            message = None
        
        nonce, balance = await get_state()
        if nonce is None:
            print("Failed to get current nonce - check RPC connection")
            return
        
        if balance is None or balance < amount:
            print(f"Insufficient balance! ({balance:.6f if balance is not None else '---'} < {amount})")
            return
        
        fee = 0.001 if amount < 1000 else 0.003
        print(f"\nTransaction Summary:")
        print(f"Send: {amount:.6f} OCT to {to}")
        if message:
            print(f"Message: {message[:50]}{'...' if len(message) > 50 else ''}")
        print(f"Fee: {fee:.3f} OCT (Nonce: {nonce + 1})")
        
        confirm = input("\nConfirm transaction? [y/n]: ").strip().lower()
        if confirm != 'y':
            return
        
        print("Sending transaction...")
        tx, _ = make_tx(to, amount, nonce + 1, message)
        ok, tx_hash, dt, _ = await send_tx(tx)
        
        if ok:
            print(f"\n✓ Transaction accepted!")
            print(f"Hash: {tx_hash}")
            print(f"Time: {dt:.2f}s")
            h.append({
                'time': datetime.now(),
                'hash': tx_hash,
                'amt': amount,
                'to': to,
                'type': 'out',
                'ok': True,
                'msg': message
            })
        else:
            print(f"\n✗ Transaction failed!")
            print(f"Error: {tx_hash}")
    except Exception as e:
        print(f"\nError sending transaction: {e}")

async def multi_send():
    try:
        print("\nMulti-Send Transactions")
        recipients = []
        
        while True:
            print("\nAdd recipient (address amount) or 'done' to finish:")
            entry = input("> ").strip()
            if entry.lower() in ['done', '']:
                break
            
            parts = entry.split()
            if len(parts) != 2:
                print("Format: address amount")
                continue
            
            address, amount = parts
            if not b58.match(address):
                print("Invalid address format!")
                continue
            
            if not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
                print("Invalid amount!")
                continue
            
            recipients.append((address, float(amount)))
            print(f"Added: {address[:20]}... {amount} OCT")
        
        if not recipients:
            return
        
        total = sum(amount for _, amount in recipients)
        print(f"\nTotal to send: {total:.6f} OCT to {len(recipients)} addresses")
        
        nonce, balance = await get_state()
        if nonce is None:
            print("Failed to get current nonce!")
            return
        
        if balance is None or balance < total:
            print(f"Insufficient balance! ({balance:.6f if balance is not None else '---'} < {total})")
            return
        
        confirm = input("\nConfirm multi-send? [y/n]: ").strip().lower()
        if confirm != 'y':
            return
        
        print(f"\nSending {len(recipients)} transactions...")
        success, failed = 0, 0
        
        for i, (to, amount) in enumerate(recipients):
            print(f"[{i+1}/{len(recipients)}] Sending {amount:.6f} to {to[:20]}...", end=' ')
            tx, _ = make_tx(to, amount, nonce + 1 + i)
            ok, tx_hash, _, _ = await send_tx(tx)
            
            if ok:
                print("✓ Success")
                success += 1
                h.append({
                    'time': datetime.now(),
                    'hash': tx_hash,
                    'amt': amount,
                    'to': to,
                    'type': 'out',
                    'ok': True
                })
            else:
                print("✗ Failed")
                failed += 1
        
        print(f"\nCompleted: {success} successful, {failed} failed")
    except Exception as e:
        print(f"\nError in multi-send: {e}")

async def encrypt_balance_ui():
    try:
        print("\nEncrypt Balance")
        _, pub_bal = await get_state()
        enc_data = await get_encrypted_balance()
        
        if not enc_data:
            print("Cannot get encrypted balance info")
            return
        
        print(f"\nCurrent Balances:")
        print(f"Public: {pub_bal:.6f} OCT" if pub_bal is not None else "Public: ---")
        print(f"Encrypted: {enc_data['encrypted']:.6f} OCT")
        print(f"Total: {enc_data['total']:.6f} OCT")
        
        max_encrypt = enc_data['public_raw'] / μ - 1.0
        if max_encrypt <= 0:
            print("\nInsufficient public balance (need > 1 OCT for fees)")
            return
        
        print(f"\nMax encryptable: {max_encrypt:.6f} OCT")
        amount = input("Amount to encrypt: ").strip()
        
        if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
            return
        
        amount = float(amount)
        if amount > max_encrypt:
            print(f"Amount too large (max: {max_encrypt:.6f})")
            return
        
        confirm = input(f"\nEncrypt {amount:.6f} OCT? [y/n]: ").strip().lower()
        if confirm != 'y':
            return
        
        print("Encrypting balance...")
        ok, result = await encrypt_balance(amount)
        
        if ok:
            print("\n✓ Encryption submitted!")
            print(f"TX Hash: {result.get('tx_hash', 'unknown')}")
            print("Will process in next epoch")
        else:
            print(f"\n✗ Error: {result.get('error', 'unknown')}")
    except Exception as e:
        print(f"\nError encrypting balance: {e}")

async def decrypt_balance_ui():
    try:
        print("\nDecrypt Balance")
        _, pub_bal = await get_state()
        enc_data = await get_encrypted_balance()
        
        if not enc_data:
            print("Cannot get encrypted balance info")
            return
        
        print(f"\nCurrent Balances:")
        print(f"Public: {pub_bal:.6f} OCT" if pub_bal is not None else "Public: ---")
        print(f"Encrypted: {enc_data['encrypted']:.6f} OCT")
        print(f"Total: {enc_data['total']:.6f} OCT")
        
        if enc_data['encrypted_raw'] == 0:
            print("\nNo encrypted balance to decrypt")
            return
        
        max_decrypt = enc_data['encrypted_raw'] / μ
        print(f"\nMax decryptable: {max_decrypt:.6f} OCT")
        amount = input("Amount to decrypt: ").strip()
        
        if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
            return
        
        amount = float(amount)
        if amount > max_decrypt:
            print(f"Amount too large (max: {max_decrypt:.6f})")
            return
        
        confirm = input(f"\nDecrypt {amount:.6f} OCT? [y/n]: ").strip().lower()
        if confirm != 'y':
            return
        
        print("Decrypting balance...")
        ok, result = await decrypt_balance(amount)
        
        if ok:
            print("\n✓ Decryption submitted!")
            print(f"TX Hash: {result.get('tx_hash', 'unknown')}")
            print("Will process in next epoch")
        else:
            print(f"\n✗ Error: {result.get('error', 'unknown')}")
    except Exception as e:
        print(f"\nError decrypting balance: {e}")

async def private_transfer_ui():
    try:
        print("\nPrivate Transfer")
        enc_data = await get_encrypted_balance()
        
        if not enc_data or enc_data['encrypted_raw'] == 0:
            print("No encrypted balance available")
            print("Encrypt some balance first")
            return
        
        print(f"\nEncrypted balance: {enc_data['encrypted']:.6f} OCT")
        
        to_addr = input("\nRecipient address: ").strip()
        if not to_addr or not b58.match(to_addr):
            print("Invalid address")
            return
        
        if to_addr == addr:
            print("Cannot send to yourself")
            return
        
        print("Checking recipient...")
        addr_info = await get_address_info(to_addr)
        
        if not addr_info:
            print("Recipient address not found on blockchain")
            return
        
        if not addr_info.get('has_public_key'):
            print("Recipient has no public key")
            print("They need to make a transaction first")
            return
        
        print(f"\nRecipient balance: {addr_info.get('balance', 'unknown')}")
        
        amount = input("\nAmount: ").strip()
        if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
            return
        
        amount = float(amount)
        if amount > enc_data['encrypted']:
            print("Insufficient encrypted balance")
            return
        
        print(f"\nTransfer Summary:")
        print(f"Send {amount:.6f} OCT privately to {to_addr}")
        
        confirm = input("\nConfirm? [y/n]: ").strip().lower()
        if confirm != 'y':
            return
        
        print("Creating private transfer...")
        ok, result = await create_private_transfer(to_addr, amount)
        
        if ok:
            print("\n✓ Private transfer submitted!")
            print(f"TX Hash: {result.get('tx_hash', 'unknown')}")
            print(f"Recipient can claim in next epoch")
            print(f"Ephemeral key: {result.get('ephemeral_key', 'unknown')[:40]}...")
        else:
            print(f"\n✗ Error: {result.get('error', 'unknown')}")
    except Exception as e:
        print(f"\nError in private transfer: {e}")

async def claim_transfers_ui():
    try:
        print("\nClaim Private Transfers")
        print("Loading pending transfers...")
        
        transfers = await get_pending_transfers()
        
        if not transfers:
            print("No pending transfers")
            return
        
        print(f"\nFound {len(transfers)} claimable transfers:")
        print("ID  From                Amount         Epoch")
        print("-------------------------------------------")
        
        for i, t in enumerate(transfers[:10]):
            amount_str = "[encrypted]"
            
            if t.get('encrypted_data') and t.get('ephemeral_key'):
                try:
                    shared = derive_shared_secret_for_claim(priv, t['ephemeral_key'])
                    amt = decrypt_private_amount(t['encrypted_data'], shared)
                    if amt:
                        amount_str = f"{amt/μ:.6f} OCT"
                except:
                    pass
            
            print(f"[{i+1}] {t['sender'][:20]}... {amount_str:>14} ep{t.get('epoch_id', '?')}")
        
        if len(transfers) > 10:
            print(f"... and {len(transfers) - 10} more")
        
        choice = input("\nEnter number to claim (0 to cancel): ").strip()
        
        if not choice or choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(transfers):
                transfer = transfers[idx]
                transfer_id = transfer['id']
                
                print(f"\nClaiming transfer #{transfer_id}...")
                ok, result = await claim_private_transfer(transfer_id)
                
                if ok:
                    print("\n✓ Transfer claimed!")
                    print(f"Amount: {result.get('amount', 'unknown')}")
                    print("Your encrypted balance has been updated")
                else:
                    print(f"\n✗ Error: {result.get('error', 'unknown')}")
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid number")
    except Exception as e:
        print(f"\nError claiming transfers: {e}")

async def export_keys():
    try:
        print("\nExport Keys")
        print("\nCurrent wallet info:")
        print(f"Address: {addr}")
        nonce, balance = await get_state()
        print(f"Balance: {balance:.6f} OCT" if balance is not None else "Balance: ---")
        print(f"Nonce: {nonce}" if nonce is not None else "Nonce: ---")
        
        print("\nOptions:")
        print("1. Show private key")
        print("2. Save full wallet to file")
        print("3. Copy address to clipboard")
        print("0. Cancel")
        
        choice = input("\nChoice: ").strip()
        
        if choice == '1':
            print("\nPrivate key (keep secret!):")
            print(priv)
            print("\nPublic key:")
            print(pub)
            input("\nPress enter to continue...")
            
        elif choice == '2':
            filename = f"octra_wallet_{int(time.time())}.json"
            wallet_data = {
                'priv': priv,
                'addr': addr,
                'rpc': rpc
            }
            os.umask(0o077)
            with open(filename, 'w') as f:
                json.dump(wallet_data, f, indent=2)
            os.chmod(filename, 0o600)
            print(f"\nWallet saved to {filename}")
            print("Warning: File contains private key - keep safe!")
            input("\nPress enter to continue...")
            
        elif choice == '3':
            try:
                import pyperclip
                pyperclip.copy(addr)
                print("\nAddress copied to clipboard!")
            except:
                print("\nClipboard not available")
            input("\nPress enter to continue...")
    except Exception as e:
        print(f"\nError exporting keys: {e}")

def signal_handler(sig, frame):
    stop_flag.set()
    if session:
        asyncio.create_task(session.close())
    sys.exit(0)

async def main_menu():
    print("\nOctra Wallet - Console Interface")
    print("===============================")
    
    while not stop_flag.is_set():
        print("\nMain Menu:")
        print("1. Wallet Info")
        print("2. Transaction History")
        print("3. Send Transaction")
        print("4. Multi-Send")
        print("5. Encrypt Balance")
        print("6. Decrypt Balance")
        print("7. Private Transfer")
        print("8. Claim Transfers")
        print("9. Export Keys")
        print("0. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        try:
            if choice == '1':
                await show_wallet_info()
            elif choice == '2':
                await show_transaction_history()
            elif choice == '3':
                await send_transaction()
            elif choice == '4':
                await multi_send()
            elif choice == '5':
                await encrypt_balance_ui()
            elif choice == '6':
                await decrypt_balance_ui()
            elif choice == '7':
                await private_transfer_ui()
            elif choice == '8':
                await claim_transfers_ui()
            elif choice == '9':
                await export_keys()
            elif choice in ['0', 'q']:
                break
            else:
                print("Invalid choice")
        except Exception as e:
            print(f"Error: {e}")

async def main():
    global session
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if not load_wallet():
        sys.exit("[!] Error loading wallet.json")
    if not addr:
        sys.exit("[!] Wallet not configured")
    
    try:
        await main_menu()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if session:
            await session.close()
        executor.shutdown(wait=False)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)
    
    # Fix for Windows event loop
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("\nGoodbye!")
        os._exit(0)