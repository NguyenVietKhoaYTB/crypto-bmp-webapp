# crypto_utils.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    if not data:
        return data
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        # Không hợp lệ -> trả về nguyên vẹn (tránh crash)
        return data
    return data[:-padding_len]

def normalize_key(key_input: str) -> bytes:
    """
    Chấp nhận:
      - hex string: "001122..." (độ dài 32/48/64 hex)
      - plain text: 'mysecret' -> sẽ encode và pad/truncate để được 16 bytes (AES-128) mặc định
    """
    if not key_input:
        raise ValueError("Key rỗng")
    # nếu có ký tự hex (0-9a-f) và độ dài chẵn, thử decode hex
    try:
        if all(c in "0123456789abcdefABCDEF" for c in key_input) and len(key_input) % 2 == 0:
            b = bytes.fromhex(key_input)
            if len(b) in (16, 24, 32):
                return b
            # nếu khác kích thước hợp lệ thì pad/truncate
    except Exception:
        pass
    # else: treat as text
    b = key_input.encode('utf-8')
    if len(b) <= 16:
        return b.ljust(16, b'\0')
    elif len(b) <= 24:
        return b[:24] if len(b) >= 24 else b.ljust(24, b'\0')
    else:
        return b[:32]  # default truncate to 32 (AES-256)

def normalize_iv(iv_input: str) -> bytes:
    """
    Nếu iv_input là hex -> decode; nếu rỗng -> generate None caller sẽ sinh tự động.
    """
    if not iv_input:
        return None
    if all(c in "0123456789abcdefABCDEF" for c in iv_input) and len(iv_input) % 2 == 0:
        return bytes.fromhex(iv_input)
    # else treat as ascii
    b = iv_input.encode('utf-8')
    return b[:16].ljust(16, b'\0')

def get_cipher_for_encrypt(mode: str, key: bytes, iv: bytes = None):
    mode = mode.upper()
    if mode == "ECB":
        return AES.new(key, AES.MODE_ECB)
    if mode == "CBC":
        if iv is None:
            iv = get_random_bytes(16)
        return AES.new(key, AES.MODE_CBC, iv=iv)
    if mode == "CFB":
        if iv is None:
            iv = get_random_bytes(16)
        return AES.new(key, AES.MODE_CFB, iv=iv)
    if mode == "OFB":
        if iv is None:
            iv = get_random_bytes(16)
        return AES.new(key, AES.MODE_OFB, iv=iv)
    if mode == "CTR":
        # For CTR we will use iv as nonce (can be shorter). If iv None, generate 8-byte nonce.
        if iv is None:
            nonce = get_random_bytes(8)
        else:
            nonce = iv
        return AES.new(key, AES.MODE_CTR, nonce=nonce)
    raise ValueError("Chế độ không được hỗ trợ")

def get_cipher_for_decrypt(mode: str, key: bytes, iv: bytes = None):
    # For PyCryptodome decrypt uses same initialization arguments as encrypt.
    return get_cipher_for_encrypt(mode, key, iv)

def encrypt_bytes(data: bytes, key_input: str, mode: str, iv_input: str = None):
    key = normalize_key(key_input)
    iv = normalize_iv(iv_input)
    cipher = get_cipher_for_encrypt(mode, key, iv)
    if mode.upper() in ("ECB", "CBC"):
        data_padded = pad(data)
        ct = cipher.encrypt(data_padded)
    else:
        ct = cipher.encrypt(data)
    # return ciphertext and the iv/nonce actually used (so caller có thể lưu để giải mã)
    actual_iv = None
    if mode.upper() == "ECB":
        actual_iv = None
    elif mode.upper() == "CTR":
        actual_iv = cipher.nonce
    else:
        actual_iv = cipher.iv
    return ct, actual_iv

def decrypt_bytes(ciphertext: bytes, key_input: str, mode: str, iv_input: str = None):
    key = normalize_key(key_input)
    iv = normalize_iv(iv_input)
    cipher = get_cipher_for_decrypt(mode, key, iv)
    if mode.upper() in ("ECB", "CBC"):
        decrypted = cipher.decrypt(ciphertext)
        try:
            decrypted = unpad(decrypted)
        except Exception:
            pass
    else:
        decrypted = cipher.decrypt(ciphertext)
    return decrypted
