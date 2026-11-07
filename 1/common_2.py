import base64
import json
import secrets
from math import gcd

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 소수 판별
def is_prime(n):
    if type(n) is not int or n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# rsa 키 생성하기
def generate_rsa_key():
    primes = [n for n in range(400, 501) if is_prime(n)]
    p, q = secrets.SystemRandom().sample(primes, 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e = secrets.randbelow(n - 2) + 2
        if gcd(e, phi) == 1:
            break
    d = pow(e, -1, phi)
    return n, e, d

# 공개 키 n,e 사전 검증 안전한가?
def validate_rsa_public(n, e):
    if type(n) is not int or type(e) is not int:
        raise ValueError('RSA public key must contain integers')
    if not (400 * 400 <= n <= 500 * 500 and 1 < e < n):
        raise ValueError('Invalid RSA public key range')

# aes 키 암호화 (앨리스) C=M^d (mod n)
# pow 함수를 이용해서 mod 한 결과값 32개 리스트 리턴해서 보내기
def encrypt_aes_key(key, n, e):
    if len(key) != 32:
        raise ValueError('AES-256 requires a 32-byte key')
    return [pow(value, e, n) for value in key]

# aes 키 복호화 (밥) M = C^d (mod n)
# 앨리스가 보낸 리스트를 n,d로 풀고 원래의 aes 키로 되돌리기
def decrypt_aes_key(values, n, d):
    if not isinstance(values, list) or len(values) != 32:
        raise ValueError('encrypted_key must be a list of 32 integers')
    if any(type(value) is not int or not (0 <= value < n) for value in values):
        raise ValueError('Invalid RSA ciphertext entry')
    decrypted = [pow(value, d, n) for value in values]
    if any(not (0 <= value <= 255) for value in decrypted):
        raise ValueError('RSA-decrypted key byte out of range')
    return bytes(decrypted)

# 실제 암호화 단계 data를 암호화 키와 ecb를 사용해서 암호문으로 바꾸기
# 암호화된 데이터는 깨져서 보이니까 텍스트(base64)로 인코딩
def aes_encrypt(key, message):
    data = pad(message.encode('utf-8'), 16)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(data)
    return base64.b64encode(encrypted).decode('ascii')

# 실제 복호화 단계 base64 --> 바이너리 텍스트 --> aes 키로 복호화 --> 가짜 데이터 제거(unpad) --> 원래 텍스트로 되돌리기
def aes_decrypt(key, encoded):
    raw = base64.b64decode(encoded, validate=True)
    data = AES.new(key, AES.MODE_ECB).decrypt(raw)
    return unpad(data, 16).decode('utf-8')

# 메세지가 쪼개져서 왔을 때 모아서 읽어주는 역할
class JsonConnection:
    """Read successive JSON objects without assuming a TCP packet boundary."""
    def __init__(self, sock):
        self.sock = sock
        self.buffer = ''
        self.decoder = json.JSONDecoder()

    def send(self, message):
        self.sock.sendall(json.dumps(message, ensure_ascii=True).encode('ascii'))

    def receive(self):
        while True:
            clean = self.buffer.lstrip()
            try:
                value, end = self.decoder.raw_decode(clean)
            except json.JSONDecodeError:
                piece = self.sock.recv(4096)
                if not piece:
                    raise ConnectionError('Peer closed connection before a complete JSON message')
                self.buffer += piece.decode('ascii')
                if len(self.buffer) > 100000:
                    raise ValueError('JSON message too large')
                continue
            if not isinstance(value, dict):
                raise ValueError('Expected a JSON object')
            self.buffer = clean[end:]
            return value



