import socket
import argparse
import logging
import json
from math import gcd

# n 소수 판별 (p,q 이용해서 키 생성)
def is_prime(n):
    if not isinstance(n, int) or isinstance(n, bool) or n < 2:
        return False # 정수나, 1보다 크지 않을 때 소수 아님
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False # i로 나눴을 때 나누어 떨어지면 i라는 약수 가짐
    return True

# p,q,e,d 올바르게 생성되었는지 검증
def verify_rsa_key(p, q, e, d):
    if not all(type(x) is int for x in (p, q, e, d)):
        return False # 정수여야 함
    if not (400 <= p <= 500 and 400 <= q <= 500):
        return False # 400-500 구간
    if not is_prime(p) or not is_prime(q) or p == q:
        return False # 소수이고 서로 달라야함
    phi = (p - 1) * (q - 1) # euler's phi function
    return 1 < e < p * q and d > 0 and gcd(e, phi) == 1 and (e * d) % phi == 1 # e와 phi는 서로소이며, d가 e의 모듈러 역원이어야함


def run(addr, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect((addr, port))
        logging.info("Alice is connected to {}:{}".format(addr, port))

        smsg = {"opcode": 0, "type": "RSAKey"}
        sjs = json.dumps(smsg)
        conn.sendall(sjs.encode("ascii"))
        logging.info("[*] Sent: {}".format(sjs))

        # Protocol I only expects one small JSON reply.
        rbytes = conn.recv(4096)
        if not rbytes:
            raise ConnectionError("Bob closed the connection without a response")
        rjs = rbytes.decode("ascii")
        logging.info("[*] Received: {}".format(rjs))
        rmsg = json.loads(rjs)

        if rmsg.get("opcode") != 0 or rmsg.get("type") != "RSAKey":
            raise ValueError("Unexpected protocol response")

        params = rmsg["parameter"]
        p, q = params["p"], params["q"]
        e, d = rmsg["public"], rmsg["private"]

        print("p = {}, q = {}".format(p, q))
        print("Public key (e) = {}".format(e))
        print("Private key (d) = {}".format(d))
        print("p is prime: {}".format(is_prime(p)))
        print("q is prime: {}".format(is_prime(q)))
        print("RSA keypair is correct: {}".format(verify_rsa_key(p, q, e, d)))


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log.upper())
    try:
        run(args.addr, args.port)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        logging.error("Protocol I failed: %s", exc)


if __name__ == "__main__":
    main()

