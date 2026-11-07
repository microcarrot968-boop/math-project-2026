import socket
import threading
import argparse
import logging
import json
import secrets
from math import gcd

# bob은 서버 역할. bob.listen() bob.accept() 로 상대방 연결 받기
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

def generate_rsa_key():
    primes = [n for n in range(400, 501) if is_prime(n)]
    print("Available primes: ", primes)
    p, q = secrets.SystemRandom().sample(primes, 2)
    phi = (p-1)*(q-1)
    n = p * q

    while True:
        e = secrets.randbelow(n-2)+2
        if gcd(e, phi) == 1:
            break

    d = pow(e, -1, phi)
    return p, q, e, d


def handler(conn):
    with conn:
        try:
            conn.settimeout(10)
            rbytes = conn.recv(4096)
            if not rbytes:
                return

            rjs = rbytes.decode("ascii")
            logging.info("[*] Received: %s", rjs)
            rmsg = json.loads(rjs)

# alice에게서 요청 메시지 받으면 generate_rsa_key() 호출해서 p,q,e,d를 만들고 json형식으로 alice에게 보냄 --> alice는 밥에게서 받은 걸 소수 판별하고 검증하는 구조
            if rmsg.get("opcode") != 0 or rmsg.get("type") != "RSAKey":
                logging.warning("Unexpected request: %s", rmsg)
                return

            p, q, e, d = generate_rsa_key()
            smsg = {
                "opcode": 0,
                "type": "RSAKey",
                "private": d,
                "public": e,
                "parameter": {"p": p, "q": q},
            }
            sjs = json.dumps(smsg)
            conn.sendall(sjs.encode("ascii"))
            logging.info("[*] Sent: %s", sjs)
            
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logging.error("Protocol I failed: %s", exc)

# 지정 포트 열고 24시간 대기. 누군가 접속하면 handler한테 보내줌
def run(addr, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob:
        bob.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bob.bind((addr, port))
        bob.listen(10)
        logging.info("[*] Bob is listening on {}:{}".format(addr, port))

        while True:
            conn, info = bob.accept()
            logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))
            conn_handle = threading.Thread(target=handler, args=(conn,), daemon=True)
            conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log.upper())
    run(args.addr, args.port)


if __name__ == "__main__":
    main()

