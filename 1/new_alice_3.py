import argparse
import logging
import socket

from common_3 import (JsonConnection, aes_decrypt, aes_encrypt,
                      generate_dh_keypair, is_generator, is_prime, shared_aes_key)

def run(addr, port, message):
    with socket.create_connection((addr, port), timeout=10) as conn:
        conn.settimeout(10)
        channel = JsonConnection(conn)
        logging.info('Alice connected to %s:%s', addr, port)

        request = {'opcode': 0, 'type': 'DH'}
        channel.send(request)
        logging.info('Sent: %s', request)

        response = channel.receive()
        logging.info('Received: %s', response)
        if response.get('opcode') != 1 or response.get('type') != 'DH':
            raise ValueError('Expected DH public key response')
        p = response['parameter']['p']
        g = response['parameter']['g']
        bob_public = response['public']

        if not (type(p) is int and 400 <= p <= 500 and is_prime(p)):
            error = {'opcode': 3, 'error': 'incorrect prime number'}
            channel.send(error)
            logging.error('Sent: %s', error)
            return
        if not is_generator(g, p):
            error = {'opcode': 3, 'error': 'incorrect generator'}
            channel.send(error)
            logging.error('Sent: %s', error)
            return

        private, public = generate_dh_keypair(p, g)
        key = shared_aes_key(bob_public, private, p)
        logging.info('DH parameters accepted: p=%s, g=%s', p, g)

        alice_public_message = {'opcode': 1, 'type': 'DH', 'public': public}
        channel.send(alice_public_message)
        logging.info('Sent Alice DH public key: %s', alice_public_message)

        encrypted_message = {'opcode': 2, 'type': 'AES', 'encryption': aes_encrypt(key, message)}
        channel.send(encrypted_message)
        logging.info('Sent AES-encrypted message: %s', encrypted_message)

        reply = channel.receive()
        logging.info('Received: %s', reply)
        if reply.get('opcode') != 2 or reply.get('type') != 'AES':
            raise ValueError('Expected AES-encrypted reply')
        print('Bob plaintext:', aes_decrypt(key, reply['encryption']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--addr', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--message', default='hello')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        run(args.addr, args.port, args.message)
    except (OSError, ConnectionError, ValueError, KeyError, TypeError) as exc:
        logging.error('Protocol III Alice failed: %s', exc)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
