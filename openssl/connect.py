#!/usr/bin/env python3

import requests, OpenSSL, time
from datetime import datetime as dt
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

CLIENT_CERT_PATH = './cert/client-cert.pem'
CLIENT_KEY_PATH = './cert/client-key.pem'
ROOT_CA_PATH = './cert/root-ca.pem'
SERVER_CERT_PATH= './cert/server-cert.pem'

session = requests.Session()
session.cert = (CLIENT_CERT_PATH, CLIENT_KEY_PATH)
session.verify = ROOT_CA_PATH

enddate = None
with open(SERVER_CERT_PATH, 'rb') as file:
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, file.read())
    enddate  = dt.strptime(str(cert.get_notAfter())[2:16],'%Y%m%d%H%M%S')

url = 'https://localhost:8443/'
while True:
    print('{} is the expiration date of a server certificate'.format(enddate))
    print('{}: Connecting to a server running on {}'.format(dt.utcnow().replace(microsecond=0), url))

    try:
        response = session.get(url=url)
        print('Succeeded to connect a server')
        print(response.text)
    except Exception as e:
        print('Failed to connect a server')
        print(e)
        break
    print()
    print('Waiting for 1 min to connect a server ...')
    time.sleep(60)
