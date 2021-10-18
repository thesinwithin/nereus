#!/usr/bin/python3
# Certificate uploador for PaloAlto Networks firewalls

from xml.etree import cElementTree as ElementTree
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from secrets import token_urlsafe
from collections import defaultdict
import requests
import yaml
import json
import time

# The following two lines should be deleted if you already have
# trusted the certificate currently running on the management interface
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

commit_id = 0  # commit job ID, used to check commit progress
pan_pem = b''  # Digital certificate and private key bundle
passphrase = token_urlsafe(23)  # this is the passphrase used to encrypt the privaate key

with open('nereus.yml', 'r') as cfg_yml:
    try:
        cfg = yaml.load(cfg_yml, Loader=yaml.FullLoader)
    except yaml.YAMLError as ex:
        print(f'[ERR]: Error loading configuration. Exception: {ex}')
        exit(127)


# Shamelessly stolen from StackOverflow
def etree_to_dict(t):
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {t.tag: {k: v[0] if len(v) == 1 else v
                     for k, v in dd.items()}}
    if t.attrib:
        d[t.tag].update(('@' + k, v)
                        for k, v in t.attrib.items())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
                d[t.tag]['#text'] = text
        else:
            d[t.tag] = text
    return d


def prepare_pem_file():
    print('[Step::PreparePEMFile]: Loading Private Key and Digital Certificates chain.')
    try:
        with open(cfg['certificate']['key'], "rb") as key_file:
            in_file = key_file.read()
    except IOError as e:
        print(f'[ERR]: Could not access file. Exception: {e}')
        exit(127)
    try:
        privkey = serialization.load_pem_private_key(in_file, password=None)
    except ValueError as e:
        print(f'[ERR]: Deserialization error. Exception: {e}')
        exit(127)
    print(f'[OK]: Private Key file "{cfg["certificate"]["key"]}" with {privkey.key_size} bits parsed.')
    enc_privkey = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    ).decode('utf-8')
    try:
        with open(cfg['certificate']['fullchain'], "rb") as key_file:
            in_file = key_file.read()
    except IOError as e:
        print(f'[ERR]: Error accessing {cfg["certificate"]["fullchain"]}. Exception: {e}')
        exit(127)
    certificates = []
    parse_started = False
    pem_content = ''
    for line in in_file.decode('utf-8').splitlines():
        if '-----BEGIN CERTIFICATE-----' in line and parse_started is False:
            pem_content += line
            parse_started = True
        elif '-----END CERTIFICATE-----' in line and parse_started is True:
            pem_content += line
            certificates.append(pem_content)
            pem_content = ''
            parse_started = False
        elif parse_started is True:
            pem_content += line
    for certificate in range(len(certificates)):
        try:
            cert = x509.load_pem_x509_certificate(certificates[certificate].encode('utf-8'))
        except ValueError as e:
            print(f'[ERR]: Error loading digital certificate in PEM format. Exception: {e}')
            exit(127)
        print(f'[OK]: Certificate with Subject {cert.subject.rfc4514_string()} and serial {cert.serial_number} parsed.')
    temp_certs = []
    for t_cert in certificates:
        t_cert = x509.load_pem_x509_certificate(t_cert.encode('utf-8'))
        temp_certs.append(t_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))
    pem_certs = ''.join(temp_certs)
    global pan_pem
    temp = ''.join([enc_privkey, pem_certs])
    pan_pem = temp
    print('[OK]: PEM file prepared successfuly.')


# Uploads the prepared bundle to the firewall
def upload_certificate():
    print('[Step::CertificateKeyUpload]: Uploading bundled digital certificate and private key.')
    req_params = {'key': cfg['api']['key'],
                  'type': 'import',
                  'category': 'keypair',
                  'certificate-name': cfg['certificate']['name'],
                  'format': 'pem',
                  'passphrase': passphrase
                  }
    files = {'file': pan_pem}
    r = requests.post(cfg['api']['mgt_url'], files=files, verify=False, params=req_params)
    if r.status_code != 200:
        print(f'[ERR]: Certificate upload failed. Server said {r.text}')
        exit(127)
    if r.status_code == 200:
        print('[OK]: Certificate and private key bundle uploaded successfuly.')


# Commits the configuration to the firewall
def commit_config():
    print('[Step::CommitConfiguration]: Commiting configuration to the firewall(s)')
    req_params = {'type': 'commit',
                  'cmd': '<commit></commit>'
                  }
    headers = {'X-PAN-KEY': cfg['api']['key'],
               'Content-Type': 'application/xml'
               }
    r = requests.get(cfg['api']['mgt_url'], headers=headers, params=req_params, verify=False)
    if r.status_code != 200:
        print('[ERR]: Error encountered commiting the configuration. Server said:')
        print(json.dumps(etree_to_dict(ElementTree.fromstring(r.text)), sort_keys=True, indent=4))
    else:
        print('[OK]: Configuration commited successfuly.')
        cid_temp = etree_to_dict(ElementTree.fromstring(r.text))
        global commit_id
        commit_id = cid_temp['response']['result']['job']


# Checks the commit progress
def check_commit_progress():
    req_params = {'type': 'op',
                  'cmd': f'<show><jobs><id>{commit_id}</id></jobs></show>'
                  }
    headers = {'X-PAN-KEY': cfg['api']['key'],
               'Content-Type': 'application/xml'
               }
    progress = 0
    print('[OK]: Commit progress: ', end='')
    while progress != 100:
        r = requests.get(cfg['api']['mgt_url'], headers=headers, verify=False, params=req_params)
        resp = json.loads(json.dumps(etree_to_dict(ElementTree.fromstring(r.text)), sort_keys=True, indent=4))
        if resp['response']['@status'] != 'success':
            raise Exception('ERR: Step [check_commit_progress] encountered an issue, details below\n', r.text)
        progress = int(resp['response']['result']['job']['progress'])
        print(f'...{progress}%', end='')
        if progress < 100:
            time.sleep(3)
        else:
            if progress == 100:
                print('')
                print('[OK]: Commit completed successfully.')


if __name__ == "__main__":
    prepare_pem_file()
    upload_certificate()
    commit_config()
    check_commit_progress()
