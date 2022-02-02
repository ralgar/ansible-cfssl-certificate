#!/usr/bin/python

# Copyright: (c) 2022, Ryan Algar (https://github.com/ralgar/ansible-modules)
# GNU General Public License v3.0 (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: cfssl_certificate

short_description: Generates an SSL/TLS certificate from CFSSL API.

version_added: "0.1.1"

description:
    - The C(cfssl_certificate) module generates an SSL/TLS certificate using CFSSL.
    - The module can also create a certificate chain by providing the C(chain_path) parameter.

requirements:
    - cryptography >= 3.3.2

options:
    cert_path:
        description: Absolute path for the certificate file.
        required: true
        type: path
    cfssl_host:
        description: Hostname or IP address of the CFSSL API server.
        default: localhost
        type: str
    cfssl_port:
        description: Port number of the CFSSL API server.
        default: 8888
        type: str
    chain_path:
        description:
            - Absolute path for the certificate chain file.
            - If this value is not supplied, then no chain will be created.
        required: false
        type: path
    common_name:
        description: The commonName field of the certificate subject.
        required: true
        type: str
    hosts:
        description:
            - Valid hosts (Subject Alternative Names) for the certificate.
            - Can be an IP address, hostname, or FQDN.
        required: true
        type: list
        elements: str
    key_path:
        description: Absolute path for the private key file.
        required: true
        type: path
    names:
        description:
            - Key/Value pairs that will be present in the certificate's subject name field.
            - Possible and common values are:
            - "C" (Country Name) - A two-letter country abbreviation.
            - "ST" (State) - A full-length Province or State name.
            - "L" (Locality) - A full-length City or Region name.
            - "O" (Organization) - The full name of your organization.
            - "OU" (Organizational Unit) - An organizational identifier (ex. 'Webserver').
            - "E" (Email Address) - Email address to associate with the certificate.
        required: true
        type: dict
    profile:
        description: The CFSSL signing profile to use.
        required: true
        type: str

author:
    - Ryan Algar (@ralgar)
'''

EXAMPLES = r'''
- name: Generate a default certificate using a local CFSSL endpoint
  cfssl_certificate:
    cert_path: /var/pki/cert.pem
    key_path: /var/pki/key.pem
    common_name: My Certificate
    names:
      C: US
      ST: California
      L: San Francisco
      O: My HomeNet
      OU: Default Cert
    hosts:
      - default
      - default.home.internal
      - 192.168.1.50

- name: Generate a server certificate using a remote CFSSL endpoint
  cfssl_certificate:
    cfssl_host: pki.myorg.internal
    cert_path: /var/pki/cert.pem
    key_path: /var/pki/key.pem
    common_name: Server 1
    names:
      C: US
      ST: California
      L: San Francisco
      O: My Organization
      OU: Web Server
    hosts:
      - server1
      - server1.myorg.internal
      - 10.0.1.1

- name: Generate a client certificate using a remote CFSSL endpoint
  cfssl_certificate:
    cfssl_host: pki.myorg.internal
    cert_path: /var/pki/cert.pem
    key_path: /var/pki/key.pem
    common_name: Client 1
    names:
      C: US
      ST: California
      L: San Francisco
      O: My Organization
      OU: Client Machine
    hosts:
      - client1
      - client1.myorg.internal
      - 10.0.2.1
'''


import json
import os
import shutil
import requests

from cryptography import x509
from ansible.module_utils.basic import AnsibleModule


def compare_san(module_params, cert_object):
    '''
    Compare the Subject Alternative Name (SAN or 'hosts') between
    the Ansible module's input, and the existing certificate.
    '''

    # Get list of module input hosts
    input_san = module_params['hosts']

    # Get list of existing certificate 'SAN' values
    cert_san = []
    for attr in cert_object.extensions:
        if attr.oid._name == "subjectAltName":
            for value in attr.value:
                cert_san.append(str(value.value))

    # Compare module hosts with certificate hosts
    input_san.sort()
    cert_san.sort()

    if input_san == cert_san:
        return True

    return False


def compare_subject(module_params, cert_object):
    '''
    Compare the Subject information (or 'names') between the
    Ansible module's input, and the existing certificate.
    '''

    # Get dict of module input 'subject' attributes
    input_subject = module_params['names']
    input_subject.update({'CN': module_params['common_name']})

    # Get dict of existing certificate 'subject' attributes
    cert_subject = {}
    for attr in cert_object.subject:
        attr = attr.rfc4514_string().split('=')
        if attr[0] == '1.2.840.113549.1.9.1':
            cert_subject.update({'E': attr[1]})
        else:
            cert_subject.update({attr[0]: attr[1]})

    # Compare module subject with certificate subject
    if input_subject == cert_subject:
        return True

    return False


def request_cert():
    ''' Request a new certificate '''

    changed     = False
    cfssl_host  = module.params['cfssl_host']
    cfssl_port  = module.params['cfssl_port']
    profile     = module.params['profile']
    cert_path   = module.params['cert_path']
    key_path    = module.params['key_path']
    common_name = module.params['common_name']
    names       = module.params['names']
    hosts       = module.params['hosts']

    url = 'http://' + cfssl_host + ':' + cfssl_port + '/api/v1/cfssl/newcert'

    data = {
        'request': {
            'CN': common_name,
            'names': [names],
            'hosts': hosts,
        }
    }

    # If profile parameter is set, add it to the data dict
    if profile is not None:
        data.update({'profile': profile})

    # Request a certificate from the API
    response = requests.post(url, data=json.dumps(data)).json()

    # Try to write out the response components.
    try:
        with open(cert_path, 'w') as fd:
            fd.write(response['result']['certificate'])
        with open(key_path, 'w') as fd:
            fd.write(response['result']['private_key'])
        os.chmod(key_path, 0o600)
    except TypeError as fault:
        module.fail_json(
            msg='Unable to generate certificate!',
            exception=str(fault),
            response_code=response['success']
        )

    changed = True
    return changed


def request_chain():
    '''
    Create a certificate chain with
    the signer and endpoint certificates.
    '''

    cfssl_host  = module.params['cfssl_host']
    cfssl_port  = module.params['cfssl_port']
    cert_path   = module.params['cert_path']
    chain_path  = module.params['chain_path']

    base_url = 'http://' + cfssl_host + ':' + cfssl_port + '/api/v1/cfssl'

    data = {
        'label': 'default'
    }

    response = requests.post(base_url + '/info', data=json.dumps(data)).json()

    try:
        with open(chain_path, 'w') as f_bundle:
            f_bundle.write(response['result']['certificate'] + '\n')
            with open(cert_path, 'r') as f_cert:
                shutil.copyfileobj(f_cert, f_bundle)
    except TypeError as fault:
        module.fail_json(
            msg='Unable to get signer certificate!',
            exception=str(fault),
            response_code=response['success']
        )

    changed = True
    return changed


def main():
    '''
    Module variable declarations and main logic
    '''

    global module

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=dict(
            cfssl_host=dict(type='str',    default='localhost'),
            cfssl_port=dict(type='str',    default='8888'),
            profile=dict(type='str',       required=False),
            cert_path=dict(type='path',    required=True),
            key_path=dict(type='path',     required=True),
            chain_path=dict(type='path',   required=False),
            common_name=dict(type='str',   required=True),
            names=dict(type='dict',        required=True),
            hosts=dict(type='list',        required=True)
        ),
        supports_check_mode=True
    )

    cert_path    = module.params['cert_path']
    key_path     = module.params['key_path']
    chain_path   = module.params['chain_path']

    # If the cert already exists, compare it against input params.
    # Also, create only the bundle if needed
    if os.path.exists(cert_path) and os.path.exists(key_path):
        with open(cert_path, 'r') as fp:
            cert = x509.load_pem_x509_certificate(bytes(fp.read(), 'utf-8'))
        if compare_san(module.params, cert) and compare_subject(module.params, cert):
            if chain_path is not None and not os.path.exists(chain_path):
                if request_chain():
                    result['changed']=True
            module.exit_json(**result)

    # If we haven't exited by this point, generate a new cert
    # TODO: Ensure module check is implemented properly
    if not module.check_mode:
        if request_cert():
            result['changed']=True
        if chain_path is not None:
            if request_chain():
                result['changed']=True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
