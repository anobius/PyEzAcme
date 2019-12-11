#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
@note: Easy-Automatic Certificate Management Environment v2 (ACMEv2)

References:
    Automatic Certificate Management Environment (ACME):
        https://tools.ietf.org/html/draft-ietf-acme-acme-09
    JSON Web Key (JWK) Thumbprint:
        https://tools.ietf.org/html/draft-ietf-jose-jwk-thumbprint-08
    JSON Web Signature (JWS):
        https://tools.ietf.org/html/rfc7515
    Secure Hash Standard (SHS), FIPS 180-4:
        https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf
'''

import binascii
import json
import hashlib
import copy
import requests
import base64
import time
import threading
import random
from OpenSSL import crypto

from easy_crypto import *


CA = "https://acme-v02.api.letsencrypt.org"


RANDOMIZATION_FACTOR = 60;
MAX_VALIDATION_POLL_COUNT = 20;

# acme specification section 6.1. should comply with RFC4648
def _b64e(b):
    return base64.urlsafe_b64encode(b).replace("=", "")

def RAND():
    return random.random() * RANDOMIZATION_FACTOR;

def _getstringbetweentwostrings(body, string1, string2):
    # offset1 = body.find(string1) + len(string1);
    offset1 = body.find(string1);
    if offset1 == -1:
        return ('', offset1);
    offset1 += len(string1);
    offset2 = body[offset1:].find(string2) + offset1;
    rVal = body[offset1:offset2].strip();
    return rVal, offset2 if rVal else -1;


def getChallengeAuth(authorization_obj):
    '''
    Helper function: Returns the required TXT records per domain given an authorization object
    :param authorization_obj:
    :return: dictionary of {domain: [chauth]}
    '''
    rVal = dict();
    for i in authorization_obj['challenges']:
        if i not in rVal:
            rVal[i] = list();
        for j in authorization_obj['challenges'][i]:
            rVal[i].append(j[3]);
    return rVal;


class v1(object):
    def __init__(self, account_key_file, timeout=None):
        self.__t = timeout;
        self.__crypto_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(account_key_file).read());

        e, n = getExponentModuloPair(self.__crypto_privkey)
        n_hexd = binascii.unhexlify("%x" % n);  # binascii.unhexlify(hex(n)[2:-1]);
        hex_exp = "%x" % e;
        self.__header = {
            "alg": "RS256",
            "jwk": {
                "e": _b64e(binascii.unhexlify(("0" + hex_exp) if len(hex_exp) % 2 else hex_exp)),
                "kty": "RSA",
                "n": _b64e(n_hexd)
            }
        }

        jwk_json = json.dumps(self.__header['jwk'], sort_keys=True, separators=(',', ':'))
        self.__jwk_thumbprint = _b64e(hashlib.sha256(jwk_json).digest())

        # REGISTER
        test_register_payload = {
            "resource": "new-reg",
            "agreement": json.loads(requests.get(CA + "/directory", timeout=self.__t).content.decode('utf8'))['meta'][
                'terms-of-service'],
        }
        print self.__sendSignedRequest(CA + '/acme/new-reg', test_register_payload);

    # API COMMUNICATIONS ALWAYS SIGNED WITH YOUR ACCOUNT(PRIVATE KEY)
    def __sendSignedRequest(self, url, payload):
        payload = _b64e(json.dumps(payload));
        header_info = copy.deepcopy(self.__header);
        # retrieve nonce. 1 request = 1 unique nonce
        header_info["nonce"] = requests.get(CA + "/directory", timeout=self.__t).headers['Replay-Nonce'];
        header_info = _b64e(json.dumps(header_info));

        signature = _b64e(crypto.sign(self.__crypto_privkey, "%s.%s" % (header_info, payload), "sha256"));
        data = {
            "header": self.__header,
            "protected": header_info,
            "payload": payload,
            "signature": signature
        };
        print json.dumps(data, indent=4)
        response = requests.post(url, json=data, timeout=self.__t);
        print response.headers;
        return response.status_code, response.headers, response.content;

    def finalize(self, CSR_PEM):
        '''
        Retrieve certificate from CA on successful validation
        :param CSR_PEM: CSR containing all validated domains
        :param authorization_obj: unnecessary on v1
        :return: dictionary containing PEM String of signed certificate and status
        '''
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, CSR_PEM);
        DER_STRING = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr);
        payload = {
            "resource": "new-cert",
            "csr": _b64e(DER_STRING)
        }
        code, headers, result = self.__sendSignedRequest(CA + "/acme/new-cert", payload)
        # todo: read response headers, follow for links to other required certificates for chain
        try:
            cert_der = crypto.load_certificate(crypto.FILETYPE_ASN1, result)
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_der)

            for i in headers['Link'].split(','):
                cert_der = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                                   requests.get(_getstringbetweentwostrings(i, '<', '>')[0],
                                                                timeout=self.__t).content
                                                   );
                cert_pem += "\n%s" % crypto.dump_certificate(crypto.FILETYPE_PEM, cert_der);
            return (True, cert_pem)
            # return cert_pem;
        except:
            return (False, json.loads(result)["detail"]);

    def validateDNS(self, authorization_obj):
        '''
        Signals the CA that we are ready for DNS validation
        :param authorization_obj:
        :return: tuple of (validation status, error message if exists)
        '''
        challenge_url_list = list()
        if authorization_obj['validity']:
            for i in authorization_obj['challenges']:
                for j in authorization_obj['challenges'][i]:
                    challenge_url_list.append(j[0]);
                    key_auth = j[2];
                    payload = {
                        "resource": "challenge",
                        "keyAuthorization": key_auth,
                    }
                    code, headers, result = self.__sendSignedRequest(j[0], payload)
                    print "validateDNS: (%s) %s" % (code, result)
            # todo: poll status (on result['url'])
            for i in challenge_url_list:
                while True:
                    res = json.loads(requests.get(i, timeout=self.__t).content);
                    if res['status'] == 'valid':
                        break;
                    elif res['status'] == 'invalid':
                        authorization_obj['validity'] = False;
                        return False, res['error']['detail'];
                    time.sleep(1);
            return True, ""
        return False, "Order invalidated"

    def applyForCertificate(self, CSR_PEM):
        '''
        :param CSR_PEM: CSR PEM string
        :return: authorization object
        '''
        # dom_csr, dom_key = generate_csr_key_pair(CN=CN);

        rVal = {
            "finalize_url": None,
            "validity": True,
            "challenges": dict(),
        }
        for i in get_csr_domains_from_pem(CSR_PEM):
            # for authurl in authurls:
            code, headers, result = self.__sendSignedRequest(CA + "/acme/new-authz", {
                "resource": "new-authz",
                "identifier": {"type": "dns", "value": i},
            })
            authz_results = json.loads(result);
            print "authz response: %s" % (authz_results,);
            if "challenges" not in authz_results:
                del rVal['challenges'];
                rVal['validity'] = False;
                rVal['message'] = authz_results['detail']
                return rVal;
            challenges = authz_results["challenges"];

            dns_challenge_url = None;
            dns_challenge_token = None;
            for i in challenges:
                if i["type"] == "dns-01" and i['status'] != 'valid':
                    dns_challenge_token = i["token"];
                    dns_challenge_url = i["uri"];
            print "Challenge token: %s for %s" % (dns_challenge_token, dns_challenge_url);
            if dns_challenge_token and dns_challenge_url:
                # compute key auth, as per ietf acme draft section 8.1
                key_auth = dns_challenge_token + "." + self.__jwk_thumbprint;
                # print key_auth
                dom_pri = authz_results["identifier"]["value"];
                if dom_pri not in rVal["challenges"]:
                    rVal["challenges"][dom_pri] = list()
                challenge_auth = _b64e(hashlib.sha256(key_auth).digest());
                rVal["challenges"][dom_pri].append(
                    (dns_challenge_url, None, key_auth, challenge_auth));
        return rVal;

class v2(object):
    def __JWS_SEND(self, url, header_info, payload):
        payload = _b64e(json.dumps(payload));
        while True:
            header_info['nonce'] = self.__tlocal.nonce if 'nonce' in dir(self.__tlocal) else requests.get(CA + "/acme/new-nonce", timeout=self.__t).headers['Replay-Nonce']
            headerInfo = _b64e(json.dumps(header_info));

            signature = _b64e(crypto.sign(self.__crypto_privkey, "%s.%s" % (headerInfo, payload), "sha256"));
            data = {
                "protected": headerInfo,
                "payload": payload,
                "signature": signature
            };

            rVal = requests.post(url, json=data, headers={"Content-Type": "application/jose+json"}, timeout=self.__t);


            #check HTTP Layer before checking Application variables
            self.__tlocal.nonce = rVal.headers["Replay-Nonce"];


            #if rVal.status_code == 429: #if request rate-limited
            #    tSleep = RAND();
            #    print rVal.content;
            #    print "Too many requests, retrying in %.2f" % tSleep;
            #    time.sleep(tSleep);
            #    continue;

            #Continue to application (boulder)
            ###Validate boulder response
            if 'error:badNonce' in rVal.content:
                print "badNonce obtained for %s, retrying.." % header_info['nonce']
                time.sleep(1);
            elif rVal.status_code == 500:
                print "BOULDER INTERNAL ERROR (%s):\n%s" % (url,rVal.content);
                time.sleep(1);
            else:
                return rVal;

    def __signedRequestKID(self, url, payload):
        # ietf acme draft section 6.2, for queries that aren't account-related or certificate revocation-related
        header_info = {
            "alg": "RS256",
            "kid": self.__kid,
            "url": url,
        }
        response = self.__JWS_SEND(url, header_info, payload)
        return response.status_code, response.headers, response.content;

    def __signedRequestJWK(self, url, payload):
        # ietf acme draft section 6.2, for account-related queries and certificate revocation
        header_info = {
            "alg": "RS256",
            "jwk": self.__jwk,
            "url": url,
        }
        response = self.__JWS_SEND(url, header_info, payload);
        return response.status_code, response.headers, response.content;

    def __init__(self, account_key_file, timeout=None):
        '''
        ACME v2 endpoint invoker
        :param account_key_file: PEM File to be related to your account
        '''
        self.__tlocal = threading.local();
        self.__t = timeout;
        self.__crypto_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(account_key_file).read());

        # CACHE ACCOUNT KEY
        e, n = getExponentModuloPair(self.__crypto_privkey)
        n_hexd = binascii.unhexlify("%x" % n);
        hex_exp = "%x" % e;

        #Save JSON Web-key
        self.__jwk = {
            "e": _b64e(binascii.unhexlify(("0" + hex_exp) if len(hex_exp) % 2 else hex_exp)), #pubkey exponent
            "kty": "RSA", #key encryption type
            "n": _b64e(n_hexd) #pubkey modulus
        }

        # ietf jose jwk thumbprint draft section 3.3, ordered "lexicographically" (omg werd?)
        jwk_json = json.dumps(self.__jwk, sort_keys=True, separators=(',', ':'))
        self.__jwk_thumbprint = _b64e(hashlib.sha256(jwk_json).digest())

        # REGISTER, SAVE KID (Url retrieved from POSTing the registration (ietf acme draft section 6.2)
        test_register_payload = {
            "termsOfServiceAgreed": True,
        }
        self.__kid = self.__signedRequestJWK(CA + '/acme/new-acct', test_register_payload)[1]['Location'];


    def finalize(self, CSR_PEM, authorization_obj):
        '''
        Retrieve certificate from CA on successful validation
        :param CSR_PEM: CSR containing all validated domains
        :param authorization_obj:
        :return: PEM String of signed certificate. Null on failure
        '''
        finalize_url = authorization_obj['finalize_url'];
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, CSR_PEM);
        DER_STRING = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr);
        payload = {
            "csr": _b64e(DER_STRING)
        }
        code, headers, result = self.__signedRequestKID(finalize_url, payload)
        result = json.loads(result);
        if result['status'] == 'valid':
            #return requests.get(result['certificate'], timeout=self.__t).content;
            return (True,requests.get(result['certificate'], timeout=self.__t).content);
        else:
            print "Finalization response: %s" % result;
            return (False,result["detail"]);

    def validateDNS(self, authorization_obj):
        '''
        Signals the CA that we are ready for DNS validation
        :param authorization_obj:
        :return: tuple of (validation status, error message if exists)
        '''
        challenge_url_list = list()
        if authorization_obj['validity']:
            for i in authorization_obj['challenges']:
                for j in authorization_obj['challenges'][i]:
                    challenge_url_list.append(j[0]);
                    key_auth = j[2];
                    payload = {
                        "keyAuthorization": key_auth,
                    }
                    code, headers, result = self.__signedRequestKID(j[0], payload)
                    print "validateDNS: (%s) %s" % (code, result)
            # todo: poll status (on result['url'])
            for i in challenge_url_list:
                j=0;
                while True:
                    res = json.loads(requests.get(i, timeout=self.__t).content);
                    if res['status'] == 'valid':
                        break;
                    elif res['status'] == 'invalid':
                        authorization_obj['validity'] = False;
                        return False, res['error']['detail'];
                    j+=1;
                    if j > MAX_VALIDATION_POLL_COUNT: return False, "Excessive retry count, unknown failure"
                    time.sleep(1);
            return True, ""
        return False, "Order invalidated"

    def deactivateAuthorization(self, authorization_obj):
        '''
        deactivate all authz from an order
        :param authorization_obj:
        :return: todo
        '''
        for i in authorization_obj['challenges']:
            for j in authorization_obj['challenges'][i]:
                payload = {
                    "status": "deactivated",
                }
                code, headers, result = self.__signedRequestKID(j[1], payload)
                print "Authorization deactivation (%s): %s" % (code, result);

    def revoke(self, certSignedDER, reason=None):
        '''
        Queue this certificate for the certificate revocation list
        :param certSignedDER: bytearray of a certificate in DER format
        :param reason: reason for the revocation
        :return: True on success, otherwise False
        '''
        payload = {
            "certificate" : _b64e(certSignedDER)
        };
        if reason:
            payload['reason'] = reason;
        code, headers, result = self.__signedRequestKID(CA + "/acme/revoke-cert", payload);
    #    print code, result
        return True if code == 200 else False;


    def applyForCertificate(self, CSR_PEM):
        '''
        Apply for a signed certificate. Uses DNS for validation.
        :param CSR_PEM: CSR PEM string
        :return: authorization object. Contains information on the requirements for the domain to be successfully validated.
        '''

        code, headers, result = self.__signedRequestKID(CA + "/acme/new-order", {
            "identifiers": [{"type": "dns", "value": i} for i in get_csr_domains_from_pem(CSR_PEM)],
            # "notBefore" : '2018-02-09T22:05:18Z',
            # "notAfter" : '2018-02-09T23:05:18Z',
        })
        print "New-order (%s): %s" % (code, result)
        result = json.loads(result);

        #check if error (*)
        if 'detail' in result:
            rVal = dict();
            rVal['validity'] = False;
            rVal['message'] = result['detail']
            return rVal;

        authurls = result['authorizations'];
        rVal = {
            "finalize_url": result['finalize'],
            "validity": True,
            "challenges": dict(),
        }
        for authurl in authurls:
            print "Authz url: %s" % authurl;
            authz_results = json.loads(requests.get(authurl, timeout=self.__t).content);
            print "Authz content: %s" % authz_results;
            if authz_results['status'] == 'pending':
                challenges = authz_results["challenges"];

                dns_challenge_url = None;
                dns_challenge_token = None;
                for i in challenges:
                    if i["type"] == "dns-01":
                        dns_challenge_token = i["token"];
                        dns_challenge_url = i["url"];
                if not dns_challenge_url and not dns_challenge_token:
                    print "missing dns-01 challenge"
                    return;
                print "Challenge token: %s for %s" % (dns_challenge_token, dns_challenge_url);

                # compute key auth, as per ietf acme draft section 8.1
                key_auth = dns_challenge_token + "." + self.__jwk_thumbprint;
                # print key_auth
                dom_pri = authz_results["identifier"]["value"];
                challenge_auth = _b64e(hashlib.sha256(key_auth).digest());
                if dom_pri not in rVal["challenges"]:
                    rVal["challenges"][dom_pri] = list()
                rVal["challenges"][dom_pri].append((dns_challenge_url, authurl, key_auth, challenge_auth));
        return rVal;

