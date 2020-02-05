#!/usr/bin/env python
#-*- coding: utf-8 -*-

import string

from OpenSSL import crypto


def get_csr_domains_from_pem(csr_pem):
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,csr_pem);
    domains = [csr.get_subject().CN];
    for i in csr.get_extensions():
        if i.get_short_name() == 'subjectAltName':
            for j in i.get_data().split('\x82')[1:]:
                if all(ch in string.printable for ch in j[1:]): #hotfix for some unknown characters I haven't got around into yet
                    domains.append(j[1:])
    return domains;


def getExponentModuloPair(crypto_pkey):
    c_key = crypto_pkey.to_cryptography_key();
    pub_num = c_key.private_numbers().public_numbers
    e = pub_num.e;
    n = pub_num.n;
    return e,n

def generate_csr_key_pair(CN, C='HK', ST='HK', L='HK', altNames=[], Format=crypto.FILETYPE_PEM):
    '''

    :param CN: Common Name
    :param C: Country
    :param ST: State
    :param L: Locality
    :return: tuple of (csr pem, key pem)
    '''
    print "LL %s" % CN

    fuf = list();
    for i in altNames:
        fuf.append(str(i));
    altNames = fuf;
    req = crypto.X509Req()
    req.get_subject().CN = CN
    req.get_subject().countryName = C
    req.get_subject().stateOrProvinceName = ST
    req.get_subject().localityName = L

    x509_extensions = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
    ])
    if altNames:

        altNames = "DNS: " + (", DNS: ".join(altNames));
        print altNames
        x509_extensions.append(
            crypto.X509Extension("subjectAltName", False, altNames)
        );
    req.add_extensions(x509_extensions);

    key = crypto.PKey();
    key.generate_key(crypto.TYPE_RSA, 2048);

    req.set_pubkey(key);

    req.sign(key, "sha256");

    csr_pem_string = crypto.dump_certificate_request(Format,req);
    key_pem_string = crypto.dump_privatekey(Format,key);

    return csr_pem_string,key_pem_string;

def get_csr_components(csr):
    '''
    :param csr: CSR PEM string
    :return: dictionary of subject attributes (c/cn/l/st/etc..)
    '''
    req = crypto.load_certificate_request(crypto.FILETYPE_PEM,csr);
    subject = req.get_subject();
    return dict(subject.get_components());
