// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include "poc.h"
#include "util.h"
#include "utilstrencodings.h"
#include "base58.h"

using namespace std;

uint32_t nCvnNodeId = 0;
CKey cvnPrivKey;
CPubKey cvnPubKey;

void PrintCertDetails(X509 *x509Certificate)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;

    X509_NAME *name = X509_get_subject_name(x509Certificate);
    BIO_printf(mem, "CVN operator   : ");
    X509_NAME_print_ex(mem, name, 0, XN_FLAG_SEP_CPLUS_SPC);
    BIO_get_mem_ptr(mem, &bptr); bptr->data[bptr->length] = 0;
    LogPrintf("%s\n", bptr->data);
    BIO_free(mem);

    mem = BIO_new(BIO_s_mem());
    name = X509_get_issuer_name(x509Certificate);
    BIO_printf(mem, "CVN issuer     : ");
    X509_NAME_print_ex(mem, name, 0, XN_FLAG_SEP_CPLUS_SPC);
    BIO_get_mem_ptr(mem, &bptr); bptr->data[bptr->length] = 0;
    LogPrintf("%s\n", bptr->data);
    BIO_free(mem);

    mem = BIO_new(BIO_s_mem());
    ASN1_INTEGER *serialNumber = X509_get_serialNumber(x509Certificate);
    BIO_printf(mem, "CVN serial no  : ");
    i2a_ASN1_INTEGER(mem, serialNumber);
    BIO_get_mem_ptr(mem, &bptr); bptr->data[bptr->length] = 0;
    LogPrintf("%s\n", bptr->data);
    BIO_free(mem);

    LogPrintf("CVN public key : %s\n", HexStr(cvnPubKey));
}

uint32_t SetupCVN(X509 *x509Cert)
{
    PrintCertDetails(x509Cert);

    X509_NAME *name = X509_get_subject_name(x509Cert);
    int pos = X509_NAME_get_index_by_NID(name, NID_commonName, 0);
    X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);

    if (!e) {
        LogPrintf("could not find CN in certificate\n");
        return 0;
    }

    ASN1_STRING *asn1name = X509_NAME_ENTRY_get_data(e);
    if (!asn1name) {
        LogPrintf("could not extract ASN1 CN from certificate\n");
        return 0;
    }

    unsigned char *buf = 0;
    int len = ASN1_STRING_to_UTF8(&buf, asn1name);
    if (len <= 0) {
        LogPrintf("could not extract CN string from certificate\n");
        return 0;
    }

    uint32_t lnCvnNodeId = 0;

    try {
        std::stringstream ss;
        ss << std::hex << buf;
        ss >> lnCvnNodeId;
    } catch (const exception& e) {
        if (buf)
            OPENSSL_free(buf);
        return 0;
    }

    OPENSSL_free(buf);

    return lnCvnNodeId;
}

X509* InitCVNWithCertificate()
{
    boost::filesystem::path privkeyFile = GetDataDir() / GetArg("-cvnkeyfile", "cvn.pem");
    FILE* file = fopen(privkeyFile.string().c_str(), "r");
    if (!file) {
        LogPrintf("ERROR: key file not found: %s, is -cvnkeyfile set correctly?\n", privkeyFile);
        return NULL;
    }

    EVP_PKEY *privkey = EVP_PKEY_new();
    PEM_read_PrivateKey(file, &privkey, NULL, NULL);
    fclose(file);

    const EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(privkey);

    if (!EC_KEY_check_key(eckey)) {
        LogPrintf("ERROR: invalid key supplied\n");
        return NULL;
    }

    const BIGNUM *bnPrivKey = EC_KEY_get0_private_key(eckey);

    unsigned char buf[256];
    size_t sKeyLen = BN_bn2bin(bnPrivKey, buf);
    const vector<unsigned char> data(buf, buf + sKeyLen);

    cvnPrivKey.Set(data.begin(), data.end(), false);

    if (!cvnPrivKey.IsValid()) {
        LogPrintf("ERROR: could not validate supplied key\n");
        return NULL;
    }

    BIO *bioCert = BIO_new(BIO_s_file());
    boost::filesystem::path certFile = GetDataDir() / GetArg("-cvncertfile", "cvn.pem");
    if (!BIO_read_filename(bioCert, certFile.string().c_str())) {
        LogPrintf("ERROR: cert file not found: %s, is -cvncertfile set correctly?\n", certFile);
        return NULL;
    }

    X509 *x509Cert = PEM_read_bio_X509(bioCert, NULL, 0, NULL);

    BIO_free(bioCert);

    cvnPubKey = cvnPrivKey.GetPubKey();
    return x509Cert;
}
