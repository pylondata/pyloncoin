// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "primitives/block.h"
#include "poc.h"
#include "cvn.h"

#include "pkcs11/pkcs11.h"
#include <secp256k1.h>
#include <openssl/ssl.h>

bool fSmartCardUnlocked = false;

extern "C" CK_RV C_UnloadModule(void *module);
extern "C" void *C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs);
static void *module = NULL;
static CK_FUNCTION_LIST_PTR p11 = NULL;
static CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
static CK_MECHANISM mech;

#define P(x) #x
#define USE_OPENSC_MODULE_PATH(x) P(x)

#if defined(WIN32)
static std::string defaultPkcs11ModulePath = "";
#elif defined(MAC_OSX)
static std::string defaultPkcs11ModulePath = "";
#else
static std::string defaultPkcs11ModulePath = USE_OPENSC_MODULE_PATH(USE_OPENSC) "/target/lib/opensc-pkcs11.so";
#endif

static void cleanup_p11()
{
    if (p11)
        p11->C_Finalize(NULL_PTR);
    if (module)
        C_UnloadModule(module);
}

static unsigned char* getAttribute(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount, CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE attr = { type, NULL, 0 };
    CK_RV rv;

    rv = p11->C_GetAttributeValue(sess, obj, &attr, 1);
    if (rv == CKR_OK) {
        if (!(attr.pValue = calloc(1, attr.ulValueLen + 1))) {
            LogPrintf("getAttribute: out of memory\n");
            return NULL;
        }
        rv = p11->C_GetAttributeValue(sess, obj, &attr, 1);
        if (pulCount)
            *pulCount = attr.ulValueLen;
    } else {
        LogPrintf("getAttribute: ERROR, C_GetAttributeValue %u\n", rv);
    }
    return (unsigned char *)attr.pValue;
}

static int find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
        CK_OBJECT_HANDLE_PTR ret,
        const unsigned char *id, size_t id_len, int obj_index)
{
    CK_ATTRIBUTE attrs[2];
    unsigned int nattrs = 0;
    CK_ULONG count;
    CK_RV rv;
    int i;

    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof(cls);
    nattrs++;
    if (id) {
        attrs[nattrs].type = CKA_ID;
        attrs[nattrs].pValue = (void *) id;
        attrs[nattrs].ulValueLen = id_len;
        nattrs++;
    }

    rv = p11->C_FindObjectsInit(sess, attrs, nattrs);
    if (rv != CKR_OK) {
        LogPrintf("C_FindObjectsInit");
        goto done;
    }

    for (i = 0; i < obj_index; i++) {
        rv = p11->C_FindObjects(sess, ret, 1, &count);
        if (rv != CKR_OK) {
            LogPrintf("C_FindObjects\n");
            goto done;
        }
        if (count == 0)
            goto done;
    }
    rv = p11->C_FindObjects(sess, ret, 1, &count);
    if (rv != CKR_OK) {
        LogPrintf("C_FindObjects\n");
        goto done;
    }

done:
    if (count == 0)
        *ret = CK_INVALID_HANDLE;

    p11->C_FindObjectsFinal(sess);

    return count;
}

bool CvnSignWithSmartCard(const uint256& hashUnsignedBlock, CCvnSignature& signature, const CCvnInfo& cvnInfo)
{
    CK_ULONG nSigLen = 64;
    secp256k1_ecdsa_signature sig;

    if (cvnInfo.vPubKey != cvnPubKey) {
        LogPrintf("CvnSignWithSmartCard : key does not match node ID\n  CVN pubkey: %s\n CARD pubkey: %s\n", HexStr(cvnInfo.vPubKey), HexStr(cvnPubKey));
        return false;
    }

    CK_RV rv = p11->C_SignInit(session, &mech, key);
    if (rv != CKR_OK) {
        LogPrintf("CvnSignWithSmartCard : ERROR, could not create signature with smart card(init): %08x\n", (unsigned int)rv);
        return false;
    }

    rv =  p11->C_Sign(session,
            (unsigned char*) hashUnsignedBlock.begin(), hashUnsignedBlock.size(),
            (unsigned char*) &sig, &nSigLen);

    if (rv != CKR_OK) {
        LogPrintf("CvnSignWithSmartCard : ERROR, could not create signature with smart card: %08x\n", (unsigned int)rv);
        return false;
    }

    std::reverse(sig.data, sig.data + 32);
    std::reverse(&sig.data[32], &sig.data[32] + 32);

    size_t nSigLenDER = 72;
    signature.vSignature.resize(72);

    secp256k1_context* tmp_secp256k1_context_sign = NULL;
    secp256k1_ecdsa_signature_serialize_der(tmp_secp256k1_context_sign, &signature.vSignature[0], &nSigLenDER, &sig);

    signature.vSignature.resize(nSigLenDER);

    if (!CvnVerifySignature(hashUnsignedBlock, signature)) {
        LogPrintf("CvnSignWithSmartCard : ERROR: created invalid signature\n");
        return false;
    }

#ifdef SMARTCARD_DEBUG
    LogPrintf("CvnSignWithSmartCard : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            HexStr(cvnInfo.vPubKey),
            HexStr(signature.vSignature));
#endif
    return true;
}

X509* InitCVNWithSmartCard()
{
    CK_OBJECT_HANDLE tmpPubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE tmpCertificate = CK_INVALID_HANDLE;
    CK_BYTE opt_object_id[1];
    CK_RV rv;

    if (GetArg("-cvnpin", "").empty()) {
        LogPrintf("ERROR: -cvnpin not supplied.\n");
        return NULL;
    }
    std::string pkcs11module = GetArg("-pkcs11module", defaultPkcs11ModulePath);
    static const char * opt_module = pkcs11module.c_str();

    module = C_LoadModule(opt_module, &p11);
    if (module == NULL) {
        LogPrintf("Failed to load pkcs11 module: %s\n", pkcs11module);
        return NULL;
    }

    rv = p11->C_Initialize(NULL);
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        LogPrintf("library has already been initialized\n");
    } else if (rv != CKR_OK) {
        LogPrintf("error initializing pkcs11 framework\n");
        return NULL;
    }

    LogPrintf("OpenSC successfully initialized using pkcs11 module at %s\n", opt_module);

    rv = p11->C_OpenSession(GetArg("-cvnslot", 0), CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        LogPrintf("ERROR: could not open session: %04x\n", (unsigned int)rv);
        cleanup_p11();
        return NULL;
    }

    string strCardPIN = GetArg("-cvnpin", "");
    rv = p11->C_Login(session, CKU_USER,(CK_UTF8CHAR *) strCardPIN.c_str(), strCardPIN.size());
    if (rv != CKR_OK) {
        LogPrintf("ERROR: could not log into smart card (is the supplied -cvnpin correct?)\n");
        cleanup_p11();
        return NULL;
    }

    opt_object_id[0] = GetArg("-cvnkeyid", 3);
    if (find_object(session, CKO_PRIVATE_KEY, &key, opt_object_id, 1, 0) != 1){
        LogPrintf("ERROR: Private key not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return NULL;
    }

    if (find_object(session, CKO_PUBLIC_KEY, &tmpPubKey, opt_object_id, 1, 0) != 1){
        LogPrintf("ERROR: Public key not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return NULL;
    }

    CK_ULONG nAttrValueSize = 0;
    unsigned char *pPubKey = getAttribute(session, tmpPubKey, &nAttrValueSize, CKA_EC_POINT);

    if (!pPubKey) {
        LogPrintf("ERROR: Public key not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return NULL;
    }

    cvnPubKey.Set(&pPubKey[2], pPubKey + nAttrValueSize);
    free(pPubKey);

    opt_object_id[0] = GetArg("-cvncertid", 5);
    if (find_object(session, CKO_CERTIFICATE, &tmpCertificate, opt_object_id, 1, 0) != 1){
        LogPrintf("ERROR: Certificate not found on card (is the -cvncertid correct?)\n");
        cleanup_p11();
        return NULL;
    }

    nAttrValueSize = 0;
    unsigned char *pCert = getAttribute(session, tmpCertificate, &nAttrValueSize, CKA_VALUE);
    if (!pCert) {
        LogPrintf("ERROR: Certificate not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return NULL;
    }

    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_ECDSA;
    fSmartCardUnlocked = true;

    const unsigned char *pCertStore = pCert;
    X509* x509Certificate = d2i_X509(NULL, &pCertStore, nAttrValueSize);

    LogPrintf("Smart card successfully initialized\n");
    free(pCert);

    return x509Certificate;
}
