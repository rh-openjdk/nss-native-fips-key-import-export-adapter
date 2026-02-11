// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "importer.h"
#include "dbg_trace.h"
#include "p11_util.h"
#include <blapi.h>
#include <limits.h>
#include <lowkeyi.h>
#include <secasn1.h>
#include <secder.h>
#include <secoid.h>

#define INVALID_IDX ((CK_ULONG) - 1L)

#define __nth_attr_to_SECItem(attr_type, sec_item)                             \
    do {                                                                       \
        if (attributes[n].pValue == NULL) {                                    \
            dbg_trace_attr(#attr_type " has no data", attributes[n]);          \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        if (attributes[n].ulValueLen > UINT_MAX) {                             \
            dbg_trace_attr(#attr_type " is too big", attributes[n]);           \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        (sec_item).data = attributes[n].pValue;                                \
        (sec_item).len = (unsigned int)attributes[n].ulValueLen;               \
    } while (0)

#define __for_each_attr_switch_by_its_type_and_validate_template(              \
    switch_body, required_attrs, template_incomplete_message)                  \
    do {                                                                       \
        CK_ULONG found_attrs = 0;                                              \
        for (size_t n = 0; n < n_attributes; n++) {                            \
            switch (attributes[n].type)                                        \
                switch_body                                                    \
        }                                                                      \
        if (found_attrs < (required_attrs)) {                                  \
            dbg_trace(template_incomplete_message);                            \
            return CKR_TEMPLATE_INCOMPLETE;                                    \
        }                                                                      \
    } while (0)

#define __attr_case(attr_type, sec_item)                                       \
    case (attr_type):                                                          \
        found_attrs++;                                                         \
        __nth_attr_to_SECItem(attr_type, (sec_item));                          \
        break

#define __attr_case_store_sensitive_attr_idx_if_false                          \
    case CKA_SENSITIVE:                                                        \
        if (attributes[n].pValue != NULL &&                                    \
            attributes[n].ulValueLen >= sizeof(CK_BBOOL) &&                    \
            *((CK_BBOOL *)attributes[n].pValue) == CK_FALSE) {                 \
            *sensitive_attr_idx = n;                                           \
        }                                                                      \
        break

static CK_RV encode_secret_key(CK_ATTRIBUTE_PTR attributes,
                               CK_ULONG n_attributes, SECItem *encoded_key_item,
                               CK_ULONG *sensitive_attr_idx) {
    __for_each_attr_switch_by_its_type_and_validate_template(
        {
            __attr_case(CKA_VALUE, *encoded_key_item);
            __attr_case_store_sensitive_attr_idx_if_false;
        },
        1, "Unavailable attribute: CKA_VALUE");
    return CKR_OK;
}

static CK_RV encode_private_key(CK_ATTRIBUTE_PTR attributes,
                                CK_ULONG n_attributes, CK_KEY_TYPE key_type,
                                PLArenaPool *arena, SECItem *encoded_key_item,
                                bool *nss_db_attr_present,
                                CK_ULONG *sensitive_attr_idx) {
    SECItem *alg_params = NULL;
    SECOidTag alg_tag = SEC_OID_UNKNOWN;
    NSSLOWKEYPrivateKeyInfo *pki;
    NSSLOWKEYPrivateKey *lpk;
    if (!allocate_PrivateKeyInfo_and_PrivateKey(arena, &pki, &lpk)) {
        return CKR_HOST_MEMORY;
    }

    switch (key_type) {
    case CKK_RSA:
        // For a RSA key to have the CKA_PUBLIC_KEY_INFO attribute when calling
        // C_CreateObject(), it has to be present in the attributes template.
        // In such case, we forward this attribute to C_UnwrapKey(). To avoid
        // CKA_PUBLIC_KEY_INFO being overwritten by C_UnwrapKey() with a value
        // taken from NSSLOWKEYPrivateKeyInfo (pki), we leave alg_params as
        // NULL and set alg_tag to SEC_OID_PKCS1_RSA_ENCRYPTION -instead of
        // SEC_OID_PKCS1_RSA_PSS_SIGNATURE-.
        alg_tag = SEC_OID_PKCS1_RSA_ENCRYPTION;
        lpk->keyType = NSSLOWKEYRSAKey;
        lpk->u.rsa.arena = arena;
        if (DER_SetUInteger(arena, &lpk->u.rsa.version,
                            NSSLOWKEY_PRIVATE_KEY_INFO_VERSION) != SECSuccess) {
            dbg_trace("Failed to encode the RSA private key version");
            return CKR_HOST_MEMORY;
        }
        __for_each_attr_switch_by_its_type_and_validate_template(
            {
                __attr_case(CKA_MODULUS, lpk->u.rsa.modulus);
                __attr_case(CKA_PUBLIC_EXPONENT, lpk->u.rsa.publicExponent);
                __attr_case(CKA_PRIVATE_EXPONENT, lpk->u.rsa.privateExponent);
                __attr_case(CKA_PRIME_1, lpk->u.rsa.prime1);
                __attr_case(CKA_PRIME_2, lpk->u.rsa.prime2);
                __attr_case(CKA_EXPONENT_1, lpk->u.rsa.exponent1);
                __attr_case(CKA_EXPONENT_2, lpk->u.rsa.exponent2);
                __attr_case(CKA_COEFFICIENT, lpk->u.rsa.coefficient);
                __attr_case_store_sensitive_attr_idx_if_false;
            },
            8, "Too few attributes for an RSA private key");
        prepare_low_rsa_priv_key_for_asn1(lpk);
        if (SEC_ASN1EncodeItem(arena, &pki->privateKey, lpk,
                               nsslowkey_RSAPrivateKeyTemplate) == NULL) {
            dbg_trace("Failed to encode the RSA private key");
            return CKR_GENERAL_ERROR;
        }
        dbg_trace("Successfully encoded RSA private key");
        break;
    case CKK_DSA:
        alg_tag = SEC_OID_ANSIX9_DSA_SIGNATURE;
        lpk->keyType = NSSLOWKEYDSAKey;
        lpk->u.dsa.params.arena = arena;
        __for_each_attr_switch_by_its_type_and_validate_template(
            {
                __attr_case(CKA_PRIME, lpk->u.dsa.params.prime);
                __attr_case(CKA_SUBPRIME, lpk->u.dsa.params.subPrime);
                __attr_case(CKA_BASE, lpk->u.dsa.params.base);
                __attr_case(CKA_VALUE, lpk->u.dsa.privateValue);
                __attr_case_store_sensitive_attr_idx_if_false;
            case CKA_NSS_DB:
                *nss_db_attr_present = true;
                break;
            },
            4, "Too few attributes for a DSA private key");
        prepare_low_dsa_priv_key_export_for_asn1(lpk);
        if (SEC_ASN1EncodeItem(arena, &pki->privateKey, lpk,
                               nsslowkey_DSAPrivateKeyExportTemplate) == NULL) {
            dbg_trace("Failed to encode the DSA private key");
            return CKR_GENERAL_ERROR;
        }
        prepare_low_pqg_params_for_asn1(&lpk->u.dsa.params);
        alg_params = SEC_ASN1EncodeItem(arena, NULL, &lpk->u.dsa.params,
                                        nsslowkey_PQGParamsTemplate);
        if (alg_params == NULL) {
            dbg_trace("Failed to encode the DSA private key PQG params");
            return CKR_GENERAL_ERROR;
        }
        dbg_trace("Successfully encoded DSA private key");
        break;
    case CKK_EC:
        alg_tag = SEC_OID_ANSIX962_EC_PUBLIC_KEY;
        lpk->keyType = NSSLOWKEYECKey;
        lpk->u.ec.ecParams.arena = arena;
        if (DER_SetUInteger(arena, &lpk->u.ec.version,
                            NSSLOWKEY_EC_PRIVATE_KEY_VERSION) != SECSuccess) {
            dbg_trace("Failed to encode the EC private key version");
            return CKR_HOST_MEMORY;
        }
        __for_each_attr_switch_by_its_type_and_validate_template(
            {
                __attr_case(CKA_EC_PARAMS, lpk->u.ec.ecParams.DEREncoding);
                __attr_case(CKA_VALUE, lpk->u.ec.privateValue);
                __attr_case_store_sensitive_attr_idx_if_false;
            case CKA_NSS_DB:
                *nss_db_attr_present = true;
                __nth_attr_to_SECItem(CKA_NSS_DB, lpk->u.ec.publicValue);
                break;
            },
            2, "Too few attributes for an EC private key");
        if (EC_FillParams(arena, &lpk->u.ec.ecParams.DEREncoding,
                          &lpk->u.ec.ecParams) != SECSuccess) {
            dbg_trace("Failed to fill the EC params");
            return CKR_GENERAL_ERROR;
        }
        prepare_low_ec_priv_key_for_asn1(lpk);
        // Public value is encoded as a bit string so adjust length
        // to be in bits before ASN encoding and readjust
        // immediately after.
        //
        // Since the SECG specification recommends not including the
        // parameters as part of ECPrivateKey, we zero out the curveOID
        // length before encoding and restore it later.
        unsigned int saved_len = lpk->u.ec.ecParams.curveOID.len;
        lpk->u.ec.ecParams.curveOID.len = 0;
        lpk->u.ec.publicValue.len <<= 3;
        if (SEC_ASN1EncodeItem(arena, &pki->privateKey, lpk,
                               nsslowkey_ECPrivateKeyTemplate) == NULL) {
            dbg_trace("Failed to encode the EC private key");
            return CKR_GENERAL_ERROR;
        }
        lpk->u.ec.publicValue.len >>= 3;
        lpk->u.ec.ecParams.curveOID.len = saved_len;
        alg_params =
            SECITEM_ArenaDupItem(arena, &lpk->u.ec.ecParams.DEREncoding);
        if (alg_params == NULL) {
            dbg_trace("Failed to duplicate the DER encoded EC params");
            return CKR_HOST_MEMORY;
        }
        dbg_trace("Successfully encoded EC private key");
        break;
    default:
        dbg_trace("This should never happen, given is_importable_exportable() "
                  "was previously called\n  key_type = " CKK_FMT,
                  key_type);
        return CKR_GENERAL_ERROR;
    }

    if (SECOID_SetAlgorithmID(arena, &pki->algorithm, alg_tag, alg_params) !=
        SECSuccess) {
        dbg_trace("Failed to encode the private key algorithm");
        return CKR_GENERAL_ERROR;
    }
    if (SEC_ASN1EncodeInteger(arena, &pki->version,
                              NSSLOWKEY_PRIVATE_KEY_INFO_VERSION) == NULL) {
        dbg_trace("Failed to encode the private key version");
        return CKR_HOST_MEMORY;
    }
    if (SEC_ASN1EncodeItem(arena, encoded_key_item, pki,
                           nsslowkey_PrivateKeyInfoTemplate) == NULL) {
        dbg_trace("Failed to encode the private key");
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

CK_RV import_key(CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
                 CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes,
                 CK_ULONG n_attributes, CK_OBJECT_HANDLE_PTR key_id) {
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE_PTR modified_attrs = NULL;
    bool nss_db_attr_present = false;
    CK_ULONG sensitive_attr_idx = INVALID_IDX;
    PLArenaPool *arena = NULL;
    SECItem encoded_key_item = {0};
    CK_BYTE_PTR encrypted_key = NULL;
    CK_ULONG encrypted_key_len = 0;

    if (dbg_is_enabled()) {
        for (size_t n = 0; n < n_attributes; n++) {
            dbg_trace_attr("Attribute received by Adapter's C_CreateObject()",
                           attributes[n]);
        }
    }

    // Encode.
    if (key_class == CKO_SECRET_KEY) {
        ret = encode_secret_key(attributes, n_attributes, &encoded_key_item,
                                &sensitive_attr_idx);
    } else if (key_class == CKO_PRIVATE_KEY) {
        arena = PORT_NewArena(2048);
        if (arena == NULL) {
            return_with_cleanup(CKR_HOST_MEMORY);
        }
        ret = encode_private_key(attributes, n_attributes, key_type, arena,
                                 &encoded_key_item, &nss_db_attr_present,
                                 &sensitive_attr_idx);
    } else {
        dbg_trace("This should never happen, given is_importable_exportable() "
                  "was previously called\n  key_class = " CKO_FMT,
                  key_class);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    if (ret != CKR_OK) {
        return_with_cleanup(ret);
    }

    // Encrypt.
    ret = P11.C_EncryptInit(session, &IEK.mech, IEK.id);
    if (ret != CKR_OK) {
        dbg_trace("C_EncryptInit has failed with ret = " CKR_FMT, ret);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    p11_call_with_allocation(P11.C_Encrypt, encrypted_key, encrypted_key_len,
                             session, encoded_key_item.data,
                             encoded_key_item.len);
    dbg_trace("Called C_Encrypt() to import the key\n  "
              "encoded_key_item.len = %u, encrypted_key_len = %lu, "
              "ret = " CKR_FMT,
              encoded_key_item.len, encrypted_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Unwrap.
    CK_BYTE byte_zero = 0;
    CK_BBOOL bool_true = CK_TRUE;
    if (sensitive_attr_idx != INVALID_IDX ||
        (!nss_db_attr_present && key_class == CKO_PRIVATE_KEY &&
         (key_type == CKK_DSA || key_type == CKK_EC))) {
        modified_attrs = malloc((n_attributes + (nss_db_attr_present ? 0 : 1)) *
                                sizeof(CK_ATTRIBUTE));
        if (modified_attrs == NULL) {
            return_with_cleanup(CKR_HOST_MEMORY);
        }
        memcpy(modified_attrs, attributes, n_attributes * sizeof(CK_ATTRIBUTE));
        if (sensitive_attr_idx != INVALID_IDX) {
            dbg_trace("Forcing CKA_SENSITIVE=CK_TRUE to avoid being rejected "
                      "by the NSS FIPS token");
            modified_attrs[sensitive_attr_idx].pValue = &bool_true;
            modified_attrs[sensitive_attr_idx].ulValueLen = sizeof(bool_true);
        }
        if (!nss_db_attr_present) {
            dbg_trace("Adding CKA_NSS_DB (a.k.a. CKA_NETSCAPE_DB) attribute");
            modified_attrs[n_attributes].type = CKA_NSS_DB;
            modified_attrs[n_attributes].pValue = &byte_zero;
            modified_attrs[n_attributes].ulValueLen = sizeof(byte_zero);
            n_attributes++;
        }
        attributes = modified_attrs;
    }
    ret = P11.C_UnwrapKey(session, &IEK.mech, IEK.id, encrypted_key,
                          encrypted_key_len, attributes, n_attributes, key_id);
    dbg_trace("Called C_UnwrapKey() to import the key\n  "
              "imported key_id = %lu, ret = " CKR_FMT,
              ret == CKR_OK ? *key_id : CK_INVALID_HANDLE, ret);

cleanup:
    if (modified_attrs != NULL) {
        free(modified_attrs);
    }
    if (encrypted_key != NULL) {
        zeroize_and_free(encrypted_key, encrypted_key_len);
    }
    if (arena != NULL) {
        PORT_FreeArena(arena, /* zero = */ PR_TRUE);
    }
    return ret;
}
