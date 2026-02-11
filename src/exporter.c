// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "exporter.h"
#include "dbg_trace.h"
#include "p11_util.h"
#include <limits.h>
#include <lowkeyi.h>
#include <secasn1.h>
#include <secoid.h>

// OpenJDK's libj2pkcs11 follows the "Conventions for functions returning output
// in a variable-length buffer" (PKCS #11 v3.0 Section 5.2). Keep state between
// querying the buffer sizes and executing the actual call in thread-local
// variables.
static __thread CK_OBJECT_HANDLE cached_sensitive_attrs_key_id =
    CK_INVALID_HANDLE;
static __thread CK_ATTRIBUTE cached_sensitive_attrs[] = {
#define for_each_sensitive_attr(idx, sensitive_attr_type)                      \
    {.type = sensitive_attr_type, .pValue = NULL, .ulValueLen = 0},
#include "sensitive_attributes.h"
#undef for_each_sensitive_attr
};

static inline CK_ATTRIBUTE_PTR
get_sensitive_cached_attr(CK_ATTRIBUTE_TYPE type) {
    switch (type) {
#define for_each_sensitive_attr(idx, sensitive_attr_type)                      \
    case sensitive_attr_type:                                                  \
        return &cached_sensitive_attrs[idx];
#include "sensitive_attributes.h"
#undef for_each_sensitive_attr
    default:
        return NULL;
    }
}

static inline void clear_sensitive_cached_attrs(void) {
    for (size_t n = 0; n < attrs_count(cached_sensitive_attrs); n++) {
        if (cached_sensitive_attrs[n].pValue != NULL) {
            zeroize_and_free(cached_sensitive_attrs[n].pValue,
                             cached_sensitive_attrs[n].ulValueLen);
            cached_sensitive_attrs[n].pValue = NULL;
        }
        cached_sensitive_attrs[n].ulValueLen = 0;
    }
    cached_sensitive_attrs_key_id = CK_INVALID_HANDLE;
}

#define __store_cached_attr(attr_type, sec_item_attr)                          \
    do {                                                                       \
        CK_ATTRIBUTE_PTR cached_attr_slot =                                    \
            get_sensitive_cached_attr(attr_type);                              \
        if (cached_attr_slot == NULL) {                                        \
            dbg_trace("Cannot store unknown sensitive attribute " #attr_type); \
            return CKR_GENERAL_ERROR;                                          \
        }                                                                      \
        cached_attr_slot->pValue = malloc((sec_item_attr).len);                \
        if (cached_attr_slot->pValue == NULL) {                                \
            dbg_trace("Ran out of memory while exporting " #attr_type);        \
            return CKR_HOST_MEMORY;                                            \
        }                                                                      \
        memcpy(cached_attr_slot->pValue, (sec_item_attr).data,                 \
               (sec_item_attr).len);                                           \
        cached_attr_slot->ulValueLen = (sec_item_attr).len;                    \
    } while (0)

static CK_RV decode_and_store_secret_key(CK_BYTE_PTR *encoded_key,
                                         CK_ULONG encoded_key_len) {
    CK_ATTRIBUTE_PTR cached_attr_slot = get_sensitive_cached_attr(CKA_VALUE);
    cached_attr_slot->ulValueLen = encoded_key_len;
    cached_attr_slot->pValue = *encoded_key;
    // Transfer ownership to the above assignation to cached_attr_slot->pValue:
    *encoded_key = NULL;
    return CKR_OK;
}

static CK_RV decode_and_store_private_key(CK_KEY_TYPE key_type,
                                          CK_BYTE_PTR encoded_key,
                                          CK_ULONG encoded_key_len) {
    CK_RV ret = CKR_OK;
    PLArenaPool *arena = NULL;
    NSSLOWKEYPrivateKeyInfo *pki;
    NSSLOWKEYPrivateKey *lpk;

    if (encoded_key_len > UINT_MAX) {
        dbg_trace("Too big encoded key (%lu bytes)", encoded_key_len);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    SECItem encoded_key_item = {.type = siBuffer,
                                .data = encoded_key,
                                .len = (unsigned int)encoded_key_len};

    arena = PORT_NewArena(2048);
    if (arena == NULL) {
        return_with_cleanup(CKR_HOST_MEMORY);
    }
    if (!allocate_PrivateKeyInfo_and_PrivateKey(arena, &pki, &lpk)) {
        return_with_cleanup(CKR_HOST_MEMORY);
    }

    if (SEC_QuickDERDecodeItem(arena, pki, nsslowkey_PrivateKeyInfoTemplate,
                               &encoded_key_item) != SECSuccess) {
        dbg_trace("Failed to decode PKCS #8 private key");
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    SECOidTag alg_tag = SECOID_GetAlgorithmTag(&pki->algorithm);
    switch (key_type) {
    case CKK_RSA:
        // We only care about sensitive attributes. For this reason,
        // SEC_OID_PKCS1_RSA_PSS_SIGNATURE does not need algorithm
        // parameters handling to extract the CKA_PUBLIC_KEY_INFO
        // value: P11.C_GetAttributeValue() already did so.
        if (alg_tag != SEC_OID_PKCS1_RSA_ENCRYPTION &&
            alg_tag != SEC_OID_PKCS1_RSA_PSS_SIGNATURE) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        lpk->keyType = NSSLOWKEYRSAKey;
        prepare_low_rsa_priv_key_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk, nsslowkey_RSAPrivateKeyTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 RSA private key");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        __store_cached_attr(CKA_PRIVATE_EXPONENT, lpk->u.rsa.privateExponent);
        __store_cached_attr(CKA_PRIME_1, lpk->u.rsa.prime1);
        __store_cached_attr(CKA_PRIME_2, lpk->u.rsa.prime2);
        __store_cached_attr(CKA_EXPONENT_1, lpk->u.rsa.exponent1);
        __store_cached_attr(CKA_EXPONENT_2, lpk->u.rsa.exponent2);
        __store_cached_attr(CKA_COEFFICIENT, lpk->u.rsa.coefficient);
        dbg_trace("Successfully decoded RSA private key");
        break;
    case CKK_DSA:
        // We only care about sensitive attributes. For this reason,
        // we don't need to decode the PQG parameters to extract the
        // CKA_PRIME, CKA_SUBPRIME and CKA_BASE attribute values:
        // P11.C_GetAttributeValue() already did so.
        if (alg_tag != SEC_OID_ANSIX9_DSA_SIGNATURE) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        lpk->keyType = NSSLOWKEYDSAKey;
        prepare_low_dsa_priv_key_export_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk,
                                   nsslowkey_DSAPrivateKeyExportTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 DSA private key");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        __store_cached_attr(CKA_VALUE, lpk->u.dsa.privateValue);
        dbg_trace("Successfully decoded DSA private key");
        break;
    case CKK_EC:
        // We only care about sensitive attributes. For this reason, we don't
        // need to copy lpk->u.ec.ecParams.DEREncoding to set the CKA_EC_PARAMS
        // attribute value: P11.C_GetAttributeValue() already did so.
        if (alg_tag != SEC_OID_ANSIX962_EC_PUBLIC_KEY) {
            dbg_trace("Unexpected key algorithm tag: %u", alg_tag);
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        lpk->keyType = NSSLOWKEYECKey;
        prepare_low_ec_priv_key_for_asn1(lpk);
        if (SEC_QuickDERDecodeItem(arena, lpk, nsslowkey_ECPrivateKeyTemplate,
                                   &pki->privateKey) != SECSuccess) {
            dbg_trace("Failed to decode PKCS #8 EC private key");
            return_with_cleanup(CKR_GENERAL_ERROR);
        }
        __store_cached_attr(CKA_VALUE, lpk->u.ec.privateValue);
        dbg_trace("Successfully decoded EC private key");
        break;
    default:
        dbg_trace("This should never happen, given is_importable_exportable() "
                  "was previously called\n  key_type = " CKK_FMT,
                  key_type);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

cleanup:
    if (arena != NULL) {
        PORT_FreeArena(arena, /* zero = */ PR_TRUE);
    }
    return ret;
}

static CK_RV export_and_store_key(key_data_t *key_data,
                                  CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key_id) {
    if (cached_sensitive_attrs_key_id != CK_INVALID_HANDLE) {
        // This should never happen because OpenJDK follows the "Conventions
        // for functions returning output in a variable-length buffer" (PKCS
        // #11 v3.0 Section 5.2) for sensitive attributes.
        dbg_trace("Overwriting previous cached sensitive attributes:\n  "
                  "old_id = %lu, new_id = %lu",
                  cached_sensitive_attrs_key_id, key_id);
        clear_sensitive_cached_attrs();
    }

    CK_RV ret = CKR_OK;
    CK_BYTE_PTR encoded_key = NULL;
    CK_ULONG encoded_key_len = 0;
    CK_BYTE_PTR encrypted_key = NULL;
    CK_ULONG encrypted_key_len = 0;

    // Wrap.
    p11_call_with_allocation(P11.C_WrapKey, encrypted_key, encrypted_key_len,
                             session, &IEK.mech, IEK.id, key_id);
    dbg_trace("Called C_WrapKey() to export the key\n  "
              "encrypted_key_len = %lu, ret = " CKR_FMT,
              encrypted_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Decrypt.
    ret = P11.C_DecryptInit(session, &IEK.mech, IEK.id);
    if (ret != CKR_OK) {
        dbg_trace("C_DecryptInit has failed with ret = " CKR_FMT, ret);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    p11_call_with_allocation(P11.C_Decrypt, encoded_key, encoded_key_len,
                             session, encrypted_key, encrypted_key_len);
    dbg_trace("Called C_Decrypt() to export the key\n  encoded_key_len = %lu, "
              "ret = " CKR_FMT,
              encoded_key_len, ret);
    if (ret != CKR_OK) {
        return_with_cleanup(CKR_GENERAL_ERROR);
    }

    // Decode and store.
    if (key_data->class == CKO_SECRET_KEY) {
        ret = decode_and_store_secret_key(&encoded_key, encoded_key_len);
    } else if (key_data->class == CKO_PRIVATE_KEY) {
        ret = decode_and_store_private_key(key_data->type, encoded_key,
                                           encoded_key_len);
    } else {
        dbg_trace("This should never happen, given is_importable_exportable() "
                  "was previously called\n  key_data.class = " CKO_FMT,
                  key_data->class);
        return_with_cleanup(CKR_GENERAL_ERROR);
    }
    if (ret != CKR_OK) {
        return_with_cleanup(ret);
    }
    cached_sensitive_attrs_key_id = key_id;

cleanup:
    if (encrypted_key != NULL) {
        zeroize_and_free(encrypted_key, encrypted_key_len);
    }
    if (encoded_key != NULL) {
        zeroize_and_free(encoded_key, encoded_key_len);
    }
    if (ret != CKR_OK) {
        clear_sensitive_cached_attrs();
    }
    return ret;
}

CK_RV export_key(key_data_t *key_data, CK_SESSION_HANDLE session,
                 CK_OBJECT_HANDLE key_id, CK_ATTRIBUTE_PTR attributes,
                 CK_ULONG n_attributes) {
    CK_RV ret = CKR_OK;
    bool should_clear_cache = false;

    // Keep a copy of the original value lengths as P11.C_GetAttributeValue()
    // may overwrite any of these values with CK_UNAVAILABLE_INFORMATION.
    CK_ULONG *original_value_lens = malloc(n_attributes * sizeof(CK_ULONG));
    if (original_value_lens == NULL) {
        dbg_trace("Could not allocate copy of the original attribute lengths");
        should_clear_cache = true;
        return_with_cleanup(CKR_HOST_MEMORY);
    }
    for (size_t n = 0; n < n_attributes; n++) {
        original_value_lens[n] = attributes[n].ulValueLen;
    }

    // Forward the C_GetAttributeValue() call to NSS.
    CK_RV forwarded_call_ret =
        P11.C_GetAttributeValue(session, key_id, attributes, n_attributes);
    dbg_trace("Forwarded to NSS C_GetAttributeValue()\n  session = 0x%08lx, "
              "key_id = %lu, attributes = %p, n_attributes = %lu, "
              "forwarded_call_ret = " CKR_FMT,
              session, key_id, (void *)attributes, n_attributes,
              forwarded_call_ret);

    bool has_sensitive_attrs = false;
    bool has_invalid_attrs = false;
    bool has_too_small_buffers = false;
    CK_ATTRIBUTE_PTR cached_attr_slot = NULL;
    for (size_t n = 0; n < n_attributes; n++) {
        dbg_trace_attr("Attribute returned by NSS' C_GetAttributeValue()",
                       attributes[n]);
        if ((attributes[n].type == CKA_SENSITIVE ||
             attributes[n].type == CKA_ALWAYS_SENSITIVE) &&
            attributes[n].pValue != NULL &&
            attributes[n].ulValueLen >= sizeof(CK_BBOOL)) {
            if (attributes[n].type == CKA_SENSITIVE) {
                // Make the key look as non-sensitive.
                // The exporter will handle that.
                dbg_trace("Forcing CKA_SENSITIVE=CK_FALSE to avoid an opaque "
                          "P11Key object");
            } else {
                dbg_trace("Making CKA_ALWAYS_SENSITIVE=CK_FALSE as we changed "
                          "the CKA_SENSITIVE value to CK_FALSE");
            }
            *((CK_BBOOL *)attributes[n].pValue) = CK_FALSE;
        }
        if (attributes[n].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            cached_attr_slot = get_sensitive_cached_attr(attributes[n].type);
            if (cached_attr_slot != NULL) {
                if (cached_sensitive_attrs_key_id != key_id) {
                    ret = export_and_store_key(key_data, session, key_id);
                    if (ret != CKR_OK) {
                        return_with_cleanup(ret);
                    }
                } else if (!has_sensitive_attrs &&
                           cached_attr_slot->pValue != NULL) {
                    dbg_trace("key_id = %lu is already in the thread-cache",
                              key_id);
                }
                if (cached_attr_slot->pValue == NULL) {
                    has_invalid_attrs = true;
                    continue;
                }
                has_sensitive_attrs = true;
                attributes[n].ulValueLen = cached_attr_slot->ulValueLen;
                if (attributes[n].pValue != NULL) {
                    if (original_value_lens[n] < cached_attr_slot->ulValueLen) {
                        // This should never happen because OpenJDK follows the
                        // "Conventions for functions returning output in a
                        // variable-length buffer" (PKCS #11 v3.0 Section 5.2)
                        // for sensitive attributes.
                        has_too_small_buffers = true;
                        attributes[n].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        dbg_trace("Buffer too small, actual size: %lu, "
                                  "required size: %lu",
                                  original_value_lens[n],
                                  cached_attr_slot->ulValueLen);
                    } else {
                        should_clear_cache = true;
                        memcpy(attributes[n].pValue, cached_attr_slot->pValue,
                               cached_attr_slot->ulValueLen);
                        dbg_trace_attr("Copied previously exported attribute",
                                       attributes[n]);
                    }
                } else {
                    dbg_trace_attr("Replaced ulValueLen", attributes[n]);
                }
            } else {
                // NOTE: if attributes[n].pValue is not NULL, may also be the
                // case that the buffer was a too small. We will return
                // CKR_ATTRIBUTE_TYPE_INVALID anyways because OpenJDK never
                // passes small buffers.
                has_invalid_attrs = true;
            }
        }
    }
    if (forwarded_call_ret == CKR_ATTRIBUTE_SENSITIVE) {
        // CKR_ATTRIBUTE_SENSITIVE implies that there is at least one sensitive
        // attribute. Other attributes may have CK_UNAVAILABLE_INFORMATION for a
        // different reason, and could have led to a CKR_ATTRIBUTE_TYPE_INVALID
        // or CKR_BUFFER_TOO_SMALL return value. Since we fixed the sensitive
        // attributes issues, adjust the return value.
        if (has_invalid_attrs) {
            ret = CKR_ATTRIBUTE_TYPE_INVALID;
        } else if (has_too_small_buffers) {
            ret = CKR_BUFFER_TOO_SMALL;
        } else if (has_sensitive_attrs) {
            ret = CKR_OK;
        } else {
            dbg_trace("CKR_ATTRIBUTE_SENSITIVE with unknown sensitive attr");
            ret = CKR_GENERAL_ERROR;
        }
    } else {
        ret = forwarded_call_ret;
    }

cleanup:
    if (should_clear_cache) {
        clear_sensitive_cached_attrs();
    }
    if (original_value_lens != NULL) {
        free(original_value_lens);
    }
    return ret;
}
