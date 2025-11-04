// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#include "nssadapter.h"
#include "dbg_trace.h"
#include "exporter.h"
#include "importer.h"
#include "p11_util.h"
#include <nss.h>
#include <pkcs11.h>

/* ****************************************************************************
 * Global importer / exporter data
 * ****************************************************************************/

// This IV is not relevant for security as we are importing or exporting keys in
// plain.
static CK_BYTE iv[] = {0xa1, 0xe9, 0xe1, 0x95, 0xbf, 0x11, 0x6c, 0xca,
                       0xef, 0xa5, 0x56, 0x5e, 0xdd, 0xfc, 0xdc, 0x8c};
static global_data_t global_data = {
    .orig_funcs_list = NULL,
    .importer_exporter_key = {.session = CK_INVALID_HANDLE,
                              .id = CK_INVALID_HANDLE,
                              .mech = {CKM_AES_CBC_PAD, &iv, sizeof(iv)}},
};

static bool nss_initialization_failed = false;

// CK_INTERFACE and CK_FUNCTION_LIST_3_0 for return to OpenJDK.
// decorated_func_list includes pointers to either NSS functions or the
// adapter's decorated ones. NOTE: CK_FUNCTION_LIST_3_0 has enough space to hold
// all the CK_FUNCTION_LIST data. In runtime, one or the other can be present.
static CK_INTERFACE decorated_interface = {0};
static CK_FUNCTION_LIST_3_0 decorated_func_list = {0};

inline global_data_t *__get_global_data() {
    return &global_data;
}

/* ****************************************************************************
 * Common code for importer / exporter entry points
 * ****************************************************************************/

static inline bool get_key_type_from_attrs(CK_ATTRIBUTE_PTR attributes,
                                           CK_ULONG n_attributes,
                                           CK_OBJECT_CLASS *key_class,
                                           CK_KEY_TYPE *key_type) {
    bool has_key_class = false;
    bool has_key_type = false;
    for (size_t n = 0; n < n_attributes; n++) {
        if (attributes[n].pValue != NULL) {
            if (attributes[n].type == CKA_CLASS &&
                attributes[n].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
                *key_class = *((CK_OBJECT_CLASS *)attributes[n].pValue);
                has_key_class = true;
                if (has_key_type) {
                    break;
                }
            } else if (attributes[n].type == CKA_KEY_TYPE &&
                       attributes[n].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                *key_type = *((CK_KEY_TYPE *)attributes[n].pValue);
                has_key_type = true;
                if (has_key_class) {
                    break;
                }
            }
        }
    }
    dbg_trace("key_class = " CKO_FMT ", key_type = " CKK_FMT, *key_class,
              *key_type);
    return has_key_class && has_key_type;
}

static inline bool get_key_data_from_object(CK_SESSION_HANDLE session,
                                            CK_OBJECT_HANDLE key_id,
                                            key_data_t *key_data) {
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS,       &key_data->class,       sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,    &key_data->type,        sizeof(CK_KEY_TYPE)    },
        {CKA_TOKEN,       &key_data->token,       sizeof(CK_BBOOL)       },
        {CKA_SENSITIVE,   &key_data->sensitive,   sizeof(CK_BBOOL)       },
        {CKA_EXTRACTABLE, &key_data->extractable, sizeof(CK_BBOOL)       },
    };
    CK_RV ret = P11.C_GetAttributeValue(session, key_id, attributes,
                                        attrs_count(attributes));
    if (ret == CKR_OK) {
        dbg_trace("session = 0x%08lx, key_id = %lu, obtained data:\n  "
                  "key_data.class = " CKO_FMT ", key_data.type = " CKK_FMT ", "
                  "key_data.token = %u, key_data.sensitive = %u, "
                  "key_data.extractable = %u",
                  session, key_id, key_data->class, key_data->type,
                  key_data->token, key_data->sensitive, key_data->extractable);
        return true;
    } else {
        dbg_trace("C_GetAttributeValue() call failed with ret = " CKR_FMT, ret);
        return false;
    }
}

static inline bool is_importable_exportable(CK_OBJECT_CLASS key_class,
                                            CK_KEY_TYPE key_type) {
    // NOTE: see OPENJDK-824 for reasons behind skipping DH keys.
    return key_class == CKO_SECRET_KEY ||
           (key_class == CKO_PRIVATE_KEY &&
            (key_type == CKK_RSA || key_type == CKK_DSA || key_type == CKK_EC));
}

/* ****************************************************************************
 * Initialization
 * ****************************************************************************/

static CK_RV initialize_importer_exporter() {
    if (IEK.id != CK_INVALID_HANDLE) {
        // Already initialized.
        return CKR_OK;
    }

    // Create importer / exporter session.
    CK_RV ret = P11.C_OpenSession(FIPS_SLOT_ID, CKF_SERIAL_SESSION, NULL, NULL,
                                  &IEK.session);
    dbg_trace("Called C_OpenSession() to create the session for the "
              "import / export key\n  IEK.session = 0x%08lx, ret = " CKR_FMT,
              IEK.session, ret);
    if (ret != CKR_OK) {
        return ret;
    }

    // Create importer / exporter key.
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG keyLen = 256 >> 3;
    CK_MECHANISM mechanisms[] = {
        {CKM_AES_KEY_GEN, NULL, 0},
    };
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS,     &keyClass, sizeof(keyClass)},
        {CKA_VALUE_LEN, &keyLen,   sizeof(keyLen)  },
    };
    ret = P11.C_GenerateKey(IEK.session, mechanisms, attributes,
                            attrs_count(attributes), &IEK.id);
    dbg_trace("Called C_GenerateKey() to create the import / export key\n  "
              "IEK.id = %lu, ret = " CKR_FMT,
              IEK.id, ret);
    return ret;
}

/* ****************************************************************************
 * Initialization entry point
 * ****************************************************************************/

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    CK_RV ret = P11.C_Initialize(pInitArgs);
    dbg_trace("Forwarded to NSS function\n  pInitArgs = %p, ret = " CKR_FMT,
              pInitArgs, ret);
    if (ret == CKR_OK || ret == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        // This method is called from OpenJDK's PKCS11::getInstance(), which is
        // synchronized. initialize_importer_exporter() can be called at this
        // point without concurrency issues.
        if (initialize_importer_exporter() != CKR_OK) {
            ret = CKR_GENERAL_ERROR;
        }
    }
    return ret;
}

/* ****************************************************************************
 * Importer entry point
 * ****************************************************************************/

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
    CK_OBJECT_CLASS keyClass = (CK_OBJECT_CLASS)-1;
    CK_KEY_TYPE keyType = (CK_KEY_TYPE)-1;
    if (get_key_type_from_attrs(pTemplate, ulCount, &keyClass, &keyType) &&
        is_importable_exportable(keyClass, keyType)) {
        // Intercept call.
        CK_RV ret = import_key(keyClass, keyType, hSession, pTemplate, ulCount,
                               phObject);
        dbg_trace("Returning " CKR_FMT, ret);
        return ret;
    }
    dbg_trace("There is no support for importing this key, forwarding to NSS"
              "\n  hSession = 0x%08lx, pTemplate = %p, ulCount = %lu, "
              "phObject = %p",
              hSession, (void *)pTemplate, ulCount, (void *)phObject);
    return P11.C_CreateObject(hSession, pTemplate, ulCount, phObject);
}

/* ****************************************************************************
 * Exporter entry point
 * ****************************************************************************/

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    key_data_t keyData = {0};
    if (get_key_data_from_object(hSession, hObject, &keyData) &&
        is_importable_exportable(keyData.class, keyData.type)) {
        // Based on our FIPS configuration (FIPS enabled and no-DB), token
        // should be CK_FALSE and sensitive should be CK_TRUE.
        if (keyData.token == CK_TRUE) {
            dbg_trace("Without an NSS DB, CKA_TOKEN should always be CK_FALSE");
            return CKR_DEVICE_ERROR;
        }
        if (keyData.sensitive == CK_FALSE) {
            dbg_trace("Non-sensitive key, this is unexpected in FIPS mode");
            return CKR_DEVICE_ERROR;
        }
        if (keyData.extractable == CK_TRUE) {
            // Intercept call.
            CK_RV ret =
                export_key(&keyData, hSession, hObject, pTemplate, ulCount);
            dbg_trace("Returning " CKR_FMT, ret);
            return ret;
        } else {
            dbg_trace("Let non-extractable key be handled as opaque");
        }
    }
    dbg_trace("There is no support for exporting this key, forwarding to NSS"
              "\n  hSession = 0x%08lx, hObject = %lu, pTemplate = %p, "
              "ulCount = %lu",
              hSession, hObject, (void *)pTemplate, ulCount);
    return P11.C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

/* ****************************************************************************
 * Get interface entry point
 * ****************************************************************************/

// Prototype for the FIPS version in NSS' libsoftokn3.so.
CK_RV FC_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                      CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags);

EXPORTED_FUNCTION CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName,
                                       CK_VERSION_PTR pVersion,
                                       CK_INTERFACE_PTR_PTR ppInterface,
                                       CK_FLAGS flags) {
    dbg_trace("Adapting NSS interface\n  pInterfaceName = \"%s\", "
              "pVersion = %p, ppInterface = %p, flags = %lu",
              pInterfaceName, (void *)pVersion, (void *)ppInterface, flags);
    if (nss_initialization_failed) {
        dbg_trace("NSS Initialization failed");
        return CKR_GENERAL_ERROR;
    }
    if (pInterfaceName != NULL) {
        dbg_trace("Only the default interface is supported by this adapter");
        return CKR_GENERAL_ERROR;
    }
    if (decorated_interface.pFunctionList == &decorated_func_list) {
        // Already initialized.
        *ppInterface = &decorated_interface;
        return CKR_OK;
    }

    CK_INTERFACE_PTR pInterface = NULL;
    CK_RV ret = FC_GetInterface(pInterfaceName, pVersion, &pInterface, flags);
    dbg_trace("Called NSS FC_GetInterface()\n  ret = " CKR_FMT, ret);
    if (ret == CKR_OK) {
        // Save non-decorated original function list, for internal use.
        global_data.orig_funcs_list = pInterface->pFunctionList;
        CK_VERSION_PTR version = &global_data.orig_funcs_list->version;

        // Clone returned structures.
        memcpy(&decorated_interface, pInterface, sizeof(decorated_interface));
        memcpy(&decorated_func_list, global_data.orig_funcs_list,
               version->major == 3 ? sizeof(CK_FUNCTION_LIST_3_0)
                                   : sizeof(CK_FUNCTION_LIST));

        // Decorate functions.
        decorated_func_list.C_CreateObject = C_CreateObject;
        decorated_func_list.C_GetAttributeValue = C_GetAttributeValue;
        decorated_func_list.C_Initialize = C_Initialize;

        // Update pointers.
        decorated_interface.pFunctionList = &decorated_func_list;
        *ppInterface = &decorated_interface;
        dbg_trace("NSS PKCS #11 v%d.%d, software token successfully adapted",
                  version->major, version->minor);
    }
    return ret;
}

EXPORTED_FUNCTION CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    dbg_trace("Forwarding to C_GetInterface()\n  "
              "ppFunctionList = %p",
              (void *)ppFunctionList);
    CK_INTERFACE_PTR pInterface;
    CK_RV ret = C_GetInterface(NULL, NULL, &pInterface, 0);
    if (ret == CKR_OK) {
        *ppFunctionList = pInterface->pFunctionList;
    }
    return ret;
}

/* ****************************************************************************
 * Library constructor/destructor
 * ****************************************************************************/

static void CONSTRUCTOR_FUNCTION library_constructor(void) {
    dbg_initialize();
    SECStatus res = NSS_NoDB_Init(NULL);
    if (res != SECSuccess) {
        // NOTE: SECWouldBlock = -2, SECFailure = -1, SECSuccess = 0.
        dbg_trace("NSS_NoDB_Init() has failed with res = %d", res);
        nss_initialization_failed = true;
    }
}

static void DESTRUCTOR_FUNCTION library_destructor(void) {
    // Destroy import / export key, if created.
    if (IEK.session != CK_INVALID_HANDLE) {
        P11.C_CloseSession(IEK.session);
    }
    dbg_finalize();
}
