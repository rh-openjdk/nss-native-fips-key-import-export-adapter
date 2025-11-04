// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

#ifndef NSS_ADAPTER_H
#define NSS_ADAPTER_H

#include <pkcs11.h>

// Shared library constructor/initializer and destructor/finalizer
#define CONSTRUCTOR_FUNCTION __attribute__((constructor))
#define DESTRUCTOR_FUNCTION  __attribute__((destructor))
#define EXPORTED_FUNCTION    __attribute__((visibility("default")))
#define UNUSED               __attribute__((unused))

// Global data, see members description in nssadapter.c initialization
typedef struct {
    // Following is the saved non-decorated original function list from NSS, for
    // this adapter's internal use. NOTE: the PKCS #11 v3.0 standard states
    // 'CK_FUNCTION_LIST_3_0 is a structure which contains the same function
    // pointers as in CK_FUNCTION_LIST and additional functions added to the end
    // of the structure that were defined in Cryptoki version 3.0'. This implies
    // that we can safely use CK_FUNCTION_LIST regardless of the version, as
    // long as it contains all the functions we need.
    CK_FUNCTION_LIST_PTR orig_funcs_list; // aliased &P11

    // The following session, key, and mechanism, are used to import and export
    // sensitive keys by means of the C_WrapKey() and C_UnwrapKey() PKCS #11
    // APIs.
    struct {
        CK_SESSION_HANDLE session; // aliased IEK.session
        CK_OBJECT_HANDLE id;       // aliased IEK.id
        CK_MECHANISM mech;         // aliased IEK.mech
    } importer_exporter_key;
} global_data_t;

// Global data accessor and facilities
global_data_t *__get_global_data();
#define IEK (__get_global_data()->importer_exporter_key)
#define P11 (*(__get_global_data()->orig_funcs_list))

#endif // NSS_ADAPTER_H
