#include <openssl/core.h>
#include <openssl/core_names.h>
#include "vpd_cipher.h" // include cipher dispatch table
#include <openssl/core_dispatch.h>

const OSSL_ALGORITHM vpd_ciphers[] = {
    { "VPD", NULL, vpd_cipher_functions, NULL },
    { NULL, NULL, NULL, NULL }
};


const OSSL_ALGORITHM *vpd_query(
    void *provctx,
    int operation_id,
    int *no_cache)
{
    *no_cache = 0;

    if (operation_id == OSSL_OP_CIPHER)
        return vpd_ciphers;

    return NULL;
}


const OSSL_DISPATCH vpd_provider_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))vpd_query },
    { 0, NULL }
};


int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    *out = vpd_provider_dispatch;
    *provctx = NULL;
    return 1;
}

