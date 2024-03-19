#include "benchmark.h"
#include <mbedtls/aes.h>
#include <string.h>

[[clang::obelix("extern")]] extern int OBELIX(mbedtls_aes_crypt_ecb)(mbedtls_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16]);
[[clang::obelix("extern")]] extern int OBELIX(mbedtls_aes_setkey_enc)(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits);

uint8_t key[16] = { 0 };
uint8_t plain[16] = { 0 };

int main(void)
{
    int result = 0;
    uint8_t cipher[16];

    mbedtls_aes_context aes;

    MEASUREMENT_BASELINE_START(1000)
    {
        result = mbedtls_aes_setkey_enc(&aes, key, 128);
        result = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plain, cipher);
    }
    MEASUREMENT_BASELINE_END()

    fprintf(stderr, "Result: %d\n", result);
    dump_bytes(stderr, (uint8_t *)&cipher, sizeof(cipher));
    memset(cipher, 0, sizeof(cipher));

    MEASUREMENT_INSTRUMENTED_START()
    {
        result = OBELIX(mbedtls_aes_setkey_enc)(&aes, key, 128);
        result = OBELIX(mbedtls_aes_crypt_ecb)(&aes, MBEDTLS_AES_ENCRYPT, plain, cipher);
    }
    MEASUREMENT_INSTRUMENTED_END()

    fprintf(stderr, "Result: %d\n", result);
    dump_bytes(stderr, (uint8_t *)&cipher, sizeof(cipher));

    return 0;
}
