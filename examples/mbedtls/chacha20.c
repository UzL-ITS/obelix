#include "benchmark.h"
#include <mbedtls/chachapoly.h>
#include <string.h>

[[clang::obelix("extern")]] extern int OBELIX(mbedtls_chachapoly_setkey)(mbedtls_chachapoly_context *ctx, const unsigned char key[32]);
[[clang::obelix("extern")]] extern int OBELIX(mbedtls_chachapoly_encrypt_and_tag)(mbedtls_chachapoly_context *ctx, size_t length, const unsigned char nonce[12], const unsigned char *aad, size_t aad_len, const unsigned char *input, unsigned char *output, unsigned char tag[16]);

const uint8_t key[32] = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };
const uint8_t plain[32] = { 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11};
const uint8_t nonce[12] = { 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };

int main(void)
{
    int result = 0;
    uint8_t cipher[32];
    uint8_t tag[16];

    mbedtls_chachapoly_context chacha;
    mbedtls_chachapoly_init(&chacha);

    MEASUREMENT_BASELINE_START(1000)
    {
        result = mbedtls_chachapoly_setkey(&chacha, key);
        result = mbedtls_chachapoly_encrypt_and_tag(&chacha, sizeof(plain), nonce, NULL, 0, plain, cipher, tag);
    }
    MEASUREMENT_BASELINE_END()

    fprintf(stderr, "Result: %d\n", result);
    fprintf(stderr, "Cipher: ");
    dump_bytes(stderr, cipher, sizeof(cipher));
    fprintf(stderr, "Tag: ");
    dump_bytes(stderr, tag, sizeof(tag));

    memset(cipher, 1, sizeof(cipher));
    memset(tag, 2, sizeof(tag));

    MEASUREMENT_INSTRUMENTED_START()
    {
        result = OBELIX(mbedtls_chachapoly_setkey)(&chacha, key);
        result = OBELIX(mbedtls_chachapoly_encrypt_and_tag)(&chacha, sizeof(plain), nonce, NULL, 0, plain, cipher, tag);
    }
    MEASUREMENT_INSTRUMENTED_END()

    fprintf(stderr, "Result: %d\n", result);
    fprintf(stderr, "Cipher: ");
    dump_bytes(stderr, cipher, sizeof(cipher));
    fprintf(stderr, "Tag: ");
    dump_bytes(stderr, tag, sizeof(tag));

    return 0;
}
