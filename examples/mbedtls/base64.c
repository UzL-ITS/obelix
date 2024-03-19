#include "benchmark.h"
#include <mbedtls/base64.h>
#include <string.h>

[[clang::obelix("extern")]] extern int OBELIX(mbedtls_base64_encode)(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
[[clang::obelix("extern")]] extern int OBELIX(mbedtls_base64_decode)(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);

uint8_t plain[32] = { 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11};

int main(void)
{
    int result = 0;
    uint8_t data1[64];
    uint8_t data2[64];
    size_t dataLen1;
    size_t dataLen2;

    MEASUREMENT_BASELINE_START(1000)
    {
        result = mbedtls_base64_encode(data1, sizeof(data1), &dataLen1, plain, sizeof(plain));
        if(result)
            fprintf(stderr, "Error %d\n", result);
        result = mbedtls_base64_decode(data2, sizeof(data2), &dataLen2, data1, dataLen1);
    }
    MEASUREMENT_BASELINE_END()

    fprintf(stderr, "Result: %d\n", result);
    fprintf(stderr, "Encoded: %*s\n", (int)dataLen1, (char *)&data1[0]);
    fprintf(stderr, "Decoded: ");
    dump_bytes(stderr, data2, dataLen2);

    memset(data1, 1, sizeof(data1));
    memset(data2, 2, sizeof(data2));

    MEASUREMENT_INSTRUMENTED_START()
    {
        result = OBELIX(mbedtls_base64_encode)(data1, sizeof(data1), &dataLen1, plain, sizeof(plain));
        if(result)
            fprintf(stderr, "Error %d\n", result);
        result = OBELIX(mbedtls_base64_decode)(data2, sizeof(data2), &dataLen2, data1, dataLen1);
    }
    MEASUREMENT_INSTRUMENTED_END()

    fprintf(stderr, "Result: %d\n", result);
    fprintf(stderr, "Encoded: %*s\n", (int)dataLen1, (char *)&data1[0]);
    fprintf(stderr, "Decoded: ");
    dump_bytes(stderr, data2, dataLen2);

    return 0;
}
