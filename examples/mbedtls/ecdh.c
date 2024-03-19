#include "benchmark.h"
#include <mbedtls/ecdh.h>
#include <string.h>

[[clang::obelix("extern")]] extern int OBELIX(mbedtls_ecdh_compute_shared)(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng);


uint8_t ecdhOurD[] = { 0x49, 0x6b, 0xd0, 0xa7, 0xd4, 0xc5, 0xda, 0x01, 0x54, 0xe3, 0xa9, 0x91, 0x5d, 0xda, 0x43, 0xfd, 0xd5, 0x87, 0x67, 0x05, 0xb1, 0x6c, 0xd8, 0x21, 0x19, 0xc2, 0x81, 0x2e, 0x83, 0x61, 0x15, 0xf8 };
uint8_t ecdhOurQ[] = { 0x59, 0xa5, 0xeb, 0x93, 0x5e, 0x89, 0xfa, 0xa7, 0x94, 0x9d, 0xf0, 0xfa, 0x75, 0xbd, 0x05, 0x39, 0xc0, 0x43, 0x05, 0x92, 0xdb, 0x56, 0xe4, 0x84, 0x76, 0xfb, 0x75, 0x80, 0x6b, 0xfe, 0x21, 0x7a };

uint8_t plain[32] = { 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11, 0xc0, 0xff, 0xee, 0x11};

extern int _obelix_rng(void *context, uint8_t *buffer, size_t length);

int main(void)
{
    int result = 0;
    
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

    // Generate new remote public key
    mbedtls_mpi theirD;
    mbedtls_ecp_point theirQ;
    mbedtls_mpi_init(&theirD);
    mbedtls_ecp_point_init(&theirQ);
    mbedtls_ecdh_gen_public(&grp, &theirD, &theirQ, _obelix_rng, NULL);

    mbedtls_mpi ourD;
    mbedtls_mpi secret;
    uint8_t secretBuf[256];
    size_t secretLen;

    MEASUREMENT_BASELINE_START(1)
    {
        mbedtls_mpi_init(&ourD);
        result = mbedtls_mpi_read_binary(&ourD, ecdhOurD, sizeof(ecdhOurD));
        if(result)
            fprintf(stderr, "Error %d\n", result);

        mbedtls_mpi_init(&secret);
        result = mbedtls_ecdh_compute_shared(&grp, &secret, &theirQ, &ourD, _obelix_rng, NULL);
        if(result)
            fprintf(stderr, "Error %d\n", result);

        secretLen = mbedtls_mpi_size(&secret);
        mbedtls_mpi_write_binary(&secret, secretBuf, secretLen);
    }
    MEASUREMENT_BASELINE_END()

    fprintf(stderr, "Result: %d\n", result);
    fprintf(stderr, "Secret: ");
    dump_bytes(stderr, secretBuf, secretLen);

    memset(&secretBuf, 1, sizeof(secretBuf));
    memset(&ourD, 2, sizeof(ourD));
    memset(&secret, 3, sizeof(secret));

    MEASUREMENT_INSTRUMENTED_START()
    {
        mbedtls_mpi_init(&ourD);
        result = mbedtls_mpi_read_binary(&ourD, ecdhOurD, sizeof(ecdhOurD));
        if(result)
            fprintf(stderr, "Error %d\n", result);

        mbedtls_mpi_init(&secret);
        result = OBELIX(mbedtls_ecdh_compute_shared)(&grp, &secret, &theirQ, &ourD, _obelix_rng, NULL);
        if(result)
            fprintf(stderr, "Error %d\n", result);

        secretLen = mbedtls_mpi_size(&secret);
        mbedtls_mpi_write_binary(&secret, secretBuf, secretLen);
    }
    MEASUREMENT_INSTRUMENTED_END()

    fprintf(stderr, "Result: %d\n", result);
    fprintf(stderr, "Secret: ");
    dump_bytes(stderr, secretBuf, secretLen);

    return 0;
}
