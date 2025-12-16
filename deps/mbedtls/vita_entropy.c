/*
 * PS Vita entropy source for mbedTLS
 * 
 * This provides a basic entropy source for PS Vita using
 * platform-specific random number generation.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(VITA) && defined(MBEDTLS_ENTROPY_C)

#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"
#include <stdlib.h>
#include <time.h>

int mbedtls_vita_entropy_poll(void *data,
                                unsigned char *output, 
                                size_t len, 
                                size_t *olen)
{
    size_t i;
    static int initialized = 0;
    
    (void) data;
    
    /* Initialize random seed on first call */
    if (!initialized)
    {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }
    
    /* Fill output buffer with random bytes */
    for (i = 0; i < len; i++)
    {
        output[i] = (unsigned char)(rand() & 0xFF);
    }
    
    *olen = len;
    return 0;
}

#endif /* VITA && MBEDTLS_ENTROPY_C */
