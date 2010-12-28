
#ifndef SKEINMACAPI_H
#define SKEINMACAPI_H

/**
 * @file SkeinMACApi.h
 * @brief Convenience API for Skein MAC functions
 *
 * Defines an API to use Skein as a MAC.
 *
 * @{
 */

#include "skein.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Which Skein size to use
     */
    typedef enum SkeinSize {
        Skein256 = 256,
        Skein512 = 512,
        Skein1024 = 1024
    } SkeinSize_t;
    
    /**
     * Context for Skein MAC.
     * 
     * This structure was setup with some know-how of the internal
     * Skein structures, in particular ordering of header and size dependent
     * variables. If Skein implementation changes this, the adapt these
     * structures as well.
     */
    typedef struct SkeinMacCtx {
        u64b_t skeinSize;
        u64b_t  XSave[SKEIN1024_STATE_WORDS];   /* saved chaining variables, max number */
        union {
            Skein_Ctxt_Hdr_t h;
            Skein_256_Ctxt_t s256;
            Skein_512_Ctxt_t s512;
            Skein1024_Ctxt_t s1024;
        } m;
    } SkeinMacCtx_t;

    /**
     * Prepare a Skein MAC context.
     * 
     * An application must call this function before it can use the Skein MAC
     * context. The functions clears memory and initializes size dependent
     * variables.
     *
     * @param ctx
     *     Pointer to a Skein MAC context.
     * @param size
     *     Which Skein size to use.
     * @return
     *     SKEIN_SUCESS of SKEIN_FAIL
     */
    int skeinMacCtxPrepare(SkeinMacCtx_t* ctx, SkeinSize_t size);

    /**
     * Initializes or reuses a Skein MAC Context.
     *
     * If the parameters @c key, @c keyLen, and @c hashBitLen are set then
     * SkeinMacInit initializes the Skein has with these data and saves the
     * resulting chaining variables for further use.
     *
     * If @c key is NULL and @c keyLen is zero and @c hashBitLen is zero
     * then SkeinMacCtx uses the saved chaining variables to initialze
     * the Skein context. Application can use this if they need to use
     * the same @c key, @c keyLen, and @c hashBitLen to authenticate
     * several messages and it saves a complete Skein initialization cycle.
     *
     * @param ctx
     *     Pointer to an empty or preinitialized Skein MAC context
     * @param key
     *     Pointer to key bytes or NULL
     * @param keyLen
     *     Length of the key in bytes or zero
     * @param hashBitLen
     *     Number of MAC hash bits to compute or zero
     * @return
     *     Success or error code.
     */
    int skeinMacInit(SkeinMacCtx_t* ctx, const uint8_t *key, size_t keyLen,
                     size_t hashBitLen);

    /**
     * Update the Skein MAC with the next part of the message.
     *
     * @param ctx
     *     Pointer to initialized Skein MAC context
     * @param msg
     *     Pointer to the message.
     * @param msgByteCnt
     *     Length of the message in bytes
     * @return
     *     Success or error code.
     */
    int skeinMacUpdate(SkeinMacCtx_t *ctx, const uint8_t *msg,
                       size_t msgByteCnt);

    /**
     * Finalize the Skein MAC and return the MAC.
     *
     * @param ctx
     *     Pointer to initialized Skein MAC context
     * @param macVal
     *     Pointer to buffer that receives the MAC. The buffer must be large
     *     enough to store @c hashBitLen bits.
     * @return
     *     Success or error code.
     */
    int skeinMacFinal (SkeinMacCtx_t* ctx, uint8_t* macVal);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */
#endif
