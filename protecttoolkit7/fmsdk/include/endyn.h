/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 *  (c) Copyright 2009-2019 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
#if (_MSC_VER <=1600)
#define inline __inline
#endif

static inline uint16_t swap16(uint16_t i)
{
    return (i << 8) | (i >> 8);
}
static inline uint32_t swap32(uint32_t i)
{
    return (i << 24) | ((i << 8) & 0xff0000UL) | ((i >> 8) & 0xff00UL) | (i >> 24);
}
static inline uint64_t swap64(uint64_t i)
{
    return (uint64_t)swap32((uint32_t)i) << 32 | swap32( (uint32_t) (i >> 32));
}

/*
 * is current platform Big/Little endian?
 */
static inline uint8_t isBE()
{
    uint32_t i = 1;
    return *(uint8_t *)&i != 1;
}

static inline uint8_t isLE() { return !isBE(); }

//
void BigEndianBuf(void *tgt, void *src, size_t len);

static inline uint16_t hton_short(uint16_t val) { return isBE() ? val : swap16(val); }
static inline uint16_t ntoh_short(uint16_t val) { return hton_short(val); }

static inline uint32_t hton_long(uint32_t val) { return isBE() ? val : swap32(val); }
static inline uint32_t ntoh_long(uint32_t val) { return hton_long(val); }

static inline uint64_t hton_longlong(uint64_t val) { return isBE() ? val : swap64(val); }
static inline uint64_t ntoh_longlong(uint64_t val) { return hton_longlong(val); }

#ifndef htole32
static inline uint32_t htole32(uint32_t val)
{
    return isLE() ? val : swap32(val);
}
#endif
#ifndef letoh32
static inline uint32_t letoh32(uint32_t val)
{
    return htole32(val);
}
#endif

#define DEP_FN(T, F, X) \
    static inline T F(T val) { return X(val); }
#define DEP_STR(X) "Use '" #X "' instead"
#if defined(_MSC_VER)
#define DEPRECATED(T, F, X) \
    __declspec(deprecated(DEP_STR(X))) DEP_FN(T, F, X)
#else
#define DEPRECATED(T, F, X) \
    __attribute__((deprecated(DEP_STR(X)))) DEP_FN(T, F, X)
#endif

DEPRECATED(uint16_t, fromBEs, ntoh_short)
DEPRECATED(uint16_t, toBEs, hton_short)
DEPRECATED(uint32_t, fromBEl, ntoh_long)
DEPRECATED(uint32_t, toBEl, hton_long)

#undef DEP_FN
#undef DEP_STR
#undef DEPRECATED

#ifdef __cplusplus
}
#endif
