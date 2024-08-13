
#ifndef X942DH_H_
#define X942DH_H_

#include "../bn/bn.h"               /* BIGNUM library */

#define X9_42_MAX_SEED_LENGTH BYTES_IN_BITS(512)
#define X942_BN_SIZE 4096 + 1024

/**
 * Struct Definitions
 */
typedef struct dh_x9_42_comp_st X9_42_DH_COMP;
typedef struct dh_X9_42_domain_st X9_42_DH_DOMAIN;
typedef struct dh_X9_42_pub_key_st X9_42_DH_PUB_KEY;
typedef struct dh_X9_42_priv_key_st X9_42_DH_PRI_KEY;
typedef struct dh_X9_42_st X9_42_DH_CTX;

struct dh_X9_42_domain_st
   {
   BN_DeclareInStructure(p, X942_BN_SIZE);
   BN_DeclareInStructure(q, X942_BN_SIZE);
   BN_DeclareInStructure(g, X942_BN_SIZE);
   unsigned char seed[X9_42_MAX_SEED_LENGTH];
   uint32_t seedLen;
   uint32_t pgenCounter;
   };

struct dh_X9_42_pub_key_st
   {
   BN_DeclareInStructure(y, X942_BN_SIZE);
   };

struct dh_X9_42_priv_key_st
   {
   BN_DeclareInStructure(x, X942_BN_SIZE);
   };

struct dh_X9_42_st
   {
   struct dh_X9_42_domain_st* dom;
   struct dh_X9_42_pub_key_st* pub;
   struct dh_X9_42_priv_key_st* pri;
   int fw_unlock;
   };

struct dh_x9_42_comp_st
   {
   BN_DeclareInStructure(Y, X942_BN_SIZE);
   BN_DeclareInStructure(k, X942_BN_SIZE);
   };


/**
 * Helper functions to manage structs
 */

void X9_42_DH_dom_init(X9_42_DH_DOMAIN *dom);
void X9_42_DH_dom_copy(X9_42_DH_DOMAIN *to, X9_42_DH_DOMAIN *from);

void X9_42_DH_dom_release(X9_42_DH_DOMAIN *dom);
void X9_42_DH_dom_release_clean(X9_42_DH_DOMAIN *dom);

void X9_42_DH_pri_key_init(X9_42_DH_PRI_KEY *k);
void X9_42_DH_pri_key_copy(X9_42_DH_PRI_KEY *to, X9_42_DH_PRI_KEY *from);

void X9_42_DH_pri_key_release(X9_42_DH_PRI_KEY *k);
void X9_42_DH_pri_key_release_clean(X9_42_DH_PRI_KEY *k);

void X9_42_DH_pub_key_init(X9_42_DH_PUB_KEY *k);
void X9_42_DH_pub_key_copy(X9_42_DH_PUB_KEY *to, X9_42_DH_PUB_KEY *from);

void X9_42_DH_pub_key_release(X9_42_DH_PUB_KEY *k);
void X9_42_DH_pub_key_release_clean(X9_42_DH_PUB_KEY *k);

void X9_42_DH_ctx_init(X9_42_DH_CTX *dh, X9_42_DH_DOMAIN *dom, X9_42_DH_PUB_KEY *pub, X9_42_DH_PRI_KEY *pri, int fw_unlock);
void X9_42_DH_ctx_copy(X9_42_DH_CTX *to, X9_42_DH_CTX *from);

void X9_42_DH_ctx_release(X9_42_DH_CTX *dh);
void X9_42_DH_ctx_release_clean(X9_42_DH_CTX *dh);

void X9_42_DH_comp_init(X9_42_DH_COMP *comp);
void X9_42_DH_comp_release(X9_42_DH_COMP *comp);

/**
 * Domain Parameter Generation
 */
X9_42_DH_DOMAIN *DH_X9_42_generate_parameters_primes(X9_42_DH_DOMAIN *dom, unsigned int L, unsigned int m, int fw_unlock);
X9_42_DH_DOMAIN * DH_X9_42_generate_parameters_base(X9_42_DH_DOMAIN *dom, int fw_unlock);

/**
 * Key pair generation
 */
int dh_x9_42_generate_key(X9_42_DH_CTX *ctx);
int X9_42_DH_VerifyPublicKey(X9_42_DH_DOMAIN *dom, BIGNUM *pub, int fw_unlock);

/**
 * Key Derivation
 */
int X9_42_DH_compute_key(X9_42_DH_CTX *dh, X9_42_DH_COMP *comp);

#endif /* X942DH_H_ */
