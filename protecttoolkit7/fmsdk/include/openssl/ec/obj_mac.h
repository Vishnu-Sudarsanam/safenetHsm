/* crypto/objects/obj_mac.h */

/* THIS FILE IS GENERATED FROM objects.txt by objects.pl via the
 * following command:
 * perl objects.pl objects.txt obj_mac.num obj_mac.h
 */

/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#define NID_X9_62_prime_field		406
#define NID_X9_62_characteristic_two_field		407

#define NID_X9_62_prime192v1		409
#define NID_X9_62_prime192v2		410
#define NID_X9_62_prime192v3		411
#define NID_X9_62_prime239v1		412
#define NID_X9_62_prime239v2		413
#define NID_X9_62_prime239v3		414
#define NID_X9_62_prime256v1		415

#define NID_X9_62_c2pnb163v1		507
#define NID_X9_62_c2pnb163v2		508
#define NID_X9_62_c2pnb163v3		509
#define NID_X9_62_c2pnb176v1		510
#define NID_X9_62_c2tnb191v1		511
#define NID_X9_62_c2tnb191v2		512
#define NID_X9_62_c2tnb191v3		513
#define NID_X9_62_c2onb191v4		514
#define NID_X9_62_c2onb191v5		515
#define NID_X9_62_c2pnb208w1		516
#define NID_X9_62_c2tnb239v1		517
#define NID_X9_62_c2tnb239v2		518
#define NID_X9_62_c2tnb239v3		519
#define NID_X9_62_c2onb239v4		520
#define NID_X9_62_c2onb239v5		521
#define NID_X9_62_c2pnb272w1		522
#define NID_X9_62_c2pnb304w1		523
#define NID_X9_62_c2tnb359v1		524
#define NID_X9_62_c2pnb368w1		525
#define NID_X9_62_c2tnb431r1		526

#define NID_secp112r1		529
#define NID_secp112r2		530
#define NID_secp128r1		531
#define NID_secp128r2		532
#define NID_secp160k1		533
#define NID_secp160r1		534
#define NID_secp160r2		535
#define NID_secp192k1		536
#define NID_secp224k1		538
#define NID_secp224r1		539
#define NID_secp256k1		540
#define NID_secp384r1		542
#define NID_secp521r1		543

#define NID_sect113r1		544
#define NID_sect113r2		545
#define NID_sect131r1		546
#define NID_sect131r2		547
#define NID_sect163k1		548
#define NID_sect163r1		549
#define NID_sect163r2		550
#define NID_sect193r1		551
#define NID_sect193r2		552
#define NID_sect233k1		553
#define NID_sect233r1		554
#define NID_sect239k1		555
#define NID_sect283k1		556
#define NID_sect283r1		557
#define NID_sect409k1		558
#define NID_sect409r1		559
#define NID_sect571k1		560
#define NID_sect571r1		561
 
#define NID_wap_wsg_idm_ecid_wtls1		564
#define NID_wap_wsg_idm_ecid_wtls3		709
#define NID_wap_wsg_idm_ecid_wtls4		710
#define NID_wap_wsg_idm_ecid_wtls5		711
#define NID_wap_wsg_idm_ecid_wtls6		565
#define NID_wap_wsg_idm_ecid_wtls7		712
#define NID_wap_wsg_idm_ecid_wtls8		566
#define NID_wap_wsg_idm_ecid_wtls9		567
#define NID_wap_wsg_idm_ecid_wtls10		713
#define NID_wap_wsg_idm_ecid_wtls11		714
#define NID_wap_wsg_idm_ecid_wtls12		715


// Not sure if these definitions are required or not, or how they are used.  But I'm defining them anyway.
// Is there an official definition for these values?

#define NID_brainpool_p160r1     800
#define NID_brainpool_p160t1     801
#define NID_brainpool_p192r1     802
#define NID_brainpool_p192t1     803
#define NID_brainpool_p224r1     804
#define NID_brainpool_p224t1     805
#define NID_brainpool_p256r1     806
#define NID_brainpool_p256t1     807
#define NID_brainpool_p320r1     808
#define NID_brainpool_p320t1     809
#define NID_brainpool_p384r1     810
#define NID_brainpool_p384t1     811
#define NID_brainpool_p512r1     812
#define NID_brainpool_p512t1     813

