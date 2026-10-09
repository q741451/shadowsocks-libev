/*
 * aws-lc-bcm.c - the part of AWS-LC's crypto/fipsmodule/bcm.c that is used
 *
 * bcm.c builds the FIPS module as one translation unit and its sources rely on
 * that, so they are included here the same way: the same prelude, then only
 * the AES, GCM, AEAD and CPU capability sources, in bcm.c's order.
 */
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE  // needed for syscall() on Linux.
#endif

#include <openssl/crypto.h>

#include <stdlib.h>

#include <openssl/chacha.h>
#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "crypto/internal.h"

#include "crypto/fipsmodule/aes/aes.c"
#include "crypto/fipsmodule/aes/aes_nohw.c"
#include "crypto/fipsmodule/aes/key_wrap.c"
#include "crypto/fipsmodule/aes/mode_wrappers.c"
#include "crypto/fipsmodule/cipher/aead.c"
#include "crypto/fipsmodule/cipher/cipher.c"
#include "crypto/fipsmodule/cipher/e_aes.c"
#include "crypto/fipsmodule/cpucap/internal.h"
#include "crypto/fipsmodule/cpucap/cpu_aarch64.c"
#include "crypto/fipsmodule/cpucap/cpu_aarch64_sysreg.c"
#include "crypto/fipsmodule/cpucap/cpu_aarch64_linux.c"
#include "crypto/fipsmodule/cpucap/cpu_arm_linux.c"
#include "crypto/fipsmodule/cpucap/cpu_intel.c"
#include "crypto/fipsmodule/modes/cbc.c"
#include "crypto/fipsmodule/modes/cfb.c"
#include "crypto/fipsmodule/modes/ctr.c"
#include "crypto/fipsmodule/modes/gcm.c"
#include "crypto/fipsmodule/modes/gcm_nohw.c"
#include "crypto/fipsmodule/modes/ofb.c"
#include "crypto/fipsmodule/modes/xts.c"
#include "crypto/fipsmodule/modes/polyval.c"
#include "crypto/fipsmodule/service_indicator/service_indicator.c"
