/**
 * Stub for bz_internal_error required when BZ_NO_STDIO is defined.
 * The upstream bzip2 library normally defines this in bzlib.c when
 * stdio is available, but with BZ_NO_STDIO it must be provided externally.
 */

#include "bzlib.h"

#ifdef BZ_NO_STDIO

void bz_internal_error(int errcode) {
    /* On embedded: could log or halt. For now, just return and let
       the caller handle the BZ_* error code. */
    (void)errcode;
}

#endif
