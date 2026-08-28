/*
 * libm_shim.c - minimal log() and ceil() for libbloom
 *
 * bloom_init() is the only caller of log() and ceil() in the whole program.
 * Pulling them from libm links in its log/exp lookup tables, which cost more
 * than the bloom filter code itself in a static build. Defining them here
 * keeps the linker from touching libm at all, the same trick as
 * vendor/sodium_shim.c.
 *
 * Accuracy barely matters: the results only size the bloom filter, a value
 * that never leaves the process. They still match musl to within 1e-15.
 */

#include <math.h>

/* log(x) = log(m) + e*ln2 with x = m * 2^e. After narrowing m around
 * sqrt(2)/2, the atanh series log(m) = 2*atanh((m-1)/(m+1)) converges fast.
 */
double
log(double x)
{
    double m, z, z2, term, sum;
    int e, k;

    if (x != x)                     /* NaN */
        return x;
    if (x < 0.0)
        return (x - x) / 0.0;       /* NaN */
    if (x == 0.0)
        return -1.0 / 0.0;          /* -inf */

    m = frexp(x, &e);               /* m in [0.5, 1) */
    if (m < 0.70710678118654752440) {
        m *= 2.0;
        e--;
    }

    z    = (m - 1.0) / (m + 1.0);
    z2   = z * z;
    term = z;
    sum  = 0.0;
    for (k = 1; k < 40; k += 2) {
        sum  += term / (double)k;
        term *= z2;
    }

    return 2.0 * sum + (double)e * 0.69314718055994530942;
}

double
ceil(double x)
{
    double t;

    /* Outside this range a double is already an integer */
    if (!(x > -4503599627370496.0 && x < 4503599627370496.0))
        return x;

    t = (double)(long long)x;       /* truncate toward zero */
    if (x > 0.0 && t < x)
        t += 1.0;
    return t;
}
