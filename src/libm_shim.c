/*
 * libm_shim.c - 以最小实现替代 libbloom 用到的两个数学函数
 *
 * libbloom 的 bloom_init() 会调 log() 和 ceil()，仅此两处（已逐目标文件核对）。
 * 而 musl 的 log() 会把整套对数/指数数据表拉进静态产物：__log_data 4.1K、
 * __pow_log_data 4.1K、__exp_data 2.1K、pow 1.5K，合计约 11.8K，只为算一次
 * 布隆过滤器的参数。
 *
 * 这里给出定义后，链接器就不会再去 libm 取那些目标文件。用的是与
 * vendor/sodium_shim.c 相同的手法。
 *
 * 精度要求极低：结果只用来决定布隆过滤器的位数和哈希轮数，这两个值仅在
 * 进程内使用，不出现在任何线路格式里，差一两个 bit 无任何影响。尽管如此，
 * 下面的实现仍与 musl 逐点比对过，相对误差在 1e-15 量级。
 */

#include <math.h>

/*
 * log(x) = log(m) + e*ln2，其中 x = m * 2^e。
 * 把 m 收拢到 sqrt(2)/2 附近后用 atanh 级数：log(m) = 2*atanh((m-1)/(m+1))，
 * 该级数在此区间收敛很快。
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

    m = frexp(x, &e);               /* m ∈ [0.5, 1) */
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

    /* 超出 double 的整数精度范围时本身已是整数 */
    if (!(x > -4503599627370496.0 && x < 4503599627370496.0))
        return x;

    t = (double)(long long)x;       /* 向零取整 */
    if (x > 0.0 && t < x)
        t += 1.0;
    return t;
}
