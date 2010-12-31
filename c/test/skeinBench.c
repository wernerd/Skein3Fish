/*
Copyright (c) 2010 Werner Dittmann

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

*/

#include <skeinApi.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>


double Benchmark(int iterations, SkeinCtx_t* ctx) {

    int hashBytes = ctx->skeinSize / 8;
    uint8_t* hash = (uint8_t*)malloc(hashBytes);
    int i;
    
    double opsPerTick;
    double opsPerSec;
    double mbs;
    
    long start, stop, duration;
    
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    
    start = tv.tv_sec * 1000;
    start += tv.tv_usec / 1000;

    for (i = 0; i < iterations; i++)
        skeinUpdate(ctx, hash, hashBytes);

    skeinFinal(ctx, hash);

    gettimeofday(&tv, NULL);
    stop = tv.tv_sec * 1000;
    stop += tv.tv_usec / 1000;

    duration = stop - start;

    opsPerTick = iterations / (double) duration;
    opsPerSec = opsPerTick * 1000;

    mbs = opsPerSec * hashBytes / 1024 / 1024;
    printf("Duration: %ldms\n", duration);
    printf("Hashes per sec: %.2f, MiB/s: %.2f\n", opsPerSec, mbs);

    return 0.0;
}


int main(int argc, char* argv[])
{

    SkeinCtx_t ctx;
    
    skeinCtxPrepare(&ctx, 512);
    skeinInit(&ctx, 512);

    Benchmark(20000000, &ctx);
    return 0;
}
