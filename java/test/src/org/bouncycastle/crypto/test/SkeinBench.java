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
package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.Skein;

public class SkeinBench {

    /**
     * Benchmarks an instance of the Skein hash function.
     *
     * @param iterations 
     *     Number of hash computations to perform.
     * @param skein
     *     Resulting speed in megabytes per second.
     * @param warmup
     *     If set then don't print results, just warmup JIT compiler
     * @return
     */
    public double Benchmark(long iterations, Skein skein, boolean warmup) {
        int hashBytes = skein.getHashSize() / 8;
        byte[] hash = new byte[hashBytes];

        long start = System.currentTimeMillis();

        for (long i = 0; i < iterations; i++)
            skein.update(hash, 0, hashBytes);

        hash = skein.doFinal();
        
        if (warmup)
            return 0.0;
        
        long stop = System.currentTimeMillis();

        long duration = stop - start;

        double opsPerTick = iterations / (double) duration;
        double opsPerSec = opsPerTick * 1000;

        double mbs = opsPerSec * hashBytes / 1024 / 1024;
        System.out.println("duration: " + duration + "ms, ops per tick: "
                + opsPerTick);
        System.out.println("ops per sec: " + opsPerSec + ", mbs: " + mbs);

        return 0.0;
    }

    public static void main(String args[]) {

        try {
            SkeinBench skb = new SkeinBench();
            skb.Benchmark(1000000, new Skein(512, 512), true);
            skb.Benchmark(10000000, new Skein(512, 512), false);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Skein benchmark done.");
    }
}
