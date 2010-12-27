package org.bouncycastle.crypto.test;

import java.util.Random;
import java.util.zip.GZIPOutputStream;
import java.io.*;

import org.bouncycastle.crypto.prng.*;

/**
 * This class implements a small  test for the Fortuna PRNG
 * 
 * The test creates 64*1024 blocks of 1024 bytes of random numbers (in 
 * total 64MB)and writes them to a compressedfile (GZIP). The function
 * uses every other block as additional entropy (seed). A real application
 * shall use other entropy, for example microphone input, video data,
 * or other random data or events. 
 * 
 * Even without continous seeding (only initial seed with some random data)
 * the generator delivers random numbers in high quality, at least for 
 * this 64MB test.
 * 
 * The compressed file should be around 64MB because you can't compress files
 * that consist of real random numbers only - this however is a quick test
 * only :-) .
 */
public class FortunaTest {
    public static void main(String args[]) {
        writeFortuna();
        System.out.println("FortunaTest done");
    }

    public static void writeFortuna() {
        try {
            OutputStream out = new GZIPOutputStream(new FileOutputStream("testfortuna"));
            FortunaGenerator f = getFortuna();
            byte buf[] = new byte[1024];
            for (int i = 0; i < 64*1024; i++) {
                f.nextBytes(buf);
                out.write(buf);
                if ((i%2) == 0) {
                    f.addSeedMaterial(buf);
                }
            }
            out.close();
        } catch (Exception ioe) { ioe.printStackTrace(); }
    }

    /*
     * Get Fortuna Generator and use some random data as first
     * seed.
     */
    private static FortunaGenerator getFortuna() {
        byte buf[] = new byte[1024];
        new Random().nextBytes(buf);
        FortunaGenerator f = new FortunaGenerator(buf);
        return f;
    }
}
