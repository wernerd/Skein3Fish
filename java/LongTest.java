
import java.math.*;

public class LongTest {
    
    public LongTest() {}
    
    static byte[] tst1 = {(byte)0xff, (byte)0xfe, (byte)0xfd, (byte)0xfc, (byte)0xfb, (byte)0xfa, (byte)0xf9, (byte)0xf8};
    
    static long GetUInt64(byte[] b, int i) {
        if (i >= b.length + 8) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return  (((b[i++] & 255) | ((b[i++] & 255) << 8) |
                ((b[i++] & 255) << 16) | ((b[i++] & 255) << 24)) & 0xffffffffL) |
                (((b[i++] & 255) | ((b[i++] & 255) << 8) | ((b[i++] & 255) << 16) |
                ((b[i] & 255L) << 24)) << 32);
    }

    static void PutBytes(long[] input, byte[] output, int offset, int byteCount) {
        int j = 0;
        for (int i = 0; i < byteCount; i++) {
            output[offset++] = (byte) ((input[i >> 3] >> j) & 0xff);
            j = (j + 8) & 0x3f; 
        }
    }

    static void setAdd(long[] in, int y) {

        final int len = 3;
        long carry = y;
        
        long words[] = new long[len];
        words[0] = in[0] & 0xffffffffL;
        words[1] = ((in[0] >>> 32) & 0xffffffffL);
        words[2] = (in[1] & 0xffffffffL);
        
        System.out.println("in-0: " + Long.toHexString(in[1]) + Long.toHexString(in[0]));

        for (int i = 0; i < len; i++) {
            carry += words[i];
            words[i] = carry;
            carry >>= 32;
        }        
        in[0] = words[0] & 0xffffffffL;
        in[0] |= (words[1] & 0xffffffffL) << 32;
        in[1] |= words[2] & 0xffffffffL;
        
        System.out.println("in-1: " + Long.toHexString(in[1]) + Long.toHexString(in[0]));
    }

    public static void main(String args[]) {
//        byte[] testVector = new byte[64];
//        for (int i = 0; i < testVector.length; i++)
//            testVector[i] = (byte) (255 - i);
//
//        long v = GetUInt64(testVector, 0);
//        System.out.println("Value: " + Long.toHexString(v));
//
        long[] in = new long[2];
        in[0] = 0;
        in[1] = -1L;
        byte[] out = new byte[16];
        
        PutBytes(in, out, 0, 16);
//        hexdump("out-1", out, 16);
        out[15] = (byte)0x9c;
        
        
        long[] inl = new long[2];
        inl[0] = -100L;
        inl[1] = 0x200000000L;
        
        setAdd(inl, 100);
        setAdd(inl, 100);
        
        BigInteger bn = new BigInteger(out);
        bn = bn.add(new BigInteger("100"));
        System.out.println("BigInteger: " + bn.toString(16));
        bn = bn.add(new BigInteger("100"));
        System.out.println("BigInteger: " + bn.toString(16));
    }

    private static final char[] hex = "0123456789abcdef".toCharArray();
    /**
     * Dump a buffer in hex and readable format.
     * 
     * @param title Printed at the beginning of the dump
     * @param buf   Byte buffer to dump
     * @param len   Number of bytes to dump, should be less or equal 
     *              the buffer length
     */
    public static void hexdump(String title, byte[] buf, int len) {
        byte b;
        System.err.println(title);
        for(int i = 0 ; ; i += 16) {
            for(int j=0; j < 16; ++j) {
                if (i+j >= len) {
                    System.err.print("   ");
                }
                else {
                    b = buf[i+j];
                    System.err.print(" "+ hex[(b>>>4) &0xf] + hex[b&0xf] );
                }
            }
            System.err.print("  ");
            for(int j = 0; j < 16; ++j) {
                if (i+j >= len) break;
                b = buf[i+j];
                if ( (byte)(b+1) < 32+1) {
                    System.err.print( '.' );
                }
                else {
                    System.err.print( (char)b );
                }
            }
            System.err.println();
            if (i+16 >= len) {
                break;
            }
        }
    }

}
