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

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.MatchResult;

import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersForSkein;

import static org.junit.Assert.assertTrue;
import org.junit.*;

public class SkeinTest {

    int notProcessed = 0;

    int processed = 0;
    
    KatScanner scanner;

    public SkeinTest() {
    }

    boolean checkKATVectors() {
        KatResult kr = new KatResult();
        ParametersForSkein pfs;

        while (scanner.fillResult(kr)) {
            // Skip Tree vectors in this test function
            if (kr.restOfLine.contains("Tree")) {
                notProcessed++;
                continue;
            }
            if (kr.restOfLine.contains("MAC")) {
                pfs = new ParametersForSkein(new KeyParameter(kr.macKey),
                        kr.stateSize, kr.hashBitLength);
                SkeinMac sm = new SkeinMac();

                sm.init(pfs);
                sm.updateBits(kr.msg, 0, kr.msgLength);
                byte[] mac = new byte[(sm.getMacSize() + 7) / 8];
                sm.doFinal(mac, 0);

                if (!Arrays.equals(mac, kr.result)) {
                    System.out.println(kr.stateSize + "-" + kr.hashBitLength
                            + "-" + kr.msgLength + "-" + kr.restOfLine);
                    hexdump("Computed mac", mac, mac.length);
                    hexdump("Expected result", kr.result, kr.result.length);
                    return false;
                }
                processed++;
                continue;
            }
            Skein skein = new Skein(kr.stateSize, kr.hashBitLength);
            skein.updateBits(kr.msg, 0, kr.msgLength);
            byte[] hash = skein.doFinal();
            if (!Arrays.equals(hash, kr.result)) {
                System.out.println(kr.stateSize + "-" + kr.hashBitLength + "-"
                        + kr.msgLength + "-" + kr.restOfLine);
                hexdump("Computed hash", hash, hash.length);
                hexdump("Expected result", kr.result, kr.result.length);
                return false;
            }
            // Enable the next few line so you can check some results manually
            // if ((kr.msgLength & 1) == 1) {
            // System.out.println(kr.stateSize + "-" + kr.hashBitLength + "-"
            // + kr.msgLength + "-" + kr.restOfLine);
            // hexdump("Computed hash", hash, hash.length);
            // hexdump("Expected result", kr.result, kr.result.length);
            // }
            processed++;
        }
        return true;
    }

    @Before
    public void setUp() {
        scanner = new KatScanner("../data/skein_golden_kat.txt");
    }

    @Test
    public void vectorTest() {
        try {
            assertTrue(checkKATVectors());
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (notProcessed != 0)
            System.out.println("Processed vectors: " + processed
                    + ", some vectors skipped (Tree): " + notProcessed);
        else
            System.out.println("Processed vectors: " + processed);

    }

    public static void main(String args[]) {


        try {
            SkeinTest skt = new SkeinTest();
            skt.setUp();
            skt.vectorTest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Skein test done.");
    }

    private static final char[] hex = "0123456789abcdef".toCharArray();

    /**
     * Dump a buffer in hex and readable format.
     * 
     * @param title
     *            Printed at the beginning of the dump
     * @param buf
     *            Byte buffer to dump
     * @param len
     *            Number of bytes to dump, should be less or equal the buffer
     *            length
     */
    public static void hexdump(String title, byte[] buf, int len) {
        byte b;
        System.err.println(title);
        for (int i = 0;; i += 16) {
            for (int j = 0; j < 16; ++j) {
                if (i + j >= len) {
                    System.err.print("   ");
                }
                else {
                    b = buf[i + j];
                    System.err.print(" " + hex[(b >>> 4) & 0xf] + hex[b & 0xf]);
                }
            }
            System.err.print("  ");
            for (int j = 0; j < 16; ++j) {
                if (i + j >= len)
                    break;
                b = buf[i + j];
                if ((byte) (b + 1) < 32 + 1) {
                    System.err.print('.');
                }
                else {
                    System.err.print((char) b);
                }
            }
            System.err.println();
            if (i + 16 >= len) {
                break;
            }
        }
    }
    
    class KatResult {
        public int stateSize;
        public int hashBitLength;
        public int msgLength;
        public byte[] msg;
        public int msgFill;
        public byte[] result;
        public int resultFill;
        public int macKeyLen;
        public byte[] macKey;
        public int macKeyFill;
        String restOfLine;
    }

    class KatScanner {

        final static int Start = 0;

        final static int Message = 1;

        final static int Result = 2;

        final static int MacKeyHeader = 3;

        final static int MacKey = 4;

        final static int Done = 5;

        private int state = Start;

        private Scanner scanner;

        KatScanner(String fileName) {
            try {
                scanner = new Scanner(new File(fileName));
                scanner.useDelimiter(System.getProperty("line.separator"));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        
        /**
         * Fill in data from KAT file, one complete element at a time.
         * 
         * @param kr The resulting KAT data
         * @return
         */
        boolean fillResult(KatResult kr) {

            boolean dataFound = false;

            while (state != Done && scanner.hasNext()) {
                parseLine(scanner.next(), kr);
                dataFound = true;
            }
            state = Start;
            return dataFound;
        }

        void parseLine(String line, KatResult kr) {

            line = line.trim();
            if (line.length() <= 1)
                return;

            if (line.startsWith("Message")) {
                state = Message;
                return;
            }
            if (line.startsWith("Result")) {
                state = Result;
                return;
            }
            if (line.startsWith("MAC")) {
                state = MacKeyHeader;
            }
            if (line.startsWith("------")) {
                state = Done;
                return;
            }

            switch (state) {
            case Start:
                if (line.startsWith(":Skein-")) {
                    parseHeaderLine(line, kr);
                }
                else {
                    System.out.println("Wrong format found");
                    System.exit(1);
                }
                break;
            case Message:
                parseMessageLine(line, kr);
                break;
            case Result:
                parseResultLine(line, kr);
                break;
            case MacKey:
                parseMacKeyLine(line, kr);
                break;
            case MacKeyHeader:
                parseMacKeyHeaderLine(line, kr);
                break;
            }
        }

        void parseMessageLine(String line, KatResult kr) {
            if (line.contains("(none)")) {
                kr.msg[kr.msgFill++] = 0;
                return;
            }
            Scanner ls = new Scanner(line);
            while (ls.hasNext()) {
                try {
                    kr.msg[kr.msgFill++] = (byte) ls.nextInt(16);
                } catch (Exception e) {
                    System.out.println("Msg data: " + line);
                    e.printStackTrace();
                    System.exit(1);
                }
            }
        }

        void parseMacKeyLine(String line, KatResult kr) {
            if (line.contains("(none)")) {
                return;
            }
            Scanner ls = new Scanner(line);
            while (ls.hasNext()) {
                try {
                    kr.macKey[kr.macKeyFill++] = (byte) ls.nextInt(16);
                } catch (Exception e) {
                    System.out.println("Mac key data: " + line);
                    e.printStackTrace();
                    System.exit(1);
                }
            }
        }

        void parseMacKeyHeaderLine(String line, KatResult kr) {
            Scanner ls = new Scanner(line);
            ls.findInLine(".*=\\s*(\\d+) .*");
            MatchResult result = null;
            try {
                result = ls.match();
            } catch (Exception e) {
                System.out.println("Mac header: " + line);
                e.printStackTrace();
                System.exit(1);
            }
            kr.macKeyLen = Integer.parseInt(result.group(1));
            kr.macKey = new byte[kr.macKeyLen];
            state = MacKey;
        }

        void parseResultLine(String line, KatResult kr) {
            Scanner ls = new Scanner(line);
            while (ls.hasNext()) {
                try {
                    kr.result[kr.resultFill++] = (byte) ls.nextInt(16);
                } catch (Exception e) {
                    System.out.println("Result data: " + line);
                    e.printStackTrace();
                    System.exit(1);
                }
            }
        }

        void parseHeaderLine(String line, KatResult kr) {
            Scanner lineScanner = new Scanner(line);
            lineScanner
                    .findInLine(":Skein-(\\d+):\\s*(\\d+)-.*=\\s*(\\d+) bits(.*)");
            MatchResult result = null;
            try {
                result = lineScanner.match();
            } catch (Exception e) {
                System.out.println("Header line: " + line);
                e.printStackTrace();
                System.exit(1);
            }

            kr.stateSize = Integer.parseInt(result.group(1));
            kr.hashBitLength = Integer.parseInt(result.group(2));
            kr.msgLength = Integer.parseInt(result.group(3));
            kr.restOfLine = result.group(4);

            if ((kr.msgLength == 0) || (kr.msgLength % 8) != 0)
                kr.msg = new byte[(kr.msgLength >> 3) + 1];
            else
                kr.msg = new byte[kr.msgLength >> 3];

            if ((kr.hashBitLength % 8) != 0)
                kr.result = new byte[(kr.hashBitLength >> 3) + 1];
            else
                kr.result = new byte[kr.hashBitLength >> 3];

            kr.msgFill = 0;
            kr.resultFill = 0;
            kr.macKeyFill = 0;
        }
    }
}
