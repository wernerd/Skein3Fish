/*
Copyright (c) 2010 Alberto Fajardo

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

The tweaks and modifications for Java:
Copyright (c) 2010, Werner Dittmann. 

The same permissions granted.
 */
package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.engines.ThreefishCipher;
import org.bouncycastle.util.ByteLong;

public class Skein implements ExtendedDigest {

    public static final int Normal = 0;

    public static final int ZeroedState = 1;

    public static final int ChainedState = 2;

    public static final int ChainedConfig = 3;

    private final byte[] schema = { 83, 72, 65, 51 }; // "SHA3"

    private ThreefishCipher _cipher;

    private int _cipherStateBits;

    private int _cipherStateBytes;

    private int _cipherStateWords;

    private int _outputBytes;

    private byte[] _inputBuffer;

    private int _bytesFilled;

    private long[] _cipherInput;

    private long[] _state;

    private int _hashSize;

    SkeinConfig Configuration;

    public UbiTweak UbiParameters;

    public int getStateSize() {
        return _cipherStateBits;
    }

    /**
     * Initializes the Skein hash instance.
     *
     * @param stateSize
     *     The internal state size of the hash in bits. Supported values 
     *     are 256, 512, and 1024
     * @param outputSize
     *     The output size of the hash in bits. Output size must greater 
     *     than zero.
     * @throws IllegalArgumentException
     */

    public Skein(int stateSize, int outputSize) throws IllegalArgumentException {

        setup(stateSize, outputSize);

        // Generate the configuration string
        Configuration = new SkeinConfig(this);
        Configuration.SetSchema(schema); // "SHA3"
        Configuration.SetVersion(1);
        Configuration.GenerateConfiguration();
        initialize();
    }

    /**
     * Initializes the Skein hash instance for use with a key (Skein MAC)
     * 
     * @param stateSize
     *     The internal state size of the hash in bits. Supported values 
     *     are 256, 512, and 1024
     * @param outputSize
     *     The output size of the hash in bits. Output size must greater 
     *     than zero.
     * @param treeInfo
     *     Not yet supported.
     * @param key
     *     The key for a message authenication code (MAC)
     * @throws IllegalArgumentException
     */
    public Skein(int stateSize, int outputSize, long treeInfo, byte[] key)
            throws IllegalArgumentException {

        setup(stateSize, outputSize);

        /* compute the initial chaining state values, based on key */
        if (key.length > 0) { /* is there a key? */
            _outputBytes = _cipherStateBytes;
            UbiParameters.StartNewBlockType(UbiTweak.Key);
            update(key, 0, key.length); /* hash the key */
            byte[] preHash = finalPad();

            /* copy over into state variables */
            for (int i = 0; i < _cipherStateWords; i++)
                _state[i] = ByteLong.GetUInt64(preHash, i * 8);
        }
        /*
         * build/process the config block, type == CONFIG (could be precomputed
         * for each key)
         */
        _outputBytes = (outputSize + 7) / 8;

        Configuration = new SkeinConfig(this);
        Configuration.SetSchema(schema); // "SHA3"
        Configuration.SetVersion(1);

        initialize(ChainedConfig);
    }

    /*
     * Initialize the internal variables
     */
    private void setup(int stateSize, int outputSize)
            throws IllegalArgumentException {
        // Make sure the output bit size > 0
        if (outputSize <= 0)
            throw new IllegalArgumentException(
                    "Skein: Output bit size must be greater than zero.");

        _cipherStateBits = stateSize;
        _cipherStateBytes = stateSize / 8;
        _cipherStateWords = stateSize / 64;

        _hashSize = outputSize;
        _outputBytes = (outputSize + 7) / 8;

        // Figure out which cipher we need based on
        // the state size
        _cipher = ThreefishCipher.CreateCipher(stateSize);
        if (_cipher == null)
            throw new IllegalArgumentException("Skein: Unsupported state size.");

        // Allocate buffers
        _inputBuffer = new byte[_cipherStateBytes];
        _cipherInput = new long[_cipherStateWords];
        _state = new long[_cipherStateWords];

        // Allocate tweak
        UbiParameters = new UbiTweak();
    }

    /*
     * Process (encrypt) one block with Threefish and update internal
     * context variables. 
     */
    void ProcessBlock(int bytes) {
        // Set the key to the current state
        _cipher.SetKey(_state);

        // Update tweak
        UbiParameters.addBitsProcessed(bytes);

        _cipher.SetTweak(UbiParameters.getTweak());

        // Encrypt block
        _cipher.Encrypt(_cipherInput, _state);

        // Feed-forward input with state
        for (int i = 0; i < _cipherInput.length; i++)
            _state[i] ^= _cipherInput[i];
    }

    /**
     * Update the hash with a message bit string.
     * 
     * Skein can handle data not only as bytes but also as bit strings of
     * arbitrary length (up to its maximum design size).
     * 
     * @param array
     *     The byte array that holds the bit string. The array must be big
     *     enough to hold all bits.
     * @param start
     *     Offset into byte array where the data starts, must be a byte number
     *     (not a bit number).
     * @param length
     *     Number of bits to hash.
     */
    public void updateBits(byte[] array, int start, int length) 
        throws IllegalStateException {
        
        if (UbiParameters.isBitPad())         {
            throw new IllegalStateException("Skein: partial byte only on last data block");
        }
        // if number of bits is a multiple of bytes - that's easy
        if ((length & 0x7) == 0) {
            update(array, start, length >>> 3);
            return;
        }
        // Fill in bytes in buffer, add one for partial byte
        update(array, start, (length>>>3)+1);

        // Mask partial byte and set BitPad flag before doFinal()
        byte mask = (byte)(1 << (7 - (length & 7)));        // partial byte bit mask
        _inputBuffer[_bytesFilled-1] = (byte)((_inputBuffer[_bytesFilled-1] & (0-mask)) | mask);
        UbiParameters.setBitPad(true);
    }

    public void update(byte[] array, int start, int length) {
        int bytesDone = 0;

        // Fill input buffer
        while (bytesDone < length) {
            // Do a transform if the input buffer is filled
            if (_bytesFilled == _cipherStateBytes) {
                // Copy input buffer to cipher input buffer
                InputBufferToCipherInput();

                // Process the block
                ProcessBlock(_cipherStateBytes);

                // Clear first flag, which will be set
                // by Initialize() if this is the first transform
                UbiParameters.setFirstBlock(false);

                // Reset buffer fill count
                _bytesFilled = 0;
            }
            _inputBuffer[_bytesFilled++] = array[start++];
            bytesDone++;
        }
    }

    public byte[] doFinal() {
        int i;

        // Pad left over space in input buffer with zeros
        // and copy to cipher input buffer
        for (i = _bytesFilled; i < _inputBuffer.length; i++)
            _inputBuffer[i] = 0;

        InputBufferToCipherInput();

        // Do final message block
        UbiParameters.setFinalBlock(true);
        ProcessBlock(_bytesFilled);

        // Clear cipher input
        for (i = 0; i < _cipherInput.length; i++)
            _cipherInput[i] = 0;

        // Do output block counter mode output
        int j;

        byte[] hash = new byte[_outputBytes];
        long[] oldState = new long[_cipherStateWords];

        // Save old state
        for (j = 0; j < _state.length; j++)
            oldState[j] = _state[j];

        for (i = 0; i < _outputBytes; i += _cipherStateBytes) {
            UbiParameters.StartNewBlockType(UbiTweak.Out);
            UbiParameters.setFinalBlock(true);
            ProcessBlock(8);

            // Output a chunk of the hash
            int outputSize = _outputBytes - i;
            if (outputSize > _cipherStateBytes)
                outputSize = _cipherStateBytes;

            ByteLong.PutBytes(_state, hash, i, outputSize);

            // Restore old state
            for (j = 0; j < _state.length; j++)
                _state[j] = oldState[j];

            // Increment counter
            _cipherInput[0]++;
        }
        reset();
        return hash;
    }

    /*
     * Internal function that performs a final block processing
     * and returns the resulting data. Used during set-up of
     * MAC key hash.
     */
    private byte[] finalPad() {
        int i;

        // Pad left over space in input buffer with zeros
        // and copy to cipher input buffer
        for (i = _bytesFilled; i < _inputBuffer.length; i++)
            _inputBuffer[i] = 0;

        InputBufferToCipherInput();

        // Do final message block
        UbiParameters.setFinalBlock(true);
        ProcessBlock(_bytesFilled);

        byte[] data = new byte[_outputBytes];

        for (i = 0; i < _outputBytes; i += _cipherStateBytes) {
            // Output a chunk of the hash
            int outputSize = _outputBytes - i;
            if (outputSize > _cipherStateBytes)
                outputSize = _cipherStateBytes;

            ByteLong.PutBytes(_state, data, i, outputSize);
        }
        return data;
    }

    /*
     * Internal initialization function that sets up the state variables
     * in several ways. Used during set-up of MAC key hash for example.
     */
    private void initialize(int initializationType) {
        switch (initializationType) {
        case Normal:
            // Normal initialization
            initialize();
            return;

        case ZeroedState:
            // Start with a all zero state
            for (int i = 0; i < _state.length; i++)
                _state[i] = 0;
            break;

        case ChainedState:
            // Keep the state as it is and do nothing
            break;

        case ChainedConfig:
            // Generate a chained configuration
            Configuration.GenerateConfiguration(_state);
            // Continue initialization
            initialize();
            return;
        }

        // Reset bytes filled
        _bytesFilled = 0;
    }

    /*
     * Standard internal initialize function.
     */
    private final void initialize() {
        // Copy the configuration value to the state
        for (int i = 0; i < _state.length; i++)
            _state[i] = Configuration.ConfigValue[i];

        // Set up tweak for message block
        UbiParameters.StartNewBlockType(UbiTweak.Message);

        // Reset bytes filled
        _bytesFilled = 0;
    }

    /**
     * Initialize with state variables provided by application.
     * 
     * Applications may use this method if they provide thier own Skein
     * state before starting the Skein processing. The number of long (words)
     * of the external state must conform the to number of state variables
     * this Skein instance requires (state size bits / 64).
     * 
     * After copying the external state to Skein the functions enables
     * hash processing, thus an application can call {@code update}. The
     * Skein MAC implementation uses this function to restore the state for
     * a given state size, key, and output size combination.
     * 
     * @param externalState
     *     The state to use.
     */
    public final void initialize(long[] externalState) {
        // Copy an external saved state value to internal state
        for (int i = 0; i < _state.length; i++)
            _state[i] = externalState[i];

        // Set up tweak for message block
        UbiParameters.StartNewBlockType(UbiTweak.Message);

        // Reset bytes filled
        _bytesFilled = 0;
    }

    // Moves the byte input buffer to the long cipher input
    void InputBufferToCipherInput() {
        for (int i = 0; i < _cipherStateWords; i++)
            _cipherInput[i] = ByteLong.GetUInt64(_inputBuffer, i * 8);
    }

    /**
     * The state size of this Skein instance.
     * 
     * @return the _cipherStateBits
     */
    public int get_cipherStateBits() {
        return _cipherStateBits;
    }

    /**
     * The output hash size in bits of this Skein instance
     * @return the hashSize int bits
     */
    public int getHashSize() {
        return _hashSize;
    }

    public String getAlgorithmName() {
        return "Skein" + _cipherStateBits;
    }

    public int getDigestSize() {
        return _outputBytes;
    }

    public void update(byte in) {
        byte[] tmp = new byte[1];
        update(tmp, 0, 1);
    }

    public int doFinal(byte[] out, int outOff) {
        byte[] hash = doFinal();
        System.arraycopy(hash, 0, out, outOff, hash.length);
        return hash.length;
    }

    public void reset() {
        initialize();
    }

    public int getByteLength() {
        return _cipherStateBytes;
    }
    
    /**
     * Get the current internal state of this Skein instance.
     * 
     * An application can get the internal state, for example after some
     * key or state-chaining processing, and reuse this state.
     * 
     * @return
     *     The current internal state.
     *
     * @see initialize(long[] externalState)
     */
    public long[] getState() {
        long[] s = new long[_state.length];
        // Copy state values to external state
        for (int i = 0; i < _state.length; i++)
            s[i] = _state[i];
        return s;
    }
    
    class SkeinConfig {
        private final int _stateSize;

        long[] ConfigValue;

        // Set the state size for the configuration
        long [] ConfigString;

        SkeinConfig(Skein sourceHash)
        {
            _stateSize = sourceHash.get_cipherStateBits();

            // Allocate config value
            ConfigValue = new long[_stateSize / 8];

            // Set the state size for the configuration
            ConfigString = new long[ConfigValue.length];
            ConfigString[1] = sourceHash.getHashSize();
        }

        void GenerateConfiguration()
        {
            ThreefishCipher cipher = ThreefishCipher.CreateCipher(_stateSize);
            UbiTweak tweak = new UbiTweak();

            // Initialize the tweak value
            tweak.StartNewBlockType(UbiTweak.Config);
            tweak.setFinalBlock(true);
            tweak.setBitsProcessed(32);

            cipher.SetTweak(tweak.getTweak());
            cipher.Encrypt(ConfigString, ConfigValue);

            ConfigValue[0] ^= ConfigString[0]; 
            ConfigValue[1] ^= ConfigString[1];
            ConfigValue[2] ^= ConfigString[2];
        }

        void GenerateConfiguration(long[] initialState)
        {
            ThreefishCipher cipher = ThreefishCipher.CreateCipher(_stateSize);
            UbiTweak tweak = new UbiTweak();

            // Initialize the tweak value
            tweak.StartNewBlockType(UbiTweak.Config);
            tweak.setFinalBlock(true);
            tweak.setBitsProcessed(32);

            cipher.SetKey(initialState);
            cipher.SetTweak(tweak.getTweak());
            cipher.Encrypt(ConfigString, ConfigValue);

            ConfigValue[0] ^= ConfigString[0];
            ConfigValue[1] ^= ConfigString[1];
            ConfigValue[2] ^= ConfigString[2];
        }

        void SetSchema(byte[] schema) throws IllegalArgumentException
        {
            if (schema.length != 4) 
                throw new IllegalArgumentException("Skein configuration: Schema must be 4 bytes.");

            long n = ConfigString[0];

            // Clear the schema bytes
            n &= ~0xffffffffL;
            // Set schema bytes
            n |= (long) schema[3] << 24;
            n |= (long) schema[2] << 16;
            n |= (long) schema[1] << 8;
            n |= schema[0];

            ConfigString[0] = n;
        }

        void SetVersion(int version) throws IllegalArgumentException
        {
            if (version < 0 || version > 3)
                throw new IllegalArgumentException("Skein configuration: Version must be between 0 and 3, inclusive.");

            ConfigString[0] &= ~((long)0x03 << 32);
            ConfigString[0] |= (long)version << 32;
        }

        void SetTreeLeafSize(byte size)
        {
            ConfigString[2] &= ~(long)0xff;
            ConfigString[2] |= size;
        }

        void SetTreeFanOutSize(byte size)
        {
            ConfigString[2] &= ~((long)0xff << 8);
            ConfigString[2] |= (long)size << 8;
        }

        void SetMaxTreeHeight(byte height) throws IllegalArgumentException
        {
            if (height == 1)
                throw new IllegalArgumentException("Skein configuration: Tree height must be zero or greater than 1.");

            ConfigString[2] &= ~((long)0xff << 16);
            ConfigString[2] |= (long)height << 16;
        }
    }

    class UbiTweak {

        static final long Key = 0, Config = 4, Personalization = 8,
                PublicKey = 12, KeyIdentifier = 16, Nonce = 20, Message = 48,
                Out = 63;

        private static final long T1FlagFinal = ((long) 1 << 63);

        private static final long T1FlagFirst = ((long) 1 << 62);

        private static final long T1FlagBitPad = ((long) 1 << 55);

        private long[] Tweak = new long[2];

        UbiTweak() {
        }

        /**
         * Get status of the first block flag.
         */
        boolean IsFirstBlock() {
            return (Tweak[1] & T1FlagFirst) != 0;
        }

        /**
         * Sets status of the first block flag.
         */
        void setFirstBlock(boolean value) {
            if (value)
                Tweak[1] |= T1FlagFirst;
            else
                Tweak[1] &= ~T1FlagFirst;
        }

        /**
         * Gets status of the final block flag.
         */
        boolean isFinalBlock() {
            return (Tweak[1] & T1FlagFinal) != 0;
        }

        /**
         * Sets status of the final block flag.
         */
        void setFinalBlock(boolean value) {
            if (value)
                Tweak[1] |= T1FlagFinal;
            else
                Tweak[1] &= ~T1FlagFinal;
        }

        /**
         * Gets status of the final block flag.
         */
        boolean isBitPad() {
            return (Tweak[1] & T1FlagBitPad) != 0;
        }

        /**
         * Sets status of the final block flag.
         */
        void setBitPad(boolean value) {
            if (value)
                Tweak[1] |= T1FlagBitPad;
            else
                Tweak[1] &= ~T1FlagBitPad;
        }
        // / <summary>
        // / Gets or sets the current tree level.
        // / </summary>
        byte getTreeLevel() {
            return (byte) ((Tweak[1] >> 48) & 0x7f);
        }

        void setTreeLevel(int value) throws Exception {
            if (value > 63)
                throw new Exception(
                        "Tree level must be between 0 and 63, inclusive.");

            Tweak[1] &= ~((long) 0x7f << 48);
            Tweak[1] |= (long) value << 48;
        }

        // / <summary>
        // / Gets or sets the number of bits processed so far, inclusive.
        // / </summary>
        long[] getBitsProcessed() {
            long[] retval = new long[2];
            retval[0] = Tweak[0];
            retval[1] = Tweak[1] & 0xffffffffL;
            return retval;
        }

        void setBitsProcessed(long value) {
            Tweak[0] = value;
        }

        void addBitsProcessed(int value) {
            final int len = 3;
            long carry = value;
            
            long words[] = new long[len];
            words[0] = Tweak[0] & 0xffffffffL;
            words[1] = ((Tweak[0] >>> 32) & 0xffffffffL);
            words[2] = (Tweak[1] & 0xffffffffL);

            for (int i = 0; i < len; i++) {
                carry += words[i];
                words[i] = carry;
                carry >>= 32;
            }        
            Tweak[0] = words[0] & 0xffffffffL;
            Tweak[0] |= (words[1] & 0xffffffffL) << 32;
            Tweak[1] |= words[2] & 0xffffffffL;
        }

        // / <summary>
        // / Gets or sets the current UBI block type.
        // / </summary>
        long getBlockType() {
            return ((Tweak[1] >> 56) & 0x3f);
        }

        void setBlockType(long value) {
            Tweak[1] = value << 56;
        }

        // / <summary>
        // / Starts a new UBI block type by setting BitsProcessed to zero, setting
        // the first flag, and setting the block type.
        // / </summary>
        // / <param name="type">The UBI block type of the new block.</param>
        void StartNewBlockType(long type) {
            setBitsProcessed(0);
            setBlockType(type);
            setFirstBlock(true);
        }

        /**
         * @return the tweak
         */
        long[] getTweak() {
            return Tweak;
        }

        /**
         * @param tweak
         *            the tweak to set
         */
        void setTweak(long[] tweak) {
            Tweak = tweak;
        }

    }

}
