/*
This package implements the Skein hash and Skein MAC algorithms as defined
if the Skein V1.3 specification. Skein is one of the five SHA-3 candidate 
algorithms that advance to the third (and final) round of the SHA-3
selection.
The implementation in this package supports:
* All three state sizes of Skein and Threefish: 256, 512, and 1024 bits
* Skein MAC
* Variable length of hash and MAC - even in numbers of bits
* Support of the full message length as defined in the Skein paper (2^96 -1 bytes, not just a meager 4 GiB :-) )
* Tested with the official test vectors that are part of the NIST CD (except Tree hashes)

The implementation does not support tree hashing.
*/
package skein

import (
    "os"
    "strconv"
    "crypto/threefish"
    "encoding/binary"
    )

var schema = [4]byte{ 83, 72, 65, 51 } // "SHA3"

const (normal = iota
    zeroedState
    chainedState
    chainedConfig
    )

const (
    Skein256 = 256
    Skein512 = 512
    Skein1024 = 1024
    )
    
type Skein struct {
    cipherStateBits,
    cipherStateBytes,
    cipherStateWords,
    outputBytes,
    hashSize, 
    bytesFilled int
    config *skeinConfiguration
    cipher *threefish.Cipher
    ubiParameters *ubiTweak
    inputBuffer []byte
    cipherInput []uint64
    state []uint64
}

type stateSizeError int
func (s stateSizeError) String() string {
    return "crypto/skein: invalid Skein state size " + strconv.Itoa(int(s))
}

type outputSizeError int
func (s outputSizeError) String() string {
    return "crypto/skein: invalid Skein output size " + strconv.Itoa(int(s))
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
 */
func New (stateSize, outputSize int) (*Skein, os.Error) {
    if stateSize != 256 && stateSize != 512 && stateSize != 1024 {
        return nil, stateSizeError(stateSize)
    }
    if outputSize <= 0 {
        return nil, outputSizeError(outputSize)
    }
    s := new(Skein)
    s.setup(stateSize, outputSize)
    s.config = newSkeinConfiguration(s)
    s.config.setSchema(schema[:]); // "SHA3"
    s.config.setVersion(1);
    s.config.generateConfiguration();
    s.initialize()
    return s, nil
}

/**
 * Initializes the Skein hash instance for use with a key and tree.
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
 */
func NewExtended (stateSize, outputSize, treeInfo int, key []byte) (*Skein, os.Error) {
    if stateSize != 256 && stateSize != 512 && stateSize != 1024 {
        return nil, stateSizeError(stateSize)
    }
    if outputSize <= 0 {
        return nil, outputSizeError(outputSize)
    }
    s := new(Skein)
    s.setup(stateSize, outputSize)
    // compute the initial chaining state values, based on key
    if len(key) > 0 {               // do we have a key?
        s.outputBytes = s.cipherStateBytes;
        s.ubiParameters.startNewBlockType(uint64(Key));
        s.Update(key); // hash the key
        s.finalPad()                // computes new Skein state
    }
    s.outputBytes = (outputSize + 7) / 8;  // re-compute here
    s.config = newSkeinConfiguration(s)
    s.config.setSchema(schema[:]); // "SHA3"
    s.config.setVersion(1);

    s.initializeConf(chainedConfig)
    return s, nil
}

/*
 * Initialize the internal variables
 */
func (s *Skein) setup(stateSize, outputSize int) {
    s.cipherStateBits = stateSize
    s.cipherStateBytes = stateSize / 8
    s.cipherStateWords = stateSize / 64

    s.hashSize = outputSize
    s.outputBytes = (outputSize + 7) / 8

    // Figure out which cipher we need based on
    // the state size
    s.cipher, _ = threefish.NewSize(stateSize)

    // Allocate buffers
    s.inputBuffer = make([]byte, s.cipherStateBytes)
    s.cipherInput = make([]uint64, s.cipherStateWords)
    s.state = make([]uint64, s.cipherStateWords)

    // Allocate tweak
    s.ubiParameters = newUbiTweak()
}

/*
 * Standard internal initialize function.
 */
func (s *Skein) initialize() {
    // Copy the configuration value to the state
    for i := 0; i < len(s.state); i++ {
        s.state[i] = s.config.configValue[i]
    }
    // Set up tweak for message block
    s.ubiParameters.startNewBlockType(uint64(Message))

    // Reset bytes filled
    s.bytesFilled = 0;
}

/*
 * Internal initialization function that sets up the state variables
 * in several ways. Used during set-up of MAC key hash for example.
 */
func (s *Skein) initializeConf(initializationType int) {
    switch initializationType {
    case normal:
        // Normal initialization
        s.initialize()
    case zeroedState:
        // Start with a all zero state
        for i := 0; i < len(s.state); i++ {
            s.state[i] = 0
        }
    case chainedState:
        // Keep the state as it is and do nothing
    case chainedConfig:
        // Generate a chained configuration
        s.config.generateConfigurationState(s.state);
        s.initialize();
    }
    // Reset bytes filled
    s.bytesFilled = 0;
}

/*
 * Process (encrypt) one block with Threefish and update internal
 * context variables. 
 */
func (s *Skein) processBlock(bytes int) {
    // Set the key to the current state
    s.cipher.SetKey(s.state);
    // Update tweak
    s.ubiParameters.addBytesProcessed(bytes)

    s.cipher.SetTweak(s.ubiParameters.getTweak())

    // Encrypt block
    s.cipher.Encrypt64(s.state, s.cipherInput)

    // Feed-forward input with state
    for i := 0; i < len(s.cipherInput); i++ {
        s.state[i] ^= s.cipherInput[i]
    }
}

type statusError int
func (s statusError) String() string {
    return "crypto/skein: partial byte only on last data block"
}

type lengthError int
func (s lengthError) String() string {
    return "crypto/skein: length of input buffer does not match bit length: " + strconv.Itoa(int(s))
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
func (s *Skein) UpdateBits(input []byte, length int) os.Error {
        
    if s.ubiParameters.isBitPad() {
        return statusError(0)
        
    }
    if (length+7)/8 != len(input) {
        return lengthError(length)
    }
    s.Update(input)

    // if number of bits is a multiple of bytes - that's easy
    if (length & 0x7) == 0 {
        return nil
    }
    // Mask partial byte and set BitPad flag before doFinal()
    mask := byte(1 << (7 - uint(length & 7)))        // partial byte bit mask
    s.inputBuffer[s.bytesFilled-1] = byte((s.inputBuffer[s.bytesFilled-1] & (0-mask)) | mask)
    s.ubiParameters.setBitPad(true)
    return nil
}

func (s *Skein) Update(input []byte) {

    // Fill input buffer
    for i := 0; i < len(input); i++ {
        // Do a transform if the input buffer is filled
        if s.bytesFilled == s.cipherStateBytes {
            // Copy input buffer to cipher input buffer
            for i := 0; i < s.cipherStateWords; i++ {
                s.cipherInput[i] = binary.LittleEndian.Uint64(s.inputBuffer[i*8:i*8+8])
            }
            // Process the block
            s.processBlock(s.cipherStateBytes)

            // Clear first flag, which will be set
            // by Initialize() if this is the first transform
            s.ubiParameters.setFirstBlock(false)

            // Reset buffer fill count
            s.bytesFilled = 0
        }
        s.inputBuffer[s.bytesFilled] = input[i]
        s.bytesFilled++;
    }
}

func (s *Skein) DoFinal() []byte{

    // Pad left over space in input buffer with zeros
    // and copy to cipher input buffer
    for i := s.bytesFilled; i < len(s.inputBuffer); i++ {
        s.inputBuffer[i] = 0
    }
    for i := 0; i < s.cipherStateWords; i++ {
        s.cipherInput[i] = binary.LittleEndian.Uint64(s.inputBuffer[i*8:i*8+8])
    }
    // Do final message block
    s.ubiParameters.setFinalBlock(true)
    s.processBlock(s.bytesFilled)

    // Clear cipher input
    for i := 0; i < len(s.cipherInput); i++ {
        s.cipherInput[i] = 0
    }
    hash := make([]byte, s.outputBytes)
    oldState := make([]uint64, s.cipherStateWords)

    copy(oldState, s.state)

    for i := 0; i < s.outputBytes; i += s.cipherStateBytes {
        s.ubiParameters.startNewBlockType(uint64(Out))
        s.ubiParameters.setFinalBlock(true);
        s.processBlock(8);

        // Output a chunk of the hash
        outputSize := s.outputBytes - i
        if outputSize > s.cipherStateBytes {
            outputSize = s.cipherStateBytes
        }
        s.putBytes(s.state, hash, i, outputSize)
        // Restore old state
        copy(s.state, oldState)
        // Increment counter
        s.cipherInput[0]++;
     }
     s.Reset();
     return hash;
}

func (s *Skein) getHashSize() int {
    return s.hashSize
}

func (s *Skein) getcipherStateBits() int {
    return s.cipherStateBits
}

func (s *Skein) Reset() {
    s.initialize();
}

/*
 * Internal function that performs a final block processing
 * and returns the resulting data. Used during set-up of
 * MAC key hash.
 */
func (s *Skein) finalPad(){

    // Pad left over space in input buffer with zeros
    // and copy to cipher input buffer
    for i := s.bytesFilled; i < len(s.inputBuffer); i++ {
        s.inputBuffer[i] = 0
    }
    for i := 0; i < s.cipherStateWords; i++ {
        s.cipherInput[i] = binary.LittleEndian.Uint64(s.inputBuffer[i*8:i*8+8])
    }
    // Do final message block
    s.ubiParameters.setFinalBlock(true);
    s.processBlock(s.bytesFilled);
}

/**
 * Disassmble an array of Long into a byte array.
 * 
 * @param input
 *     The long input array.
 * @param output
 *     The byte output array.
 * @param offset
 *     The offset into the output array.
 * @param byteCount
 *     The number of bytes to disassemble.
 */
func (s *Skein) putBytes(input []uint64, output []byte, offset, byteCount int) {
    var j uint = 0
    for i := 0; i < byteCount; i++ {
        output[offset] = byte((input[i >> 3] >> j) & 255)
        offset++
        j = (j + 8) & 63;
    }
}








