package skein

import (
    "crypto/threefish"
    "encoding/binary"
    )

var schema = [4]byte{ 83, 72, 65, 51 } // "SHA3"

type Skein struct {
    config *skeinConfiguration
    cipherStateBits, cipherStateBytes, cipherStateWords, outputBytes, hashSize, bytesFilled int
    cipher *threefish.Cipher
    ubiParameters *ubiTweak
    inputBuffer []byte
    cipherInput []uint64
    state []uint64
    
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
func NewSkein (stateSize, outputSize int) *Skein {
    s := new(Skein)
    s.setup(stateSize, outputSize)
    s.config = newSkeinConfiguration(s)
    s.config.setSchema(schema[:]); // "SHA3"
    s.config.setVersion(1);
    s.config.generateConfiguration();
    s.initialize()
    return s
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
 */

func NewSkeinForMac (stateSize, outputSize, treeInfo int, key []byte) *Skein {
    s := new(Skein)
    s.setup(stateSize, outputSize)

    // setup MAC stuff
    s.outputBytes = (outputSize + 7) / 8;  // re-compute here
    s.config = newSkeinConfiguration(s)
    s.config.setSchema(schema[:]); // "SHA3"
    s.config.setVersion(1);
    s.config.generateConfiguration();
    s.initialize() // chained
    return s
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
    s.cipher, _ = threefish.NewCipherSize(stateSize)

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
func (s *Skein) UpdateBits(array []byte, start, length int) {
        
    if s.ubiParameters.isBitPad() {
        return
    }
    // if number of bits is a multiple of bytes - that's easy
    if (length & 0x7) == 0 {
        s.Update(array, start, length >> 3)
        return
    }
    // Fill in bytes in buffer, add one for partial byte
    s.Update(array, start, (length>>3)+1)

    // Mask partial byte and set BitPad flag before doFinal()
    mask := byte(1 << (7 - uint(length & 7)))        // partial byte bit mask
    s.inputBuffer[s.bytesFilled-1] = byte((s.inputBuffer[s.bytesFilled-1] & (0-mask)) | mask)
    s.ubiParameters.setBitPad(true)
}

func (s *Skein) Update(array []byte, start, length int) {
        var bytesDone int = 0

        // Fill input buffer
        for bytesDone < length {
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
            s.inputBuffer[s.bytesFilled] = array[start]
            bytesDone++; s.bytesFilled++; start++
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
//        for j := 0; j < s.cipherStateWords; j++ {
//            binary.LittleEndian.PutUint64(hash[i+j*8:i+j*8+8], s.state[j])
//        }
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








