/*
This package implements the Skein hash and Skein MAC algorithms as defined
if the Skein V1.3 specification. Skein is one of the five SHA-3 candidate 
algorithms that advance to the third (and final) round of the SHA-3
selection.

The implementation in this package supports:
* All three state sizes of Skein and Threefish: 256, 512, and 1024 bits
* Skein MAC
* Variable length of hash and MAC input and output - even in numbers of bits
* Full message length as defined in the Skein paper (2^96 -1 bytes, not just a meager 4 GiB :-) )
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

const (
    maxSkeinStateWords = Skein1024 / 64
    )
    
var nullStateWords [maxSkeinStateWords]uint64

type Skein struct {
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

// Initializes the Skein hash instance.
//
// stateSize
//     The Skein state size of the hash in bits. Supported values 
//     are 256, 512, and 1024
// outputSize
//     The output size of the hash in bits. Output size must greater 
//     than zero.
//
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
    s.config.setSchema(schema[:]) // "SHA3"
    s.config.setVersion(1)
    s.config.generateConfiguration()
    s.initialize()
    return s, nil
}

// Initializes the Skein hash instance for use with a key and tree.
// 
// stateSize
//     The internal state size of the hash in bits. Supported values 
//     are 256, 512, and 1024
// outputSize
//     The output size of the hash in bits. Output size must greater 
//     than zero.
// treeInfo
//     Not yet supported.
// key
//     The key for a message authenication code (MAC)
//
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
        s.outputBytes = s.cipherStateWords * 8
        s.ubiParameters.startNewBlockType(uint64(Key))
        s.Update(key)               // hash the key
        s.finalPad()                // computes new Skein state
    }
    s.outputBytes = (outputSize + 7) / 8  // re-compute here
    s.config = newSkeinConfiguration(s)
    s.config.setSchema(schema[:]) // "SHA3"
    s.config.setVersion(1)

    s.initializeConf(chainedConfig)
    return s, nil
}

// Initialize the internal variables
//
func (s *Skein) setup(stateSize, outputSize int) {
    s.cipherStateWords = stateSize / 64

    s.hashSize = outputSize
    s.outputBytes = (outputSize + 7) / 8

    // Figure out which cipher we need based on
    // the state size
    s.cipher, _ = threefish.NewSize(stateSize)

    // Allocate buffers
    s.inputBuffer = make([]byte, s.cipherStateWords * 8)
    s.cipherInput = make([]uint64, s.cipherStateWords)
    s.state = make([]uint64, s.cipherStateWords)

    // Allocate tweak
    s.ubiParameters = newUbiTweak()
}

// Initialize with state variables provided by application.
// 
// Applications may use this method if they provide their own Skein
// state before starting the Skein processing. The number of long (words)
// of the external state must conform the to number of state variables
// this Skein instance requires (state size bits / 64).
// 
// After copying the external state to Skein the functions enables
// hash processing, thus an application can call {@code update}. The
// Skein MAC implementation uses this function to restore the state for
// a given state size, key, and output size combination.
// 
// externalState
//     The state to use.
//
func (s *Skein) initializeWithState(externalState []uint64) {
    // Copy an external saved state value to internal state
    copy(s.state, externalState)
    // Set up tweak for message block
    s.ubiParameters.startNewBlockType(uint64(Message))
    // Reset bytes filled
    s.bytesFilled = 0
}

// Standard internal initialize function.
//
func (s *Skein) initialize() {
    // Copy the configuration value to the state
    for i := 0; i < len(s.state); i++ {
        s.state[i] = s.config.configValue[i]
    }
    // Set up tweak for message block
    s.ubiParameters.startNewBlockType(uint64(Message))
    s.bytesFilled = 0
}

// Internal initialization function that sets up the state variables
// in several ways. Used during set-up of MAC key hash for example.
//
func (s *Skein) initializeConf(initializationType int) {
    switch initializationType {
    case normal:
        s.initialize()                      // Normal initialization
    case zeroedState:
        copy(s.state, nullStateWords[:])    // Start with a all zero state
    case chainedState:
        // Keep the state as it is and do nothing
    case chainedConfig:
        // Generate a chained configuration
        s.config.generateConfigurationState(s.state)
        s.initialize()
    }
    s.bytesFilled = 0
}

// Process (encrypt) one block with Threefish and update internal
// context variables. 
//
func (s *Skein) processBlock(bytes int) {
    s.cipher.SetKey(s.state)                        // state is the key
    s.ubiParameters.addBytesProcessed(bytes)        // Update tweak
    s.cipher.SetTweak(s.ubiParameters.getTweak())

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

// Update the hash with a message bit string.
// 
// Skein can handle data not only as bytes but also as bit strings of
// arbitrary length (up to its maximum design size).
// 
// array
//     The byte array that holds the bit string. The array must be big
//     enough to hold all bits.
// numBits
//     Number of bits to hash.
//
func (s *Skein) UpdateBits(input []byte, numBits int) os.Error {
        
    if s.ubiParameters.isBitPad() {
        return statusError(0)
    }
    if (numBits+7)/8 != len(input) {
        return lengthError(numBits)
    }
    s.Update(input)

    // if number of bits is a multiple of bytes - that's easy
    if (numBits & 0x7) == 0 {
        return nil
    }
    // Mask partial byte and set BitPad flag before doFinal()
    mask := byte(1 << (7 - uint(numBits & 7)))      // partial byte bit mask
    s.inputBuffer[s.bytesFilled-1] = byte((s.inputBuffer[s.bytesFilled-1] & (0-mask)) | mask)
    s.ubiParameters.setBitPad(true)
    return nil
}

// Update Skein digest with the next part of the message.
//
// input
//      Byte slice that contains data to hash.
//
func (s *Skein) Update(input []byte) {

    // Fill input buffer
    for i := 0; i < len(input); i++ {
        // Do a transform if the input buffer is filled
        if s.bytesFilled == s.cipherStateWords * 8 {
            // Copy input buffer to cipher input buffer
            for i := 0; i < s.cipherStateWords; i++ {
                s.cipherInput[i] = binary.LittleEndian.Uint64(s.inputBuffer[i*8:i*8+8])
            }
            // Process the block
            s.processBlock(s.bytesFilled)

            // Clear first flag, which will be set
            // by Initialize() if this is the first transform
            s.ubiParameters.setFirstBlock(false)

            // Reset buffer fill count
            s.bytesFilled = 0
        }
        s.inputBuffer[s.bytesFilled] = input[i]
        s.bytesFilled++
    }
}

// Finalize Skein digest and return the hash.
// 
// This method resets the Skein digest after it computed the digest. An
// application may reuse this Skein context to compute another digest.
//
func (s *Skein) DoFinal() (hash []byte) {

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
    copy(s.cipherInput, nullStateWords[:])

    hash = make([]byte, s.outputBytes)
    oldState := make([]uint64, s.cipherStateWords)
    copy(oldState, s.state)

    stateBytes := s.cipherStateWords * 8
    for i := 0; i < s.outputBytes; i += s.cipherStateWords * 8 {
        s.ubiParameters.startNewBlockType(uint64(Out))
        s.ubiParameters.setFinalBlock(true)
        s.processBlock(8)

        // Output a chunk of the hash
        outputSize := s.outputBytes - i
        if outputSize > stateBytes {
            outputSize = stateBytes
        }
        s.putBytes(s.state, hash[i : i+outputSize])
        // Restore old state
        copy(s.state, oldState)
        // Increment counter
        s.cipherInput[0]++
     }
     s.Reset()
     return
}

// Return the Skein output hash size as number of bits
func (s *Skein) getHashSize() int {
    return s.hashSize
}

// Return the number of Skein state words
func (s *Skein) getNumberCipherStateWords() int {
    return s.cipherStateWords
}

func (s *Skein) Reset() {
    s.initialize()
}

// Internal function that performs a final block processing
// and returns the resulting data. Used during set-up of
// MAC key hash.
//
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
    s.ubiParameters.setFinalBlock(true)
    s.processBlock(s.bytesFilled)
}

// Disassmble an array of words into a byte array.
// 
// input
//     The input array.
// output
//     The byte output array.
// byteCount
//     The number of bytes to disassemble, arbitrary length.
//
func (s *Skein) putBytes(input []uint64, output []byte) {
    var j uint
    for i := 0; i < len(output); i++ {
        output[i] = byte(input[i/8] >> j)
        j = (j + 8) & 63
    }
}








