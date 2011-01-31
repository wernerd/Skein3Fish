package threefish

import (
	"os"
	"strconv"
	"encoding/binary"
)

const KEY_SCHEDULE_CONST = uint64(0x1BD11BDAA9FC1A22)
const EXPANDED_TWEAK_SIZE = 3;


// Internal interface to simplify Threefish usage
type cipherInternal interface {
    /**
     * Encrypt function
     * 
     * Derived classes must implement this function.
     * 
     * @param input
     *     The plaintext input.
     * @param output
     *     The ciphertext output.
     */
    encrypt(input, output [] uint64)

    /**
     * Decrypt function
     * 
     * Derived classes must implement this function.
     * 
     * @param input
     *     The ciphertext input.
     * @param output
     *     The plaintext output.
     */
    decrypt(input, output []uint64)
    
    getTempData() ([]uint64, []uint64)
    setTweak(tweak []uint64)
    setKey(key []uint64)
}


// A Cipher is an instance of Threefish using a particular key and state size.
type Cipher struct {
	stateSize int
	internal cipherInternal
}

type KeySizeError int

func (k KeySizeError) String() string {
	return "crypto/threefish: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a Cipher.
// The key argument should be the Threefish key, 32, 64 or 128 bytes.
func NewCipher(key []byte, tweak []uint64) (*Cipher, os.Error) {
    c := new(Cipher)

    var err os.Error

    switch len(key) {
    case 32:
        c.internal, err = newThreefish256(key, tweak)
    case 64:
        c.internal, err = newThreefish512(key, tweak)
    case 128:
        c.internal, err = newThreefish1024(key, tweak)
    default:
        return nil, KeySizeError(len(key))
    }		
    c.stateSize = len(key) * 8
    return c, err
}

// NewCipher creates and returns a Cipher.
// The key argument should be the Threefish key, 4, 8 or 16 uint64
func NewCipher64(key, tweak []uint64) (*Cipher, os.Error) {
    c := new(Cipher)

    var err os.Error
    switch len(key) {
    case 4:
        c.internal, err = newThreefish256_64(key, tweak)
    case 8:
        c.internal, err = newThreefish512_64(key, tweak)
    case 16:
        c.internal, err = newThreefish1024_64(key, tweak)
    default:
        return nil, KeySizeError(len(key))
    }       
    c.stateSize = len(key) * 8
    return c, err
}

// NewCipher creates and returns a Cipher.
// The key argument should be the request Threefish state size
func NewCipherSize(size int) (*Cipher, os.Error) {
    c := new(Cipher)
        
    var err os.Error
        
    switch size {
    case 256:
        c.internal, err = newThreefish256(nil, nil)
    case 512:
        c.internal, err = newThreefish512(nil, nil)
    case 1024:
        c.internal, err = newThreefish1024(nil, nil)
    default:
        return nil, KeySizeError(size)
    }       
    c.stateSize = size
    return c, err
}

// BlockSize returns the cipher's block size in bytes.
func (c *Cipher) BlockSize() int {
    return c.stateSize / 8
}


// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory.
func (c *Cipher) Encrypt(dst, src []byte) {

    uintLen := c.stateSize / 64

    // This saves makes
    tmpin, tmpout := c.internal.getTempData()
    
    for i := 0; i < uintLen; i++ {
        tmpin[i] = binary.LittleEndian.Uint64(src[i*8:i*8+8])
    }
    c.internal.encrypt(tmpin, tmpout)

    for i := 0; i < uintLen; i++ {
        binary.LittleEndian.PutUint64(dst[i*8:i*8+8], tmpout[i])
    }
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory.
func (c *Cipher) Decrypt(dst, src []byte) {

    uintLen := c.stateSize / 64
    
    // This saves a make
    tmpin, tmpout := c.internal.getTempData()
    
    for i := 0; i < uintLen; i++ {
        tmpin[i] = binary.LittleEndian.Uint64(src[i*8:i*8+8])
    }
    c.internal.decrypt(tmpin, tmpout)

    for i := 0; i < uintLen; i++ {
        binary.LittleEndian.PutUint64(dst[i*8:i*8+8], tmpout[i])
    }
}

// Encrypt encrypts the first block in src into dst, blocks
// are unit64 arrays
// Dst and src may point at the same memory.
func (c *Cipher) Encrypt64(dst, src []uint64) {
    c.internal.encrypt(src, dst)
}

// Decrypt encrypts the first block in src into dst, blocks
// are unit64 arrays
// Dst and src may point at the same memory.
func (c *Cipher) Decrypt64(dst, src []uint64) {
    c.internal.decrypt(src, dst)
}

func (c *Cipher) SetTweak(tweak []uint64) {
    c.internal.setTweak(tweak)
}

func (c *Cipher) SetKey(key []uint64) {
    c.internal.setKey(key)
}

// Some helper functions available for all Threefish* implementations
/**
 * Initialize the tweak data
 */
func setTweak(tweak, expTweak []uint64) {
    if tweak != nil {
        expTweak[0] = tweak[0];
        expTweak[1] = tweak[1];
        expTweak[2] = tweak[0] ^ tweak[1];
    }
}

/**
 * Expand the key data
 */
func setKey(key, expKey []uint64) {
    var i int
    parity := uint64(KEY_SCHEDULE_CONST)

    for i = 0; i < len(expKey) - 1; i++ {
        expKey[i] = key[i];
        parity ^= key[i];
    }
    expKey[i] = parity;
}
