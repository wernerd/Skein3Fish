# Skein and Threefish Software Suite

This software suite brings you Skein and Threefish functions for Java, C, and go.
Some notable features of this software suite are:

* All three state sizes of Skein and Threefish: 256, 512, and 1024 bits
* Support of Skein MAC
* Variable length of hash and MAC - even in numbers of bits
* Support of the full message length as defined in the Skein paper (2^96 -1 bytes, not just a meager 4 GiB :-) )
* Tested with the official test vectors that are part of the NIST CD (except Tree hashes)
* The Java interface uses the well known Bouncy Castle lightweight mechanisms, thus easy to
  use for Java programmers.
* The C API follows in general the lower level openSSL model  

I used some open source and public domain sources to implement and compile this suite. Most
notably are the Skein C reference and Skein C optimized implementations of the Skein team and
a very well written C# implementation from Alberto Fajardo. 

## The Java implementation

The Skein and Threefish functions for Java a fairly complete and tested and could be used
in productive environments. The `ant` build file produces a small `jar` file that contains the
Skein, Threefish, and some other useful and often needed algorithms. 

The Java implementation is a derivation (in parts a large derivation) of Alberto Fajardo's
C# implementation for .Net. Some Java specific programming tricks to deal with unsigned data
types were necessary (Java does not support unsigned data types). Also Java misses `ref`
parameters in function calls.

Because I'm familiar with the Bouncy Castle crypto library I decided to design the Java interface
along the lines of BouncyCastle's lightweight crypto API. 
 
 
## The C implementation

The C implementation provides a similar functionality as the Java implementation.

Currently the Skein implementation uses the Threefish reference implementation not
the full unrolled version. It is planned to switch to the full unrolled version to
simplify maintenace and to have a better software module structure.

### A Skein API and its functions.

This API and the functions that implement this API simplify the usage
of Skein. The design and the way to use the functions follow the openSSL
design but at the same time take care of some Skein specific behaviour
and possibilities.
 
The functions enable applications to create a normal Skein hashes and
message authentication codes (MAC).

### Threefish cipher API and its functions.

This API and the functions that implement this API simplify the usage
of the Threefish cipher. The design and the way to use the functions 
follow the openSSL design but at the same time take care of some Threefish
specific behaviour and possibilities.

These are the low level functions that deal with Threefisch blocks only.
Implementations for cipher modes such as ECB, CFB, or CBC may use these 
functions.

## The _go_ implementation

This implementation also provides the full feature set, thus you may use
it to produce Skein hashes or Skein MAC. The API is similar to Java
and uses the same function names as much as possible.


## The Threefish cipher implementation

Alberto did a wonderfull job here. In his implementation he unrolled all three Threefish
algorithms (256, 512, 1024).The Java implementatiom also has unrolled Threefish algorithms
that are even faster than Alberto's C# implementation. This happens because Java has all 
the code really unrolled. The C# implementation uses a lot of function calls with `ref` 
parameters. This unrolled code gives the Java JIT compiler good input for optimization.

The standalone Threefish cipher for C has the same code basis as the Java implementation.
Therefore also full unrolled code without loop constructs.


## Credits

Credits go to

  * the Skein team for their design of Skein and Threefish and their reference and
    optimized C implementations
  * Alberto Fajardo for his well structured C# implementation and his work to unroll the
    Threefish algorithms.