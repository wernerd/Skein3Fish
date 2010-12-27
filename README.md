# Skein and Threefish Software Suite

This software suite brings you Skein and Threefish functions for Java and C.
Some notable features of this software suite are:

* All three state sizes of Skein and Threefish: 256, 512, and 1024 bits
* Support of Skein MAC
* Variable length of hash and MAC - even in numbers of bits
* Support of the full message length as defined in the Skein paper (2^96-1 bytes, not just a meager 4 GiB :-) )
* Tested agains the official test vectors that the NIST CD contains (except Tree hashes)
* The Java interface uses the well known Bouncycastle lightweight mechanisms, thus easy to
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

Because I'm familiar with the BouncyCastle crypto library I decided to design the Java interface
along the lines of BouncyCastle's lightweight crypto API. 

### The Threefish cipher implementation

Alberto did a wonderfull job here. In his implementation he unrolled all three Threefish
algorithms (256, 512, 1024). With the help of the standard C preprocessor the Java implementatiom
also has unrolled Threefish algorithms that are even faster than the C# implementation
because Java has all the code really unrolled, not just unrolled with functions calls and `ref` parameters.
This unrolled code gives the Java JIT compiler good input for optimization.  
 
 
## The C implementation

Stay tuned for this part - will show up in a short time.
