# libiusha
## Description
A simple-to-use C library implementing the first- and second-generation Secure Hashing Algorithms (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256). `libiusha` has no dependencies beyond the C standard library and no memory is allocated on the heap internally. All hash digests are computed via a single call to one of the seven hashing functions, for which the caller provides a byte array containing the input message and an adequate buffer to populate the resulting hash digest. 

## Disclaimer
I permit any and all use of this code, but I make no guarantees...and let's face it this was really just an exercise to combat my own boredom late at night.

## Compilation

Clone the source code and navigate to the `iusha/` root directory.
```
$ cd local/path/to/iusha
```
Create a `build/` directory and navigate to it.
```
$ mkdir build && cd $_
```
Once in the build directory, configure CMake and compile the library.
```
$ cmake ..
$ cmake --build .
```
While still in the `build/` directory, run the unit tests to make sure everything is kosher.
```
ctest
```

## External Resources
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf