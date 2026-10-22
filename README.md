# PKCS#11 Provider
This library is an implementation of an [OpenSSL Provider](https://docs.openssl.org/master/man7/provider) intended to
offer cryptographic operations through devices accessed with PKCS#11.

## Contributing
- When tagging a new version, remember to bump the version number on [CMakeLists.txt](CMakeLists.txt).
- CMake is configured to enforce the usage of C99 because this is the default OpenSSL language and, since
this library is intended to be used as an external OpenSSL module, it's safer to strictly adhere to the
same compilation standards.

## Building From Source
Dependencies:
* [openssl-libs](https://www.openssl.org/) - version 3.0 or greater
* [openssl-devel](https://www.openssl.org/) - version 3.0 or greater

Testing dependencies:
* [GoogleTest](https://github.com/google/googletest)
* [SoftHSMv2](https://github.com/softhsm/SoftHSMv2) - Tested with 2.7.0, but likely to work with older versions too.

To configure as release run:
```sh
cmake -S . -Bbuild -DCMAKE_BUILD_TYPE=Release
```

To configure as debug run:  
```sh
cmake -S . -Bbuild -DCMAKE_BUILD_TYPE=Debug
```

To build run:
```sh
cmake --build build --target [all|pkcs11provider|all_tests]
```
