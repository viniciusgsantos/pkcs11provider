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

To build on *nix as release run:
```sh
cmake -S . -Bbuild -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -DCMAKE_C_FLAGS=-fPIC
cmake --build build --target all
```

To build on *nix as debug run:  
```sh
cmake -S . -Bbuild -DCMAKE_BUILD_TYPE=Debug -G "Unix Makefiles" -DCMAKE_C_FLAGS=-fPIC
cmake --build build --target all
```

If you have more than one version of OpenSSL installed, pass the `OPENSSL_ROOT_DIR` cmake variable pointing to the root installation. F. ex., if you 
want to use the version installed in `/usr/local`:
```sh
cmake -S . -Bbuild -DOPENSSL_ROOT_DIR=/usr/local ...
```

If you want to configure for a place other than `/usr/local/` add `-DCMAKE_INSTALL_PREFIX=<your desired location>` to `cmake` command.  