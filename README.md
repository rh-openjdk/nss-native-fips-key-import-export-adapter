# [OPENJDK-2135]: NSS Native FIPS Key Import Export Adapter

This native library is an adapter for OpenJDK to use the NSS
PKCS&nbsp;#&#8203;11 software token (`libsoftokn3.so`) in FIPS mode. It provides
support to import and export secret and private key material in plain.
This enables Java applications to manage PKCS&nbsp;#&#8203;12 key stores through
the `java.security.KeyStore` API and benefit from FIPS-certified cryptography.
Note: this library replaces the Java FIPS Key Importer Exporter in _Red Hat
builds of OpenJDK_ ([FIPSKeyImporter.java]).

The `libnssadapter.so` shared object provided by this library dynamically links
`libsoftokn3.so` and `libnss3.so`. Thus, a Linux operating system with the NSS
package installed is required.

In order to use this library with OpenJDK, the _SunPKCS11_ security provider
must be initialized with the following configuration (e.g. `nss.cfg`):

```
name = NSS-FIPS
library = /path/to/libnssadapter.so
slot = 3
nssUseSecmode = false
```

## Makefile

The Makefile has support for:

* Formatting the C code (with `clang-format`)
* Building, rebuilding and cleaning (RELEASE and DEBUG modes)
* Showing built library information (such as linkage and symbols)
* Running the test suite (with a specified `java` executable)
    * This test suite ensures the system is in FIPS mode, and is known to work
      with _Temurin_ builds of _OpenJDK_ 8, 11, 17 and 21
* Building a source tarball

To see a help message with all the `make` targets and a brief description invoke
`make help`.


## Debugging traces

This library implements logging functionality for both development and release
troubleshooting. Logging supports colored terminal output (ANSI escape codes)
and either displaying messages on `stderr` or recording them to a file. The
`NSS_ADAPTER_DEBUG` environment variable can be set to control logging output
as follows:

* `NSS_ADAPTER_DEBUG=no`: debug traces are disabled (default in RELEASE builds)
* `NSS_ADAPTER_DEBUG=yes`: debug traces are enabled, writing to `stderr`
  (monochromatic output)
* `NSS_ADAPTER_DEBUG=color`: debug traces are enabled, writing to `stderr`
  (colored output, default in DEBUG builds)
* `NSS_ADAPTER_DEBUG=yes:/tmp/trace.txt` or
  `NSS_ADAPTER_DEBUG=color:/tmp/trace.txt`: debug traces are enabled, writing to
  the specified file
    * The file is opened in append mode
    * If an error occurs while opening the file, the error is logged to `stderr`
      and debug traces are disabled

When the library is built in DEBUG mode, sensitive PKCS&nbsp;#&#8203;11
attribute values are logged, i.e. plain keys! When the library is built in
RELEASE mode, secret and private key material is not logged.

[OPENJDK-2135]: https://issues.redhat.com/browse/OPENJDK-2135 "Reanalyze import/export of cleartext keys from the NSS PKCS#11 software token in FIPS"
[FIPSKeyImporter.java]: https://github.com/rh-openjdk/jdk/blob/75ffdc48edad8795cfaf2fa31c743396d9054534/src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11/FIPSKeyImporter.java "fips-21u@rh-openjdk/jdk"
