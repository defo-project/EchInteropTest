
# EchInteropTest

This is a simple example app built on our [Conscrypt
fork](https://github.com/guardianproject/conscrypt) to test TLS [Encrypted
ClientHello (ECH)]() interoperability between various implementations,
platforms, and networks.  This runs as standard Android unit tests on the
emulator.


## Running
```console
$ JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 ./gradlew clean connectedDebugAndroidTest
```

For more info, see https://defo.ie
