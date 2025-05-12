# BouncyCastle LTS TLS issues

Generate initial keypair

```bash
# Compile code
./mvnw clean install

# Generate server key
keytool -genkeypair -alias mykey -keyalg RSA -keysize 4096 -validity 365 -keystore server.jks -storepass changeme

# start TLS server on port 8443
java -cp "target/tls-test-1.0-SNAPSHOT.jar:target/libs/*" com.example.tls.SimpleTLSServer
```

Start TLS client
```bash
java -cp "target/tls-test-1.0-SNAPSHOT.jar:target/libs/*" com.example.tls.SimpleTLSClient
```

Should fail with
```plaintext
Exception in thread "main" java.lang.RuntimeException: Cipher buffering error in JCE provider BC
        at java.base/sun.security.ssl.SSLCipher$T11BlockWriteCipherGenerator$BlockWriteCipher.encrypt(SSLCipher.java:1533)
        at java.base/sun.security.ssl.OutputRecord.t10Encrypt(OutputRecord.java:532)
        at java.base/sun.security.ssl.OutputRecord.encrypt(OutputRecord.java:469)
        at java.base/sun.security.ssl.SSLSocketOutputRecord.encodeAlert(SSLSocketOutputRecord.java:78)
        at java.base/sun.security.ssl.TransportContext.fatal(TransportContext.java:419)
        at java.base/sun.security.ssl.TransportContext.fatal(TransportContext.java:326)
        at java.base/sun.security.ssl.TransportContext.fatal(TransportContext.java:321)
        at java.base/sun.security.ssl.SSLSocketImpl.handleException(SSLSocketImpl.java:1712)
        at java.base/sun.security.ssl.SSLSocketImpl.startHandshake(SSLSocketImpl.java:470)
        at java.base/sun.security.ssl.SSLSocketImpl.startHandshake(SSLSocketImpl.java:426)
        at com.example.tls.SimpleTLSClient.main(SimpleTLSClient.java:33)
        Suppressed: java.lang.RuntimeException: Cipher buffering error in JCE provider BC
                at java.base/sun.security.ssl.SSLCipher$T11BlockWriteCipherGenerator$BlockWriteCipher.encrypt(SSLCipher.java:1533)
                at java.base/sun.security.ssl.OutputRecord.t10Encrypt(OutputRecord.java:532)
                at java.base/sun.security.ssl.OutputRecord.encrypt(OutputRecord.java:469)
                at java.base/sun.security.ssl.SSLSocketOutputRecord.encodeAlert(SSLSocketOutputRecord.java:78)
                at java.base/sun.security.ssl.TransportContext.warning(TransportContext.java:278)
                at java.base/sun.security.ssl.SSLSocketImpl.deliverClosedNotify(SSLSocketImpl.java:749)
                at java.base/sun.security.ssl.SSLSocketImpl.closeNotify(SSLSocketImpl.java:737)
                at java.base/sun.security.ssl.SSLSocketImpl.duplexCloseOutput(SSLSocketImpl.java:661)
                at java.base/sun.security.ssl.SSLSocketImpl.close(SSLSocketImpl.java:584)
                at com.example.tls.SimpleTLSClient.main(SimpleTLSClient.java:32)
        Caused by: javax.crypto.ShortBufferException: Need at least 144 bytes of space in output buffer
                at java.base/javax.crypto.CipherSpi.bufferCrypt(CipherSpi.java:765)
                at java.base/javax.crypto.CipherSpi.engineUpdate(CipherSpi.java:560)
                at java.base/javax.crypto.Cipher.update(Cipher.java:2043)
                at java.base/sun.security.ssl.SSLCipher$T11BlockWriteCipherGenerator$BlockWriteCipher.encrypt(SSLCipher.java:1520)
                ... 9 more
Caused by: javax.crypto.ShortBufferException: Need at least 144 bytes of space in output buffer
        at java.base/javax.crypto.CipherSpi.bufferCrypt(CipherSpi.java:765)
        at java.base/javax.crypto.CipherSpi.engineUpdate(CipherSpi.java:560)
        at java.base/javax.crypto.Cipher.update(Cipher.java:2043)
        at java.base/sun.security.ssl.SSLCipher$T11BlockWriteCipherGenerator$BlockWriteCipher.encrypt(SSLCipher.java:1520)
        ... 10 more
```