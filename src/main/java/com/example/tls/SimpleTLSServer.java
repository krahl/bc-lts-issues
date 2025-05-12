package com.example.tls;

import javax.net.ssl.*;

import java.io.*;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class SimpleTLSServer {

    private static final List<String> CIPHER_SUITES = List.of(
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA256"
    );

    private static final AtomicInteger COUNTER = new AtomicInteger(0);

    public static void main(String[] args) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream keyStoreStream = new FileInputStream("server.jks")) {
            keyStore.load(keyStoreStream, "changeme".toCharArray());
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, "changeme".toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(8443);

        System.out.println("TLS server started on port 8443");

        while (true) {
            try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {

                if (args.length > 0 && args[0].equals("--default-ciphers")) {
                    String enabledCipherSuite = clientSocket.getSession().getCipherSuite();
                    System.out.println("Client connected with cipher suite: " + enabledCipherSuite);
                } else {
                    String cipherSuite = CIPHER_SUITES.get(COUNTER.getAndIncrement() % CIPHER_SUITES.size());
                    clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});
                    System.out.println("Client connected with cipher suite: " + cipherSuite);
                }

                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

                writer.write("Hello, TLS client!\n");
                writer.flush();

                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Received: " + line);
                }
            } catch (Exception e) {
                System.err.println("Unexpected error: " + e.getMessage());
            }
        }
    }
}
