package com.example.tls;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import javax.net.ssl.*;
import java.io.*;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.LogManager;

public class SimpleTLSClient {

    private static final Logger logger = LoggerFactory.getLogger(SimpleTLSClient.class);

    public static void main(String[] args) throws Exception {
        java.util.logging.LogManager.getLogManager().reset();
        java.util.logging.Logger rootLogger = LogManager.getLogManager().getLogger("");
        rootLogger.setLevel(Level.FINER);
        SLF4JBridgeHandler.install();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        logger.info("SimpleTLSClient started");

        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        try (SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 8443)) {
            socket.startHandshake();

            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            writer.write("Hello, TLS server!\n");
            writer.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Received: " + line);
            }
        }
    }
}