/*
 * Copyright 2004-2013 H2 Group. Multiple-Licensed under the H2 License,
 * Version 1.0, and under the Eclipse Public License, Version 1.0
 * (http://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.*;

import org.h2.api.ErrorCode;
import org.h2.engine.SysProperties;
import org.h2.message.DbException;
import org.h2.store.fs.FileUtils;
import org.h2.util.StringUtils;

/**
 * A factory to create new block cipher objects.
 */
public class CipherFactory {

    /**
     * The default password to use for the .h2.keystore file
     */
    public static final String KEYSTORE_PASSWORD = "h2pass";
    private static final String KEYSTORE_ALIAS = "h2";
    private static final String KEYSTORE = "~/.h2.keystore";

    // The system SSL keyStore params
    private static final String KEYSTORE_KEY = "javax.net.ssl.keyStore";
    private static final String KEYSTORE_PASSWORD_KEY = "javax.net.ssl.keyStorePassword";

    // SSL socket factories
    private static final String ANONYMOUS_CIPHER_SUITE = "SSL_DH_anon_WITH_RC4_128_MD5";
    private static SSLSocketFactory SSL_SOCKET_FACTORY;
    private static SSLServerSocketFactory SSL_SERVER_SOCKET_FACTORY;
    private static volatile boolean SSL_FACTORY_INITIALIZED;
    private static final Lock SSL_FACTORY_INIT_LOCK = new ReentrantLock();

    private CipherFactory() {
        // utility class
    }

    /**
     * Get a new block cipher object for the given algorithm.
     *
     * @param algorithm the algorithm
     * @return a new cipher object
     */
    public static BlockCipher getBlockCipher(String algorithm) {
        if ("XTEA".equalsIgnoreCase(algorithm)) {
            return new XTEA();
        } else if ("AES".equalsIgnoreCase(algorithm)) {
            return new AES();
        } else if ("FOG".equalsIgnoreCase(algorithm)) {
            return new Fog();
        }
        throw DbException.get(ErrorCode.UNSUPPORTED_CIPHER, algorithm);
    }

    /**
     * Create a secure client socket that is connected to the given address and
     * port.
     *
     * @param address the address to connect to
     * @param port the port
     * @return the socket
     */
    public static Socket createSocket(InetAddress address, int port) throws IOException {
        initSSLSocketFactory();

        SSLSocket secureSocket = (SSLSocket) SSL_SOCKET_FACTORY.createSocket();
        boolean failed = true;
        try {
            SocketAddress sa = new InetSocketAddress(address, port);
            secureSocket.connect(sa, SysProperties.SOCKET_CONNECT_TIMEOUT);
            if (SysProperties.ENABLE_ANONYMOUS_SSL) {
                String[] list = secureSocket.getEnabledCipherSuites();
                list = addAnonymous(list);
                secureSocket.setEnabledCipherSuites(list);
            }
            failed = false;
            return secureSocket;
        } finally {
            if (failed) secureSocket.close();
        }
    }

    /**
     * Create a secure server socket. If a bind address is specified, the socket
     * is only bound to this address.
     *
     * @param port the port to listen on
     * @param bindAddress the address to bind to, or null to bind to all
     *            addresses
     * @return the server socket
     */
    public static ServerSocket createServerSocket(int port,
            InetAddress bindAddress) throws IOException {
        initSSLSocketFactory();

        SSLServerSocketFactory f = SSL_SERVER_SOCKET_FACTORY;
        SSLServerSocket secureSocket;
        if (bindAddress == null) {
            secureSocket = (SSLServerSocket) f.createServerSocket(port);
        } else {
            secureSocket = (SSLServerSocket) f.createServerSocket(port, 0, bindAddress);
        }
        boolean failed = true;
        try {
            if (SysProperties.ENABLE_ANONYMOUS_SSL) {
                String[] list = secureSocket.getEnabledCipherSuites();
                list = addAnonymous(list);
                secureSocket.setEnabledCipherSuites(list);
            }
            failed = false;
            return secureSocket;
        } finally {
            if (failed) secureSocket.close();
        }
    }

    private static void initSSLSocketFactory() {
        if (SSL_FACTORY_INITIALIZED) {
            return;
        }

        SSL_FACTORY_INIT_LOCK.lock();
        try {
            if (SSL_FACTORY_INITIALIZED) {
                return;
            }
            String password, filename = System.getProperty(KEYSTORE_KEY);
            if (SysProperties.USE_SYS_SSL_KEYSTORE &&  filename != null) {
                password = System.getProperty(KEYSTORE_PASSWORD_KEY);
            } else {
                password = KEYSTORE_PASSWORD;
                filename = FileUtils.exists(KEYSTORE)? KEYSTORE: null;
            }
            try {
                KeyStore keyStore = getKeyStore(password, filename);
                H2X509KeyManager km = new H2X509KeyManager(keyStore, password);
                X509Certificate[] trustedCerts = km.certificates.get(KEYSTORE_ALIAS);
                H2X509TrustManager tm = new H2X509TrustManager(trustedCerts);
                SSLContext sslContext = SSLContext.getInstance("TLS");
                SecureRandom rand = new SecureRandom();
                sslContext.init(new KeyManager[]{ km }, new TrustManager[]{ tm }, rand);
                SSL_SOCKET_FACTORY = sslContext.getSocketFactory();
                SSL_SERVER_SOCKET_FACTORY = sslContext.getServerSocketFactory();
            } catch (Exception e) {
                throw DbException.convert(e);
            }
            SSL_FACTORY_INITIALIZED = true;
        } finally {
            SSL_FACTORY_INIT_LOCK.unlock();
        }
    }

    /**
     * Get the keystore object using the given password.
     *
     * @param password the keystore password
     * @return the keystore
     */
    public static KeyStore getKeyStore(String password) throws IOException {
        return getKeyStore(password, null);
    }

    public static KeyStore getKeyStore(String password, String storeFile)
            throws IOException {
        char[] passwd = password.toCharArray();
        try {
            // The following source code can be re-generated
            // if you have a keystore file.
            // This code is (hopefully) more Java version independent
            // than using keystores directly. See also:
            // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4887561
            // (1.4.2 cannot read keystore written with 1.4.1)
            // --- generated code start ---

            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            if (storeFile != null) {
                try (InputStream stream = FileUtils.newInputStream(storeFile)) {
                    store.load(stream, passwd);
                }
                return store;
            }

            store.load(null, passwd);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                    StringUtils.convertHexToBytes(
                            "30820277020100300d06092a864886f70d010101" +
                            "0500048202613082025d02010002818100dc0a13" +
                            "c602b7141110eade2f051b54777b060d0f74e6a1" +
                            "10f9cce81159f271ebc88d8e8aa1f743b505fc2e" +
                            "7dfe38d33b8d3f64d1b363d1af4d877833897954" +
                            "cbaec2fa384c22a415498cf306bb07ac09b76b00" +
                            "1cd68bf77ea0a628f5101959cf2993a9c23dbee7" +
                            "9b19305977f8715ae78d023471194cc900b231ee" +
                            "cb0aaea98d02030100010281810099aa4ff4d0a0" +
                            "9a5af0bd953cb10c4d08c3d98df565664ac5582e" +
                            "494314d5c3c92dddedd5d316a32a206be4ec0846" +
                            "16fe57be15e27cad111aa3c21fa79e32258c6ca8" +
                            "430afc69eddd52d3b751b37da6b6860910b94653" +
                            "192c0db1d02abcfd6ce14c01f238eec7c20bd3bb" +
                            "750940004bacba2880349a9494d10e139ecb2355" +
                            "d101024100ffdc3defd9c05a2d377ef6019fa62b" +
                            "3fbd5b0020a04cc8533bca730e1f6fcf5dfceea1" +
                            "b044fbe17d9eababfbc7d955edad6bc60f9be826" +
                            "ad2c22ba77d19a9f65024100dc28d43fdbbc9385" +
                            "2cc3567093157702bc16f156f709fb7db0d9eec0" +
                            "28f41fd0edcd17224c866e66be1744141fb724a1" +
                            "0fd741c8a96afdd9141b36d67fff6309024077b1" +
                            "cddbde0f69604bdcfe33263fb36ddf24aa3b9922" +
                            "327915b890f8a36648295d0139ecdf68c245652c" +
                            "4489c6257b58744fbdd961834a4cab201801a3b1" +
                            "e52d024100b17142e8991d1b350a0802624759d4" +
                            "8ae2b8071a158ff91fabeb6a8f7c328e762143dc" +
                            "726b8529f42b1fab6220d1c676fdc27ba5d44e84" +
                            "7c72c52064afd351a902407c6e23fe35bcfcd1a6" +
                            "62aa82a2aa725fcece311644d5b6e3894853fd4c" +
                            "e9fe78218c957b1ff03fc9e5ef8ffeb6bd58235f" +
                            "6a215c97d354fdace7e781e4a63e8b"));
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            Certificate[] certs = { CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(
                            new ByteArrayInputStream(
                                    StringUtils.convertHexToBytes(
                            "3082018b3081f502044295ce6b300d06092a8648" +
                            "86f70d0101040500300d310b3009060355040313" +
                            "024832301e170d3035303532363133323630335a" +
                            "170d3337303933303036353734375a300d310b30" +
                            "0906035504031302483230819f300d06092a8648" +
                            "86f70d010101050003818d0030818902818100dc" +
                            "0a13c602b7141110eade2f051b54777b060d0f74" +
                            "e6a110f9cce81159f271ebc88d8e8aa1f743b505" +
                            "fc2e7dfe38d33b8d3f64d1b363d1af4d87783389" +
                            "7954cbaec2fa384c22a415498cf306bb07ac09b7" +
                            "6b001cd68bf77ea0a628f5101959cf2993a9c23d" +
                            "bee79b19305977f8715ae78d023471194cc900b2" +
                            "31eecb0aaea98d0203010001300d06092a864886" +
                            "f70d01010405000381810083f4401a279453701b" +
                            "ef9a7681a5b8b24f153f7d18c7c892133d97bd5f" +
                            "13736be7505290a445a7d5ceb75522403e509751" +
                            "5cd966ded6351ff60d5193de34cd36e5cb04d380" +
                            "398e66286f99923fd92296645fd4ada45844d194" +
                            "dfd815e6cd57f385c117be982809028bba1116c8" +
                            "5740b3d27a55b1a0948bf291ddba44bed337b9"))), };
            store.setKeyEntry(KEYSTORE_ALIAS, privateKey, passwd, certs);
            // --- generated code end ---
            return store;
        } catch (Exception e) {
            throw DbException.convertToIOException(e);
        }
    }

    private static String[] addAnonymous(String[] list) {
        String[] newList = new String[list.length + 1];
        System.arraycopy(list, 0, newList, 1, list.length);
        newList[0] = ANONYMOUS_CIPHER_SUITE;
        return newList;
    }

    static class H2X509KeyManager extends X509ExtendedKeyManager {

        private final Map<String, PrivateKey> privateKeys;
        private final Map<String, X509Certificate[]> certificates;

        H2X509KeyManager(KeyStore ks, String password) throws UnrecoverableKeyException,
                KeyStoreException, NoSuchAlgorithmException {
            this.privateKeys = new HashMap<>();
            this.certificates = new HashMap<>();

            char[] passwd = password.toCharArray();
            for (Enumeration<String> aliases = ks.aliases();
                 aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                if (!ks.isKeyEntry(alias)) {
                    continue;
                }
                Key key = ks.getKey(alias, passwd);
                if (!(key instanceof PrivateKey)) {
                    continue;
                }
                Certificate[] certs = ks.getCertificateChain(alias);
                if ((certs == null) || (certs.length == 0) ||
                        !(certs[0] instanceof X509Certificate)) {
                    continue;
                }
                if (!(certs instanceof X509Certificate[])) {
                    Certificate[] tmp = new X509Certificate[certs.length];
                    System.arraycopy(certs, 0, tmp, 0, certs.length);
                    certs = tmp;
                }
                this.privateKeys.put(alias, (PrivateKey) key);
                this.certificates.put(alias, (X509Certificate[])certs);
            }
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] { KEYSTORE_ALIAS };
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return KEYSTORE_ALIAS;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[] { KEYSTORE_ALIAS };
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return KEYSTORE_ALIAS;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            if (alias == null) {
                return null;
            }
            X509Certificate[] certs = this.certificates.get(alias);
            return certs == null? null: certs.clone();
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return this.privateKeys.get(alias);
        }

    }

    static class H2X509TrustManager extends X509ExtendedTrustManager {

        private final X509Certificate[] trustedCerts;

        H2X509TrustManager(X509Certificate[] trustedCerts) {
            if (trustedCerts == null) {
                this.trustedCerts = new X509Certificate[0];
            } else {
                this.trustedCerts = trustedCerts;
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType,
                                       Socket socket) throws CertificateException {
            validate(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType,
                                       Socket socket) throws CertificateException {
            validate(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType,
                                       SSLEngine engine) throws CertificateException {
            validate(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType,
                                       SSLEngine engine) throws CertificateException {
            validate(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            validate(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            validate(chain, authType);
        }

        void validate(X509Certificate[] chain, String authType)
                throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new CertificateException("Certifications not given");
            }
            for (X509Certificate ch: chain) {
                Principal cdn = ch.getSubjectDN();
                BigInteger csn = ch.getSerialNumber();
                boolean valid = false;

                for (X509Certificate tr: this.trustedCerts) {
                    Principal tdn = tr.getSubjectDN();
                    BigInteger tsn = tr.getSerialNumber();
                    if (cdn.equals(tdn) && csn.equals(tsn)) {
                        valid = true;
                        break;
                    }
                }

                if (!valid) {
                    throw new CertificateException("Certification is invalid");
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return this.trustedCerts.clone();
        }

    }

}
