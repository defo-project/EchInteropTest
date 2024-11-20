/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ie.defo.conscrypt;

import android.content.Context;

import org.apache.commons.io.IOUtils;
import org.conscrypt.Conscrypt;
import org.conscrypt.EchDnsPacket;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public class EchInteropTest {

    String[] hosts = {
            "www.yandex.ru",
            "openstreetmap.org",
            "en.wikipedia.org",
            "web.wechat.com",
            "mirrors.kernel.org",
            "www.google.com",
            "check-tls.akamaized.net", // uses SNI
            "duckduckgo.com", // TLS 1.3
            "deb.debian.org", // TLS 1.3 Fastly
            "enabled.tls13.com", // TLS 1.3 enabled by Cloudflare

            // ECH enabled
            "cloudflare-ech.com",
            "cloudflare.f-droid.org",
            //"draft-13.esni.defo.ie:8413", // OpenSSL s_server
            //"draft-13.esni.defo.ie:8414", // OpenSSL s_server, likely forces HRR as it only likes P-384 for TLS =09
            "draft-13.esni.defo.ie:9413",  // lighttpd
            "draft-13.esni.defo.ie:10413", // nginx
            "draft-13.esni.defo.ie:11413", // apache
            "draft-13.esni.defo.ie:12413", // haproxy shared mode (haproxy terminates TLS)
            "draft-13.esni.defo.ie:12414", // haproxy plit mode (haproxy only decrypts ECH)
    };

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        assertTrue(Conscrypt.isAvailable());
        assertTrue(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1.3")));
        Conscrypt.checkAvailability();
    }

    @After
    public void tearDown() throws NoSuchAlgorithmException {
        Security.removeProvider("Conscrypt");
        assertFalse(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1")));
    }

    @Test
    public void testConnectSocket() throws IOException {
        for (String hostString : hosts) {
            System.out.println("== EchInteroptTest.testConnectSocket " + hostString + " ===========================");
            String[] h = hostString.split(":");
            String host = h[0];
            String dnshost = host;
            int port = 443;
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    dnshost = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                    port = Integer.parseInt(h[1]);
                }
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            if (Conscrypt.getEchConfigListFromDns(dnshost) == null) {
                System.out.println(" echAccepted false");
                assertFalse(Conscrypt.echAccepted(sslSocket));
            } else {
                System.out.println(" echAccepted true");
                assertTrue(Conscrypt.echAccepted(sslSocket));
            }
            sslSocket.close();
        }
    }

    @Test
    public void testConnectHttpsURLConnectionAutoEch() throws IOException {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        assertEquals("ie.defo.conscrypt", appContext.getPackageName());

        for (String hostString : hosts) {
            System.out.println("== EchInteroptTest.testConnectHttpsURLConnectionAutoEch " + hostString + " ========");
            String[] h = hostString.split(":");
            String dnshost = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    dnshost = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }

            URL url = new URL("https://" + hostString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            SSLSocketFactory delegate = connection.getSSLSocketFactory();
            assertTrue(Conscrypt.isConscrypt(delegate));

            SaveInstanceSSLSocketFactory saveInstanceSSLSocketFactory = new SaveInstanceSSLSocketFactory(delegate);
            connection.setSSLSocketFactory(saveInstanceSSLSocketFactory);

            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                System.out.println(hostString + " " + connection.getContentType());
                assertEquals("text/html", connection.getContentType().split(";")[0]);
            } else if (responseCode == 301 || responseCode == 302) {
                // crypto.cloudflare.com is a redirect
            } else {
                InputStream errorStream = connection.getErrorStream();
                if (errorStream != null) {
                    System.out.println(IOUtils.toString(errorStream, Charset.defaultCharset()));
                }
                fail("Response code should be 200/301/302, was " + responseCode);
            }
            connection.getContent();
            assertTrue(connection.getCipherSuite().startsWith("TLS"));

            System.out.println("getCheckDnsForEch: saveInstanceSSLSocketFactory.sslSocket "
                    + Conscrypt.getCheckDnsForEch(saveInstanceSSLSocketFactory.sslSocket));

            if (Conscrypt.getEchConfigListFromDns(dnshost) == null) {
                System.out.println(" echAccepted false");
                assertFalse("ECH should NOT have been accepted",
                        Conscrypt.echAccepted(saveInstanceSSLSocketFactory.sslSocket));
            } else {
                System.out.println(" echAccepted true");
                Conscrypt.echPbuf("saveInstanceSSLSocketFactory.sslSocket",
                        Conscrypt.getEchConfigList(saveInstanceSSLSocketFactory.sslSocket));
                assertTrue("ECH should have been accepted",
                        Conscrypt.echAccepted(saveInstanceSSLSocketFactory.sslSocket));
            }
            connection.disconnect();
        }
    }

    @Test
    public void testConnectHttpsURLConnectionManualEch() throws IOException {
        for (String hostString : hosts) {
            System.out.println("== EchInteroptTest.testConnectHttpsURLConnectionManualEch " + hostString + " ======");
            String[] h = hostString.split(":");
            String dnshost = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    dnshost = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            byte[] echConfigList = Conscrypt.getEchConfigListFromDns(dnshost);
            Conscrypt.echPbuf("Conscrypt.getEchConfigListFromDns(" + hostString, echConfigList);

            URL url = new URL("https://" + hostString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            SSLSocketFactory delegate = connection.getSSLSocketFactory();
            assertTrue(Conscrypt.isConscrypt(delegate));

            ManualEchSSLSocketFactory manualEchSSLSocketFactory = new ManualEchSSLSocketFactory(delegate);
            connection.setSSLSocketFactory(manualEchSSLSocketFactory);

            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                assertEquals("text/html", connection.getContentType().split(";")[0]);
            } else if (responseCode == 301 || responseCode == 302) {
                // crypto.cloudflare.com is a redirect
            } else {
                InputStream errorStream = connection.getErrorStream();
                if (errorStream != null) {
                    System.out.println(IOUtils.toString(errorStream, Charset.defaultCharset()));
                }
                fail("Response code should be 200/301/302, was " + responseCode);
            }
            connection.getContent();
            System.out.println(dnshost + " " + connection.getCipherSuite());
            assertTrue(connection.getCipherSuite().startsWith("TLS"));

            if (echConfigList == null) {
                System.out.println(" echAccepted false");
                assertFalse("ECH should not have worked",
                        Conscrypt.echAccepted(manualEchSSLSocketFactory.sslSocket));
            } else {
                System.out.println(" echAccepted true");
                Conscrypt.echPbuf("Conscrypt.getEchConfigList(disableAutoEchSSLSocketFactory.sslSocket",
                        Conscrypt.getEchConfigList(manualEchSSLSocketFactory.sslSocket));
                assertTrue("ECH should have worked",
                        Conscrypt.echAccepted(manualEchSSLSocketFactory.sslSocket));
            }
            connection.disconnect();
        }
    }

    @Test
    public void testConnectCloudflareTrace() throws IOException, InterruptedException {
        final String[] hosts = {
                "cloudflare-ech.com",
                "cloudflare.f-droid.org",
        };
        final String urlFormat = "https://%s/cdn-cgi/trace";

        for (String host : hosts) {
            String urlString = String.format(urlFormat, host);
            System.out.println("EchInteroptTest.testConnectCloudflareTrace " + urlString + " =================");

            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);
            if (connection.getResponseCode() != 200) {
                System.out.println(IOUtils.toString(connection.getErrorStream()));
            }

            assertEquals(200, connection.getResponseCode());
            assertEquals("text/plain", connection.getContentType().split(";")[0]);
            String trace = IOUtils.toString(connection.getInputStream());
            System.out.println(urlString + " " + connection.getCipherSuite() + ":\n" + trace);
            assertTrue(connection.getCipherSuite().startsWith("TLS"));
            assertTrue(host + " contains sni=encrypted", trace.contains("sni=encrypted"));
            assertFalse(host + " does NOT contain sni=plaintext", trace.contains("sni=plaintext"));
            connection.disconnect();
        }
    }

    //@Test
    public void testWriteOutDnsAnswerBytes() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        assertEquals("ie.defo.conscrypt", appContext.getPackageName());

        for (String hostString : hosts) {
            System.out.println("EchInteroptTest.testWriteOutDnsAnswerBytes " + hostString + " =====================");
            String[] h = hostString.split(":");
            String tmp = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    tmp = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            final String host = tmp;

            android.net.DnsResolver dnsResolver = android.net.DnsResolver.getInstance();
            dnsResolver.rawQuery(null, host,
                    android.net.DnsResolver.CLASS_IN, EchDnsPacket.TYPE_HTTPS, android.net.DnsResolver.FLAG_EMPTY,
                    appContext.getMainExecutor(), null,
                    new android.net.DnsResolver.Callback<byte[]>() {

                        @Override
                        public void onAnswer(@NonNull byte[] answer, int rcode) {
                            System.out.println("onAnswer " + host + " " + rcode + ": ");
                            Conscrypt.echPbuf("onAnswer " + host + " answer", answer);
                            EchDnsPacket echDnsPacket = new EchDnsPacket(answer);
                            byte[] echConfigList = echDnsPacket.getEchConfigList();
                            Conscrypt.echPbuf("onAnswer " + host + " echConfigList", echConfigList);
                            try {
                                IOUtils.writeChunked(answer,
                                        new FileOutputStream(new File(appContext.getFilesDir(), host + ".bin")));
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            System.out.println("--------------------------------------------------------");
                        }

                        @Override
                        public void onError(@NonNull android.net.DnsResolver.DnsException error) {
                            System.out.println("onError " + error);
                        }
                    });
        }
    }

    /**
     * SSLSocketFactory that only saves the SSLSocket instance, then Conscrypt should auto-fetch from DNS
     */
    private static class SaveInstanceSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private SSLSocket sslSocket;

        public SaveInstanceSSLSocketFactory(SSLSocketFactory delegate) {
            this.delegate = delegate;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
                throws IOException {
            return saveInstance(delegate.createSocket(socket, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException, UnknownHostException {
            return saveInstance(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
                throws IOException, UnknownHostException {
            return saveInstance(delegate.createSocket(host, port, localAddress, localPort));
        }

        @Override
        public Socket createSocket(InetAddress address, int port)
                throws IOException {
            return saveInstance(delegate.createSocket(address, port));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return saveInstance(delegate.createSocket(address, port, localAddress, localPort));
        }

        private Socket saveInstance(Socket socket) {
            sslSocket = (SSLSocket) socket;
            return sslSocket;
        }
    }

    /**
     * SSLSocketFactory that disables the DNS auto-fetch, then manually do DNS in the test.
     */
    private static class ManualEchSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private String host;
        private SSLSocket sslSocket;

        public ManualEchSSLSocketFactory(SSLSocketFactory delegate) {
            this.delegate = delegate;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
                throws IOException {
            this.host = host;
            return setEchSettings(delegate.createSocket(socket, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException, UnknownHostException {
            this.host = host;
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
                throws IOException, UnknownHostException {
            this.host = host;
            return setEchSettings(delegate.createSocket(host, port, localAddress, localPort));
        }

        @Override
        public Socket createSocket(InetAddress address, int port)
                throws IOException {
            return setEchSettings(delegate.createSocket(address, port));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return setEchSettings(delegate.createSocket(address, port, localAddress, localPort));
        }

        private Socket setEchSettings(Socket socket) {
            sslSocket = (SSLSocket) socket;
            Conscrypt.setUseEchGrease(sslSocket, false);
            Conscrypt.setCheckDnsForEch(sslSocket, false);
            byte[] echConfigList = Conscrypt.getEchConfigListFromDns(host, socket.getPort());
            Conscrypt.setEchConfigList(sslSocket, echConfigList);
            return sslSocket;
        }
    }
}
