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
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;

import org.apache.commons.io.IOUtils;
import org.conscrypt.Conscrypt;
import org.conscrypt.EchDnsPacket;
import org.conscrypt.com.android.net.module.util.DnsPacket;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
            "enabled.tls13.com", // TLS 1.3 enabled by Cloudflare with ECH support
            "crypto.cloudflare.com",

            // TLS 1.3 only
            "tls13.1d.pw",

            // ECH enabled
            "draft-13.esni.defo.ie:8413", // OpenSSL s_server
            "draft-13.esni.defo.ie:8414", // OpenSSL s_server, likely forces HRR as it only likes P-384 for TLS =09
            "draft-13.esni.defo.ie:9413", // lighttpd - host down?
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
    }

    @After
    public void tearDown() throws NoSuchAlgorithmException {
        Security.removeProvider("Conscrypt");
        assertFalse(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1")));
    }

    /*
        @Test
        public void testConnectSocket() throws IOException {
            for (String hostString : hosts) {
                System.out.println("EchInteroptTest " + h + " =================================");
                String[] hostPort = hostString.split(":");
                String host = hostPort[0];
                int port = 443;
                if (hostPort.length == 2) {
                    port = Integer.parseInt(hostPort[1]);
                }

                SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
                SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
                assertTrue(Conscrypt.isConscrypt(sslSocket));
                boolean setUpEch = false;
                try {
                    byte[] echConfigList = TestUtils.readTestFile(h.replace(':', '_') + "-ech-config-list.bin");
                    Conscrypt.setUseEchGrease(sslSocket, true);
                    Conscrypt.setEchConfigList(sslSocket, echConfigList);
                    System.out.println("Enabling ECH Config List and ECH GREASE");
                    setUpEch = true;
                } catch (FileNotFoundException e) {
                    System.out.println("Enabling ECH GREASE");
                    Conscrypt.setUseEchGrease(sslSocket, true);
                }
                sslSocket.startHandshake();
                assertTrue(sslSocket.isConnected());
                AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
                if (setUpEch) {
                    assertTrue(abstractConscryptSocket.echAccepted());
                } else {
                    assertFalse(abstractConscryptSocket.echAccepted());
                }
                sslSocket.close();
            }
        }
    */

    /**
     * This is a hack to make a blocking method because the underlying blocking
     * methods that actually do the query are {@code @hide} on Android and on
     * Android's reflection blacklist:
     * <p>
     * {@code Accessing hidden method Landroid/net/NetworkUtils;->resNetworkQuery(ILjava/lang/String;III)Ljava/io/FileDescriptor; (blacklist, reflection, denied)}
     *
     * @see android.net.NetworkUtils#resNetworkQuery(int, String, int, int, int)
     */
    public static byte[] getEchConfigListFromDns(String dnshost) {
        if (Build.VERSION.SDK_INT < 29) {
            return null;
        }
        final byte[][] echConfigListReturn = {null};
        try {
            Executor executor = new Executor() {
                @Override
                public void execute(Runnable command) {
                    final Handler handler = new Handler(Looper.getMainLooper());
                    if (handler == null) {
                        throw new NullPointerException();
                    }
                    if (!handler.post(command)) {
                        throw new RejectedExecutionException(handler + " is shutting down");
                    }
                }
            };
            final CountDownLatch latch = new CountDownLatch(1);

            Class dnsResolverClass = Class.forName("android.net.DnsResolver");
            Field classInField = dnsResolverClass.getField("CLASS_IN");
            final int CLASS_IN = classInField.getInt(null);
            Field flagEmptyField = dnsResolverClass.getField("FLAG_EMPTY");
            final int FLAG_EMPTY = flagEmptyField.getInt(null);
            System.out.println("CLASS_IN " + CLASS_IN + "  FLAG_EMPTY " + FLAG_EMPTY);

            Method getInstance = dnsResolverClass.getMethod("getInstance", (Class[]) null);
            Object dnsResolverInstance = getInstance.invoke(dnsResolverClass);
            System.out.println("dnsResolverInstance " + dnsResolverInstance);

            android.net.DnsResolver dnsResolver = android.net.DnsResolver.getInstance();
            dnsResolver.rawQuery(null, dnshost,
                    CLASS_IN, EchDnsPacket.TYPE_HTTPS, FLAG_EMPTY,
                    executor, null,
                    new android.net.DnsResolver.Callback<byte[]>() {
                        final String host = "deb.debian.org";

                        @Override
                        public void onAnswer(@NonNull byte[] answer, int rcode) {
                            Conscrypt.echPbuf(dnshost + " answer", answer);
                            EchDnsPacket echDnsPacket = new EchDnsPacket(answer);
                            echConfigListReturn[0] = echDnsPacket.getEchConfigList();
                            Conscrypt.echPbuf(dnshost + "echConfigListReturn[0]", echConfigListReturn[0]);
                            latch.countDown();
                        }

                        @Override
                        public void onError(@NonNull android.net.DnsResolver.DnsException error) {
                            System.out.println("onError  " + error);
                            latch.countDown();
                        }
                    });
            latch.await(10, TimeUnit.MINUTES);
        } catch (InterruptedException | ClassNotFoundException | NoSuchFieldException | IllegalAccessException
                | NoSuchMethodException | InvocationTargetException e) {
            // ignored
        }
        return echConfigListReturn[0];
    }

    private class AndroidNetDnsResolverCallback {

        private final CountDownLatch latch = new CountDownLatch(1);
        private byte[] echConfigList = null;

        public byte[] getEchConfigList() {
            return echConfigList;
        }

        public void onAnswer(@NonNull byte[] answer, int rcode) {
            Conscrypt.echPbuf(" answer", answer);
            EchDnsPacket echDnsPacket = new EchDnsPacket(answer);
            echConfigList = echDnsPacket.getEchConfigList();
            Conscrypt.echPbuf("echConfigList", echConfigList);
            latch.countDown();
        }

        public void onError(@NonNull android.net.DnsResolver.DnsException error) {
            System.out.println("onError  " + error);
            latch.countDown();
        }
    }

    //private DnsResolver.DnsResponse

    @Test
    public void testConnectHttpsURLConnection() throws IOException, InterruptedException {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        assertEquals("ie.defo.conscrypt", appContext.getPackageName());

        for (String hostString : hosts) {
            System.out.println("EchInteroptTest.testConnectHttpsURLConnection " + hostString + " ==================");
            String[] h = hostString.split(":");
            String dnshost = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    dnshost = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            byte[] echConfigList = getEchConfigListFromDns(dnshost);
            Conscrypt.echPbuf(hostString, echConfigList);
            return;

            /*
            URL url = new URL("https://" + hostString);
            System.out.println("EchInteroptTest " + url + " =================================");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            SSLSocketFactory delegateSocketFactory = connection.getSSLSocketFactory();
            assertTrue(Conscrypt.isConscrypt(delegateSocketFactory));

            byte[] echConfigList = null;
            connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, echConfigList));
            System.out.println("Enabling ECH Config List and ECH GREASE");
            connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, true));

            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);
            if (connection.getResponseCode() != 200) {
                System.out.println(IOUtils.toString(connection.getErrorStream(), Charset.defaultCharset()));
            }
            connection.getContent();
            assertEquals(200, connection.getResponseCode());
            assertEquals("text/html", connection.getContentType().split(";")[0]);
            System.out.println(host + " " + connection.getCipherSuite());
            assertTrue(connection.getCipherSuite().startsWith("TLS"));
            connection.disconnect();

             */
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
                            //System.out.println("onAnswer " + host + " " + rcode + ": " + new String(answer));
                            Conscrypt.echPbuf("onAnswer " + host + " answer", answer);
                            DnsEchAnswer dnsEchAnswer = new DnsEchAnswer(answer);
                            byte[] echConfigList = dnsEchAnswer.getEchConfigList();
                            Conscrypt.echPbuf("onAnswer " + host + " echConfigList", echConfigList);
                            try {
                                IOUtils.writeChunked(answer,
                                        new FileOutputStream(new File(appContext.getFilesDir(), host + ".bin")));
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            System.out.println("---------------------------------------------------------");
                        }

                        @Override
                        public void onError(@NonNull android.net.DnsResolver.DnsException error) {
                            System.out.println("onError " + error);
                        }
                    });
        }
    }

    static class DnsEchAnswer extends DnsPacket {
        private static final String TAG = "DnsResolver.DnsAddressAnswer";
        private static final boolean DBG = true;

        /**
         * Service Binding [draft-ietf-dnsop-svcb-https-00]
         */
        public static final int TYPE_SVCB = 64;

        /**
         * HTTPS Binding [draft-ietf-dnsop-svcb-https-00]
         */
        public static final int TYPE_HTTPS = 65;

        private final int mQueryType;

        protected DnsEchAnswer(@NonNull byte[] data) throws ParseException {
            super(data);
            if ((mHeader.flags & (1 << 15)) == 0) {
                throw new IllegalArgumentException("Not an answer packet");
            }
            if (mHeader.getRecordCount(QDSECTION) == 0) {
                throw new IllegalArgumentException("No question found");
            }
            // Expect only one question in question section.
            mQueryType = mRecords[QDSECTION].get(0).nsType;
        }

        @NonNull
        public byte[] getEchConfigList() {
            byte[] results = new byte[0];
            if (mHeader.getRecordCount(ANSECTION) == 0) return results;

            for (final DnsRecord ansSec : mRecords[ANSECTION]) {
                // Only support SVCB and HTTPS since only they can have ECH Config Lists
                int nsType = ansSec.nsType;
                if (nsType != mQueryType || (nsType != TYPE_SVCB && nsType != TYPE_HTTPS)) {
                    continue;
                }
                Conscrypt.echPbuf("RR", ansSec.getRR());
                // TODO port local_ech_add
                // TODO results.add(InetAddress.getByAddress(ansSec.getRR()));
            }
            return results;
        }
    }

    private static class EchSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final boolean enableEchGrease;

        private byte[] echConfigList;

        public EchSSLSocketFactory(SSLSocketFactory delegate, boolean enableEchGrease) {
            this.delegate = delegate;
            this.enableEchGrease = enableEchGrease;
        }

        public EchSSLSocketFactory(SSLSocketFactory delegate, byte[] echConfigList) {
            this.delegate = delegate;
            this.enableEchGrease = true;
            this.echConfigList = echConfigList;
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
            return setEchSettings(delegate.createSocket(socket, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException, UnknownHostException {
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
                throws IOException, UnknownHostException {
            return setEchSettings(delegate.createSocket(host, port, localAddress, localPort));
        }

        @Override
        public Socket createSocket(InetAddress host, int port)
                throws IOException {
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return setEchSettings(delegate.createSocket(address, port, localAddress, localPort));
        }

        private Socket setEchSettings(Socket socket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            Conscrypt.setUseEchGrease(sslSocket, enableEchGrease);
            Conscrypt.setEchConfigList(sslSocket, echConfigList);
            return sslSocket;
        }
    }
}
