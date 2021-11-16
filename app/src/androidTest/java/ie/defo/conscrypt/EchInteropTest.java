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
import android.net.DnsResolver;

import org.apache.commons.io.IOUtils;
import org.conscrypt.Conscrypt;
import org.conscrypt.com.android.net.module.util.DnsPacket;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

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

    public static final int TYPE_SVCB = 64; // [draft-ietf-dnsop-svcb-https-00]
    public static final int TYPE_HTTPS = 65; // [draft-ietf-dnsop-svcb-https-00]

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
        prefetchDns(hosts);
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

    void echPbuf(String msg, byte[] buf) {
        int blen = buf.length;
        System.out.print(msg + " (" + blen + "):\n    ");
        for (int i = 0; i < blen; i++) {
            if ((i != 0) && (i % 16 == 0))
                System.out.print("\n    ");
            System.out.print(String.format("%02x:", Byte.toUnsignedInt(buf[i])));
        }
        System.out.print("\n");
    }

    @Test
    public void testConnectHttpsURLConnection() throws IOException {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        assertEquals("ie.defo.conscrypt", appContext.getPackageName());
        DnsResolver dnsResolver = DnsResolver.getInstance();

        dnsResolver.rawQuery(null, "deb.debian.org", DnsResolver.CLASS_IN, DnsResolver.TYPE_A, DnsResolver.FLAG_EMPTY,
                appContext.getMainExecutor(), null,
                new DnsResolver.Callback<byte[]>() {
                    final String host = "deb.debian.org";

                    @Override
                    public void onAnswer(@NonNull byte[] answer, int rcode) {
                        System.out.println("onAnswer " + host + " " + rcode + ": " + new String(answer));
                        echPbuf("onAnswer " + host, answer);
                        System.out.println("------------------------------------------------------------");
                    }

                    @Override
                    public void onError(@NonNull DnsResolver.DnsException error) {
                        System.out.println("onError " + error);
                    }
                });


        for (String hostString : hosts) {
            System.out.println("EchInteroptTest " + hostString + " =================================");
            String[] h = hostString.split(":");
            String tmp = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    tmp = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            final String host = tmp;

            dnsResolver.rawQuery(null, host, DnsResolver.CLASS_IN, TYPE_HTTPS, DnsResolver.FLAG_EMPTY, appContext.getMainExecutor(), null,
                    new DnsResolver.Callback<byte[]>() {

                        @Override
                        public void onAnswer(@NonNull byte[] answer, int rcode) {
                            System.out.println("onAnswer " + host + " " + rcode + ": ");
                            //System.out.println("onAnswer " + host + " " + rcode + ": " + new String(answer));
                            DnsEchAnswer dnsEchAnswer = new DnsEchAnswer(answer);
                            dnsEchAnswer.getEchConfigList();
                            //echPbuf("onAnswer " + host, answer);
                            try {
                                IOUtils.writeChunked(answer,
                                        new FileOutputStream(new File(appContext.getFilesDir(), host + ".bin")));
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            System.out.println("----------------------------------------------------------");
                        }

                        @Override
                        public void onError(@NonNull DnsResolver.DnsException error) {
                            System.out.println("onError " + error);
                        }
                    });

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

    class DnsEchAnswer extends DnsPacket {
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
                echPbuf("RR", ansSec.getRR());
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

    /**
     * Prime the DNS cache with the hosts that are used in these tests.
     */
    private void prefetchDns(String[] hosts) {
        for (final String host : hosts) {
            new Thread() {
                @Override
                public void run() {
                    try {
                        InetAddress.getByName(host);
                    } catch (UnknownHostException e) {
                        // ignored
                    }
                }
            }.start();
        }
    }

    /**
     * < Max RR value size, as given to API
     */
    private static int ECH_MAX_RRVALUE_LEN = 2000;
    /**
     * < Max for an ECHConfig extension
     */
    private static int ECH_MAX_ECHCONFIGEXT_LEN = 100;
    /**
     * < just for a sanity check
     */
    private static int ECH_MIN_ECHCONFIG_LEN = 32;
    /**
     * < for a sanity check
     */
    private static int ECH_MAX_ECHCONFIG_LEN = ECH_MAX_RRVALUE_LEN;

    /**
     * < implementation will try guess type
     */
    private static int ECH_FMT_GUESS = 0;
    /**
     * < one or more catenated binary ECHConfigs
     */
    private static int ECH_FMT_BIN = 1;
    /**
     * < base64 ECHConfigs (';' separated if >1)
     */
    private static int ECH_FMT_B64TXT = 2;
    /**
     * < ascii-hex ECHConfigs (';' separated if >1)
     */
    private static int ECH_FMT_ASCIIHEX = 3;
    /**
     * < presentation form of HTTPSSVC
     */
    private static int ECH_FMT_HTTPSSVC = 4;
    /**
     * the wire-format code for ECH within an SVCB or HTTPS RData
     */
    private static int ECH_PCODE_ECH = 0x0005;


    /**
     * @param rrlen    is the length of the rrval
     * @param rrval    is the binary, base64 or ascii-hex encoded RData
     * @param num_echs says how many SSL_ECH structures are in the returned array
     * @param echs     is the returned array of SSL_ECH
     * @return is 1 for success, error otherwise
     * @brief Decode SVCB/HTTPS RR value provided as binary or ascii-hex
     * <p>
     * The rrval may be the catenation of multiple encoded ECHConfigs.
     * We internally try decode and handle those and (later)
     * use whichever is relevant/best. The fmt parameter can be e.g.
     * ECH_FMT_ASCII_HEX.
     * <p>
     * Note that we "succeed" even if there is no ECHConfigs in the input - some
     * callers might download the RR from DNS and pass it here without looking
     * inside, and there are valid uses of such RRs. The caller can check though
     * using the num_echs output.
     */
    public static byte[] local_svcb_add(int rrfmt, byte[] rrval) {
        byte[] echs;
        int detfmt = ECH_FMT_GUESS;
        int rv = 0;
        int binlen = 0; /* the RData */
        byte[] binbuf = null;
        //int eklen = 0; /* the ECHConfigs, within the above */
        //byte[] ekval = null;
        int cp = 0;
        int remaining = 0;
        String dnsname = null;
        int pcode = 0;
        int plen = 0;
        boolean done = false;

        if (rrfmt == ECH_FMT_ASCIIHEX) {
            detfmt = rrfmt;
        } else if (rrfmt == ECH_FMT_BIN) {
            detfmt = rrfmt;
        } else {
            /* TODO
            rv = ech_guess_fmt(rrlen, (unsigned char*)rrval,&detfmt);
            if (rv == 0) {
                return (rv);
            }
             */
        }
        if (detfmt == ECH_FMT_ASCIIHEX) {
            /* TODO
            rv = hpke_ah_decode(rrlen, rrval, & binlen,&binbuf);
            if (rv == 0) {
                return (rv);
            }
             */
        } else if (detfmt == ECH_FMT_B64TXT) {
            /* TODO
            int ebd_rv = ech_base64_decode(rrval, & binbuf);
            if (ebd_rv <= 0) {
                return (0);
            }
            binlen = (size_t) ebd_rv;
             */
        } else if (detfmt == ECH_FMT_BIN) {
            binlen = rrval.length;
        }

        /*
         * Now we have a binary encoded RData so we'll skip the
         * name, and then walk through the SvcParamKey binary
         * codes 'till we find what we want
         */
        remaining = binlen;

        /*
         * skip 2 octet priority and TargetName as those are the
         * application's responsibility, not the library's
         */
        if (remaining <= 2) return null;
        cp += 2;
        remaining -= 2;
        cp++;
        int clen = rrval[cp];
        while (clen != 0) {
            if (clen <= remaining) {
                cp += clen;
                remaining -= clen + 1;
                clen = rrval[cp];
            }
        }
        //rv = local_decode_rdata_name( & cp,&remaining,&dnsname);
        if (rv != 1) {
            return null;
        }
        //OPENSSL_free(dnsname);
        dnsname = null;

        while (!done && remaining >= 4) {
            pcode = (rrval[cp] << 8) + rrval[cp + 1];
            cp += 2;
            plen = (rrval[cp] << 8) + rrval[cp + 1];
            cp += 2;
            remaining -= 4;
            if (pcode == ECH_PCODE_ECH) {
                //eklen = (size_t) plen;
                //ekval = cp;
                done = true;
            }
            if (plen != 0 && plen <= remaining) {
                cp += plen;
                remaining -= plen;
            }
        }
        if (!done) {
            return null;
        }
        int retlength = rrval.length - cp;
        byte[] ret = new byte[retlength];
        for (int i = 0; i < retlength; i++) {
            ret[i] = rrval[i + cp];
        }
        return ret;
        /*
         * Parse & load any ECHConfigs that we found
         */
        //rv = local_ech_add(ECH_FMT_BIN, eklen, ekval, num_echs, echs);
    }
}
