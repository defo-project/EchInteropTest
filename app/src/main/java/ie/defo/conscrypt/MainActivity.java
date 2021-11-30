/*
 * Copyright (c) 2021 Hans-Christoph Steiner
 * Copyright (c) 2018 Michael Pöhn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ie.defo.conscrypt;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import android.widget.TextView;

import org.conscrypt.Conscrypt;

import java.security.Provider;
import java.security.Security;
import java.util.Locale;

public class MainActivity extends Activity {
    public static final String TAG = "MainActivity";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Security.insertProviderAt(Conscrypt.newProviderBuilder().defaultTlsProtocol("TLSv1.3").build(), 1);
        Security.removeProvider("AndroidOpenSSL");
        for (Provider provider : Security.getProviders()) {
            Log.i(TAG, "TLS Provider: " + provider);
        }
        Conscrypt.checkAvailability();

        GenericWebViewClient webViewClient = new GenericWebViewClient(this);

        setContentView(R.layout.activity_main);
        webView = findViewById(R.id.webview);
        webView.setWebViewClient(webViewClient);
        webView.loadUrl("https://cloudflare.f-droid.org/cdn-cgi/trace");

        Conscrypt.Version version = Conscrypt.version();
        TextView status = findViewById(R.id.status);
        status.setText("TLS Provider: " + Security.getProviders()[0]
                + String.format(Locale.ENGLISH, " (%d.%d.%s)", version.major(), version.minor(), version.patch()));
    }
}
