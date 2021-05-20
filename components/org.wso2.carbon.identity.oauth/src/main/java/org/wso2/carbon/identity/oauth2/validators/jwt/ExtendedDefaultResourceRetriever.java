/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.validators.jwt;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.oauth2.util.HttpClientUtil;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Extended method to provide proxy support.
 */
public class ExtendedDefaultResourceRetriever extends DefaultResourceRetriever {

    /**
     * If {@code true} the disconnect method of the underlying
     * HttpURLConnection is called after a successful or failed retrieval.
     */
    private boolean disconnectAfterUse;

    /**
     * Creates a new resource retriever. The HTTP timeouts and entity size
     * limit are set to zero (infinite).
     */
    public ExtendedDefaultResourceRetriever() {

        this(0, 0);
    }

    /**
     * Creates a new resource retriever. The HTTP entity size limit is set
     * to zero (infinite).
     *
     * @param connectTimeout The HTTP connects timeout, in milliseconds,
     *                       zero for infinite. Must not be negative.
     * @param readTimeout    The HTTP read timeout, in milliseconds, zero
     *                       for infinite. Must not be negative.
     */
    public ExtendedDefaultResourceRetriever(final int connectTimeout, final int readTimeout) {

        this(connectTimeout, readTimeout, 0);
    }

    /**
     * Creates a new resource retriever.
     *
     * @param connectTimeout The HTTP connects timeout, in milliseconds,
     *                       zero for infinite. Must not be negative.
     * @param readTimeout    The HTTP read timeout, in milliseconds, zero
     *                       for infinite. Must not be negative.
     * @param sizeLimit      The HTTP entity size limit, in bytes, zero for
     *                       infinite. Must not be negative.
     */
    public ExtendedDefaultResourceRetriever(final int connectTimeout, final int readTimeout, final int sizeLimit) {

        this(connectTimeout, readTimeout, sizeLimit, true);
    }

    /**
     * Creates a new resource retriever.
     *
     * @param connectTimeout     The HTTP connects timeout, in
     *                           milliseconds, zero for infinite. Must not
     *                           be negative.
     * @param readTimeout        The HTTP read timeout, in milliseconds,
     *                           zero for infinite. Must not be negative.
     * @param sizeLimit          The HTTP entity size limit, in bytes, zero
     *                           for infinite. Must not be negative.
     * @param disconnectAfterUse If {@code true} the disconnect method of
     *                           the underlying {@link HttpURLConnection}
     *                           will be called after trying to retrieve
     *                           the resource. Whether the TCP socket is
     *                           actually closed or reused depends on the
     *                           underlying HTTP implementation and the
     *                           setting of the {@code keep.alive} system
     *                           property.
     */
    public ExtendedDefaultResourceRetriever(final int connectTimeout,
                                            final int readTimeout,
                                            final int sizeLimit,
                                            final boolean disconnectAfterUse) {

        super(connectTimeout, readTimeout, sizeLimit);
        this.disconnectAfterUse = disconnectAfterUse;
    }

    /**
     * Returns {@code true} if the disconnect method of the underlying
     * {@link HttpURLConnection} will be called after trying to retrieve
     * the resource. Whether the TCP socket is actually closed or reused
     * depends on the underlying HTTP implementation and the setting of the
     * {@code keep.alive} system property.
     *
     * @return If {@code true} the disconnect method of the underlying
     * {@link HttpURLConnection} will be called after trying to
     * retrieve the resource.
     */
    public boolean disconnectsAfterUse() {

        return disconnectAfterUse;
    }

    /**
     * Controls calling of the disconnect method the underlying
     * {@link HttpURLConnection} after trying to retrieve the resource.
     * Whether the TCP socket is actually closed or reused depends on the
     * underlying HTTP implementation and the setting of the
     * {@code keep.alive} system property.
     * <p>
     * If {@code true} the disconnect method of the underlying
     * {@link HttpURLConnection} will be called after trying to
     * retrieve the resource.
     */
    public void setDisconnectsAfterUse(final boolean disconnectAfterUse) {

        this.disconnectAfterUse = disconnectAfterUse;
    }

    @Override
    public Resource retrieveResource(final URL url) throws IOException {

        try {
            HttpGet request = new HttpGet(url.toString());
            HttpClient httpClient = HttpClientUtil.getHttpClient(url);
            HttpResponse httpResponse = httpClient.execute(request);

            // Check HTTP code + message
            final int statusCode = httpResponse.getStatusLine().getStatusCode();
            final String statusMessage = httpResponse.getEntity().toString();
            String content = EntityUtils.toString(httpResponse.getEntity(), StandardCharsets.UTF_8);

            // Ensure 2xx status code.
            if (statusCode > 299 || statusCode < 200) {
                throw new IOException("HTTP " + statusCode + ": " + statusMessage);
            }

            return new Resource(content, httpResponse.getEntity().getContentType().toString());

        } catch (ClassCastException e) {
            throw new IOException("Couldn't open HTTP(S) connection: " + e.getMessage(), e);
        }
    }

}
