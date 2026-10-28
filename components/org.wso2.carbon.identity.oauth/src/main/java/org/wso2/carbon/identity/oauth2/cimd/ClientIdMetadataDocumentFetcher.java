/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.cimd;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.conn.DnsResolver;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.oauth2.cimd.ClientIdMetadataDocumentException.ErrorMessage.NO_MATCHING_DOCUMENT;

/**
 * Retrieves a Client ID Metadata Document. Connects only to addresses that are not special-use, follows no
 * redirects, does not use a proxy, and applies fixed time and size limits.
 */
public class ClientIdMetadataDocumentFetcher {

    private static final Log LOG = LogFactory.getLog(ClientIdMetadataDocumentFetcher.class);

    static final int MAX_DOCUMENT_BYTES = 5 * 1024;
    static final long TOTAL_TIMEOUT_MILLIS = 5000;
    private static final int CONNECT_TIMEOUT_MILLIS = 2000;
    private static final int READ_TIMEOUT_MILLIS = 3000;
    private static final int MAX_HEADER_LINE_LENGTH = 8192;
    private static final int MAX_HEADER_COUNT = 50;
    private static final int MAX_CONNECTIONS = 50;
    private static final String JSON_SUFFIX = "+json";

    // Aborts a request at the overall deadline, wherever it is: connecting, TLS, headers or body.
    private static final ScheduledExecutorService DEADLINE_TIMER = Executors.newSingleThreadScheduledExecutor(
            runnable -> {
                Thread thread = new Thread(runnable, "cimd-fetch-deadline");
                thread.setDaemon(true);
                return thread;
            });

    private final CloseableHttpClient httpClient;

    public ClientIdMetadataDocumentFetcher() {

        this(new SpecialUseAddressRejectingDnsResolver(SystemDefaultDnsResolver.INSTANCE));
    }

    ClientIdMetadataDocumentFetcher(DnsResolver dnsResolver) {

        // No useSystemProperties(), so JVM proxy settings are not applied: a proxy would resolve the host itself.
        // TLS uses the JVM default trust store, which Carbon sets to the client trust store.
        this.httpClient = HttpClients.custom()
                .setDnsResolver(dnsResolver)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setMessageConstraints(MessageConstraints.custom()
                                .setMaxLineLength(MAX_HEADER_LINE_LENGTH)
                                .setMaxHeaderCount(MAX_HEADER_COUNT)
                                .build())
                        .build())
                .setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE)
                .setMaxConnTotal(MAX_CONNECTIONS)
                .setMaxConnPerRoute(MAX_CONNECTIONS)
                .disableRedirectHandling()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .build();
    }

    /**
     * Retrieve the document at the given URL.
     *
     * @param url Client Identifier URL, already validated.
     * @return Response body.
     * @throws ClientIdMetadataDocumentException {@code CIMD-60002} for any failure. The cause is logged only.
     */
    public String fetch(String url) throws ClientIdMetadataDocumentException {

        HttpGet request = new HttpGet(url);
        request.setConfig(RequestConfig.custom()
                .setConnectTimeout(CONNECT_TIMEOUT_MILLIS)
                .setConnectionRequestTimeout(CONNECT_TIMEOUT_MILLIS)
                .setSocketTimeout(READ_TIMEOUT_MILLIS)
                .setRedirectsEnabled(false)
                .build());
        request.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

        ScheduledFuture<?> deadline = DEADLINE_TIMER.schedule(request::abort, TOTAL_TIMEOUT_MILLIS,
                TimeUnit.MILLISECONDS);
        boolean completed = false;
        try {
            HttpResponse response = httpClient.execute(request);
            int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK) {
                throw notRetrieved(url, "The response status is " + status + ".", null);
            }
            HttpEntity entity = response.getEntity();
            if (entity == null || !isJsonMediaType(entity.getContentType())) {
                throw notRetrieved(url, "The response is not a JSON media type.", null);
            }
            String body = readBounded(url, entity.getContent());
            completed = true;
            return body;
        } catch (IOException e) {
            throw notRetrieved(url, "The document could not be retrieved.", e);
        } finally {
            deadline.cancel(false);
            if (!completed) {
                // Abort before release, so the rest of an unread body is not downloaded.
                request.abort();
            }
            request.releaseConnection();
        }
    }

    private static String readBounded(String url, InputStream content)
            throws IOException, ClientIdMetadataDocumentException {

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int read;
        while ((read = content.read(buffer)) != -1) {
            if (body.size() + read > MAX_DOCUMENT_BYTES) {
                throw notRetrieved(url, "The document is larger than " + MAX_DOCUMENT_BYTES + " bytes.", null);
            }
            body.write(buffer, 0, read);
        }
        return new String(body.toByteArray(), StandardCharsets.UTF_8);
    }

    private static boolean isJsonMediaType(Header contentType) {

        if (contentType == null || contentType.getValue() == null) {
            return false;
        }
        String mediaType = contentType.getValue().split(";", 2)[0].trim().toLowerCase(Locale.ENGLISH);
        return ContentType.APPLICATION_JSON.getMimeType().equals(mediaType) || mediaType.endsWith(JSON_SUFFIX);
    }

    private static ClientIdMetadataDocumentException notRetrieved(String url, String reason, Throwable cause) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Client ID Metadata Document not retrieved from " + url + ": " + reason, cause);
        }
        return new ClientIdMetadataDocumentException(NO_MATCHING_DOCUMENT, cause);
    }

    /**
     * Resolves a host and refuses it if any of its addresses is special-use. The connection then uses only the
     * addresses that were checked, so the host cannot be re-resolved to another address in between.
     */
    static class SpecialUseAddressRejectingDnsResolver implements DnsResolver {

        private final DnsResolver delegate;

        SpecialUseAddressRejectingDnsResolver(DnsResolver delegate) {

            this.delegate = delegate;
        }

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {

            InetAddress[] addresses = delegate.resolve(host);
            for (InetAddress address : addresses) {
                if (SpecialUseAddresses.isSpecialUse(address)) {
                    throw new UnknownHostException("The host resolves to a special-use address.");
                }
            }
            return addresses;
        }
    }
}
