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

import com.sun.net.httpserver.HttpServer;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class ClientIdMetadataDocumentFetcherTest {

    private static final String DOCUMENT = "{\"client_id\":\"x\"}";

    private HttpServer server;
    private String baseUrl;
    private final AtomicInteger requests = new AtomicInteger();

    @BeforeClass
    public void startServer() throws IOException {

        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ok", exchange -> respond(exchange, 200, "application/json", DOCUMENT, false));
        server.createContext("/json-charset", exchange ->
                respond(exchange, 200, "application/json; charset=utf-8", DOCUMENT, false));
        server.createContext("/vendor-json", exchange ->
                respond(exchange, 200, "application/vnd.example+json", DOCUMENT, false));
        server.createContext("/html", exchange -> respond(exchange, 200, "text/html", DOCUMENT, false));
        server.createContext("/error", exchange -> respond(exchange, 500, "application/json", DOCUMENT, false));
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", baseUrl + "/ok");
            respond(exchange, 302, "application/json", DOCUMENT, false);
        });
        server.createContext("/large", exchange -> respond(exchange, 200, "application/json",
                largeBody(), false));
        server.createContext("/large-chunked", exchange -> respond(exchange, 200, "application/json",
                largeBody(), true));
        server.createContext("/large-header", exchange -> {
            exchange.getResponseHeaders().add("X-Padding", largeBody() + largeBody());
            respond(exchange, 200, "application/json", DOCUMENT, false);
        });
        server.createContext("/endless", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 100; i++) {
                    out.write(' ');
                    out.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException e) {
                // The client aborted.
            }
        });
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterClass
    public void stopServer() {

        server.stop(0);
    }

    @Test
    public void testFetchReturnsJsonDocument() throws Exception {

        ClientIdMetadataDocumentFetcher fetcher = new ClientIdMetadataDocumentFetcher(
                SystemDefaultDnsResolver.INSTANCE);
        assertEquals(fetcher.fetch(baseUrl + "/ok"), DOCUMENT);
        assertEquals(fetcher.fetch(baseUrl + "/json-charset"), DOCUMENT);
        assertEquals(fetcher.fetch(baseUrl + "/vendor-json"), DOCUMENT);
    }

    @Test
    public void testFetchRejectsUnacceptableResponses() {

        ClientIdMetadataDocumentFetcher fetcher = new ClientIdMetadataDocumentFetcher(
                SystemDefaultDnsResolver.INSTANCE);
        for (String path : Arrays.asList("/html", "/error", "/redirect", "/large", "/large-chunked",
                "/large-header")) {
            assertNotRetrieved(fetcher, baseUrl + path);
        }
    }

    @Test
    public void testFetchStopsAtDeadline() {

        ClientIdMetadataDocumentFetcher fetcher = new ClientIdMetadataDocumentFetcher(
                SystemDefaultDnsResolver.INSTANCE);
        long start = System.currentTimeMillis();
        assertNotRetrieved(fetcher, baseUrl + "/endless");
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < ClientIdMetadataDocumentFetcher.TOTAL_TIMEOUT_MILLIS + 1000, "Took " + elapsed + " ms.");
    }

    @Test
    public void testFetchDoesNotConnectToSpecialUseAddress() {

        ClientIdMetadataDocumentFetcher fetcher = new ClientIdMetadataDocumentFetcher();
        int before = requests.get();
        assertNotRetrieved(fetcher, baseUrl + "/ok");
        assertNotRetrieved(fetcher, "http://localhost:" + server.getAddress().getPort() + "/ok");
        assertEquals(requests.get(), before, "No request may reach a special-use address.");
    }

    private void assertNotRetrieved(ClientIdMetadataDocumentFetcher fetcher, String url) {

        try {
            fetcher.fetch(url);
            fail("Expected the fetch to fail for " + url);
        } catch (ClientIdMetadataDocumentException e) {
            assertEquals(e.getErrorMessage().getCode(), "CIMD-60002", url);
        }
    }

    private void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String contentType, String body,
                         boolean chunked) throws IOException {

        requests.incrementAndGet();
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", contentType);
        exchange.sendResponseHeaders(status, chunked ? 0 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String largeBody() {

        StringBuilder body = new StringBuilder("{\"client_id\":\"");
        while (body.length() <= ClientIdMetadataDocumentFetcher.MAX_DOCUMENT_BYTES) {
            body.append('a');
        }
        return body.append("\"}").toString();
    }
}
