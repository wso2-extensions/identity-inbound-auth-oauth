/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oidc.session.backchannellogout;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.lang.StringUtils;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class LogoutRequestSenderTest {

    private AutoCloseable closeable;
    private LogoutRequestSender logoutRequestSender;

    /*
     * The logout request is executed in a spawned child thread and it makes it harder to
     * test the request. To overcome this, we are using a mock server to receive the request
     * and add the logout tokens for each method to a list.
     */
    private HttpServer mockServer;
    private static final int MOCK_SERVER_PORT = 8081;
    private static final List<String> mockServerTokenList = new ArrayList<>();

    @BeforeClass
    public void setUp() throws IOException {

        closeable = MockitoAnnotations.openMocks(this);
        startMockServer();
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeable.close();
        if (mockServer != null) {
            mockServer.stop(0);
        }
    }

    private void startMockServer() throws IOException {

        mockServer = HttpServer.create(new InetSocketAddress(MOCK_SERVER_PORT), 0);
        mockServer.createContext("/logout1", new MockHandler(200, "Success"));
        mockServer.createContext("/logout2", new MockHandler(200, "Success"));
        // Use the default executor.
        mockServer.setExecutor(null);
        mockServer.start();
    }

    private void initLogoutRequestSender(String poolSize, String workQueueSize, String keepAliveTime,
                                         String connectTimeout, String socketTimeout) {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(
                    OIDCSessionConstants.OIDCLogoutRequestConstants.POOL_SIZE)).thenReturn(poolSize);
            identityUtil.when(() -> IdentityUtil.getProperty(
                    OIDCSessionConstants.OIDCLogoutRequestConstants.WORK_QUEUE_SIZE)).thenReturn(workQueueSize);
            identityUtil.when(() -> IdentityUtil.getProperty(
                    OIDCSessionConstants.OIDCLogoutRequestConstants.KEEP_ALIVE_TIME)).thenReturn(keepAliveTime);
            identityUtil.when(() -> IdentityUtil.getProperty(
                    OIDCSessionConstants.OIDCLogoutRequestConstants.HTTP_CONNECT_TIMEOUT)).thenReturn(connectTimeout);
            identityUtil.when(() -> IdentityUtil.getProperty(
                    OIDCSessionConstants.OIDCLogoutRequestConstants.HTTP_SOCKET_TIMEOUT)).thenReturn(socketTimeout);
            identityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SLO_HOST_NAME_VERIFICATION_ENABLED)).thenReturn("true");

            logoutRequestSender = LogoutRequestSender.getInstance();
        }
    }

    /**
     * Mock handler to handle HTTP requests and extract the logout token from the request body.
     */
    private static class MockHandler implements HttpHandler {

        private final int responseCode;
        private final String responseBody;

        public MockHandler(int responseCode, String responseBody) {

            this.responseCode = responseCode;
            this.responseBody = responseBody;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {

            // Read the request body and extract the logout token.
            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            if (StringUtils.isNotEmpty(requestBody) && requestBody.contains("logout_token")) {
                String logoutToken = requestBody.split("logout_token=")[1].split("&")[0];
                mockServerTokenList.add(logoutToken);
            }

            // Send the response.
            exchange.sendResponseHeaders(responseCode, responseBody.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBody.getBytes());
            }
        }
    }

    @BeforeMethod
    public void beforeMethod() throws NoSuchFieldException, IllegalAccessException {

        // Reset the LogoutRequestSender instance before each test.
        Field instance = LogoutRequestSender.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);

        // Reset the mock server token list.
        mockServerTokenList.clear();
    }

    @DataProvider
    public Object[][] logoutRequestSenderDataProvider() {

        return new Object[][]{
                {null, null, null, null, null},
                {"10", "100", "60000", "10000", "20000"},
                {null, "-1", null, null, null},
                {"-1", null, null, null, null},
                {"", "", "", "", ""},
        };
    }

    @Test(dataProvider = "logoutRequestSenderDataProvider")
    public void testSendLogoutRequests(String poolSize, String workQueueSize, String keepAliveTime,
                                       String connectTimeout, String socketTimeout) throws Exception {

        initLogoutRequestSender(poolSize, workQueueSize, keepAliveTime, connectTimeout, socketTimeout);

        try (MockedConstruction<DefaultLogoutTokenBuilder> tokenBuilderMockCons = mockConstruction(
                DefaultLogoutTokenBuilder.class, (mock, context) -> {
                    Map<String, String> logoutTokenList = new HashMap<>();
                    logoutTokenList.put("logoutToken1", "http://localhost:" + MOCK_SERVER_PORT + "/logout1");
                    logoutTokenList.put("logoutToken2", "http://localhost:" + MOCK_SERVER_PORT + "/logout2");
                    when(mock.buildLogoutToken(any(), any())).thenReturn(logoutTokenList);
            });
        ) {
            // Call the method under test.
            logoutRequestSender.sendLogoutRequests("testCookie", "testTenant");

            // Stop accepting new tasks and wait for the thread pool to finish processing.
            Field threadPoolField = LogoutRequestSender.class.getDeclaredField("threadPool");
            threadPoolField.setAccessible(true);
            ExecutorService threadPool = (ExecutorService) threadPoolField.get(logoutRequestSender);

            threadPool.shutdown();
            if (!threadPool.awaitTermination(10, TimeUnit.SECONDS)) {
                throw new RuntimeException("Timeout waiting for thread pool to finish.");
            }

            // Verify that the logout token was sent to the mock server.
            Assert.assertEquals(mockServerTokenList.size(), 2);
            Assert.assertTrue(mockServerTokenList.contains("logoutToken1"));
            Assert.assertTrue(mockServerTokenList.contains("logoutToken2"));
        }
    }
}
