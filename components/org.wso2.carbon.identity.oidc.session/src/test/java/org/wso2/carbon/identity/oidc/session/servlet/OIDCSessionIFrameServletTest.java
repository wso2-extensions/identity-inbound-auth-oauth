/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oidc.session.servlet;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

/**
 * Unit test coverage for OIDCSessionIFrameServlet class
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class OIDCSessionIFrameServletTest extends TestOIDCSessionBase {

    private OIDCSessionIFrameServlet oidcSessionIFrameServlet;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    private static final String CLIENT_ID_VALUE = "3T9l2uUf8AzNOfmGS9lPEIsdrR8a";
    private static final String APP_NAME = "myApp";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String USERNAME = "user1";
    private static final String CALLBACK_URL = "http://localhost:8080/playground2/oauth2client";
    private static final int TENANT_ID = -1234;
    private static final String INVALID_CLIENT_ID = "3T9l2ufg8AzNOfmGS9lPEIsdrR8a";
    private static final String CLIENT_ID_WITH_NO_CALLBACK_URL = "3T9l2uUf8AzNOfmGS9lPEIsdrR7b";
    private static final String SECRET__WITH_NO_CALLBACK_URL = "87n9a540f544777860e44e75f605d445";
    private static final String CLIENT_ID_WITH_VALID_REGEX_CALLBACK_URL = "4T9l2uUf8AzNOfmGS9lPEIsdrR7b";
    private static final String CLIENT_ID_WITH_INVALID_REGEX_CALLBACK_URL = "4T8l2uUf8AzNOfmGS9lPEIsdrR7b";
    private static final String INVALID_REGEX_CALLBACK_URL = "regexp=http://localhost:8080/playground" +
            ".appone/oauth2client";
    private static final String VALID_REGEX_CALLBACK_URL = "regexp=http://localhost:8080/playground2/oauth2client";

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setupBeforeClass() throws Exception {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        initiateInMemoryH2(identityDatabaseUtil);
        createOAuthApp(CLIENT_ID_VALUE, SECRET, USERNAME, APP_NAME, "ACTIVE", CALLBACK_URL);
        createOAuthApp(CLIENT_ID_WITH_NO_CALLBACK_URL, SECRET__WITH_NO_CALLBACK_URL, USERNAME, APP_NAME, "ACTIVE",
                " ");
        createOAuthApp(CLIENT_ID_WITH_INVALID_REGEX_CALLBACK_URL, SECRET, USERNAME, APP_NAME, "ACTIVE",
                INVALID_REGEX_CALLBACK_URL);
        createOAuthApp(CLIENT_ID_WITH_VALID_REGEX_CALLBACK_URL, SECRET, USERNAME, APP_NAME, "ACTIVE",
                VALID_REGEX_CALLBACK_URL);
    }

    @AfterClass
    public void tearDownAfterClass() throws Exception {

        identityDatabaseUtil.close();
        super.cleanData();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        oidcSessionIFrameServlet = new OIDCSessionIFrameServlet();
    }

    /**
     * This provides data to testDoGet(String clientId, String redirectUri, String expected)
     *
     * @return
     */
    @DataProvider(name = "provideDataForTestDoGet")
    public Object[][] provideDataForTestDoGet() {

        return new Object[][]{
                {CLIENT_ID_VALUE, "", "playground2"},
                {" ", "", "Invalid"},
                {INVALID_CLIENT_ID, "", "Invalid"},
                {CLIENT_ID_WITH_NO_CALLBACK_URL, "", "Invalid"},
                {CLIENT_ID_WITH_INVALID_REGEX_CALLBACK_URL, "", "Invalid"},
                {CLIENT_ID_WITH_INVALID_REGEX_CALLBACK_URL, CALLBACK_URL, "Invalid"},
                {CLIENT_ID_WITH_VALID_REGEX_CALLBACK_URL, CALLBACK_URL, "playground2"}
        };
    }

    @Test(dataProvider = "provideDataForTestDoGet")
    public void testDoGet(String clientId, String redirectUri, String expected) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtil =
                     mockStatic(OIDCSessionManagementUtil.class)) {
            oidcSessionIFrameServlet.init();

            when(request.getParameter("client_id")).thenReturn(clientId);
            lenient().when(request.getParameter(OIDCSessionConstants.OIDC_REDIRECT_URI_PARAM)).thenReturn(redirectUri);

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor())
                    .thenReturn(tokenPersistenceProcessor);
            lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString()))
                    .thenAnswer(invocation -> invocation.getArguments()[0]);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(TENANT_ID);
            identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(TENANT_ID);

            oidcSessionManagementUtil.when(() -> OIDCSessionManagementUtil.getOrigin((CALLBACK_URL)))
                    .thenReturn("http://localhost:8080/playground2");
            StringWriter outStringwriter = new StringWriter();
            PrintWriter out = new PrintWriter(outStringwriter);
            when(response.getWriter()).thenReturn(out);
            oidcSessionIFrameServlet.doGet(request, response);
            assertTrue(outStringwriter.toString().contains(expected), "Expected one is different from the actual one");
        }
    }
}

