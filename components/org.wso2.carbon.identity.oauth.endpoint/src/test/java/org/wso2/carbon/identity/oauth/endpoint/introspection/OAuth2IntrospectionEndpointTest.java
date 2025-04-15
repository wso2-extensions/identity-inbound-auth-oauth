/*
 * Copyright (c) 2019-2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.introspection;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;

@Listeners(MockitoTestNGListener.class)
public class OAuth2IntrospectionEndpointTest {

    @Mock
    OAuth2IntrospectionResponseDTO mockedIntrospectionResponse;

    @Mock
    PrivilegedCarbonContext mockedPrivilegedCarbonContext;

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    AuthenticatedUser authenticatedUser;

    @Mock
    OrganizationManager organizationManager;

    @Mock
    OAuth2TokenValidationService mockedTokenService;

    MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext;
    MockedStatic<LoggerUtils> loggerUtils;
    MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    private static final String CLAIM_SEPARATOR = ",";
    private static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String ROLE_CLAIM_URI = "http://wso2.org/claims/role";
    private static final String BEARER_TOKEN_TYPE_HINT = "bearer";
    private static final String TOKEN = "TOKEN";
    private static final String JWT_TOKEN_TYPE = "JWT";
    private static final String OPAQUE_TOKEN_TYPE = "Bearer";
    private static final String ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String ORG_NAME = "ABC builders";
    private static final String ORG_HANDLE = "abcbuilders";

    private OAuth2IntrospectionEndpoint oAuth2IntrospectionEndpoint;

    @BeforeClass
    public void setUp() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        oAuth2IntrospectionEndpoint = new OAuth2IntrospectionEndpoint();
    }

    @BeforeMethod
    public void init() throws Exception {

        loggerUtils = mockStatic(LoggerUtils.class);
        privilegedCarbonContext = mockStatic(PrivilegedCarbonContext.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);

        mockOAuthServerConfiguration(oAuthServerConfiguration);
        privilegedCarbonContext.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockedPrivilegedCarbonContext);
        when(mockedPrivilegedCarbonContext.getOSGiService(any())).
                thenReturn(mockedTokenService);
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
        privilegedCarbonContext.close();
        oAuthServerConfiguration.close();
    }

    @Test(dataProvider = "provideTokenInfo")
    public void testTokenTypeHint(String tokenTypeHint, String expectedTokenType) throws Exception {

        String[] claims = new String[]{USERNAME_CLAIM_URI, EMAIL_CLAIM_URI, ROLE_CLAIM_URI};
        String requiredClaims = String.join(CLAIM_SEPARATOR, claims);

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(anyInt()))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

            when(mockedTokenService.buildIntrospectionResponse(any(OAuth2TokenValidationRequestDTO.class)))
                    .thenReturn(mockedIntrospectionResponse);

            when(mockedIntrospectionResponse.getError()).thenReturn(null);
            mockedIntrospectionResponse.setTokenType(expectedTokenType);

            when(mockedIntrospectionResponse.getTokenType()).thenReturn(expectedTokenType);
            when(mockedIntrospectionResponse.getBindingType())
                    .thenReturn(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
            when(mockedIntrospectionResponse.getBindingReference())
                    .thenReturn("test_reference_value");
            when(mockedIntrospectionResponse.getCnfBindingValue())
                    .thenReturn("R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");

            Response response = oAuth2IntrospectionEndpoint.introspect(TOKEN, tokenTypeHint, requiredClaims);

            HashMap<String, Object> map =
                    new Gson().fromJson((String) response.getEntity(), new TypeToken<HashMap<String,
                            Object>>() {
                    }.getType());

            assertEquals(map.get("token_type"), expectedTokenType);
            assertEquals(map.get("binding_type"), OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
            assertEquals(map.get("binding_ref"), "test_reference_value");
            assertEquals(((Map<String, String>) map.get(OAuthConstants.CNF))
                    .get(OAuthConstants.X5T_S256), "R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");
        }
    }

    @Test
    public void testOrgDetailsInIntrospection() throws Exception {

        when(mockedTokenService.buildIntrospectionResponse(any(OAuth2TokenValidationRequestDTO.class)))
                .thenReturn(mockedIntrospectionResponse);
        when(mockedIntrospectionResponse.getError()).thenReturn(null);
        when(mockedIntrospectionResponse.getAuthorizedUser()).thenReturn(authenticatedUser);
        mockedIntrospectionResponse.setAuthorizedUser(authenticatedUser);

        when(authenticatedUser.getAccessingOrganization()).thenReturn(ORG_ID);
        authenticatedUser.setAccessingOrganization(ORG_ID);

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManager);
        when(organizationManager.getOrganizationNameById(ORG_ID)).thenReturn(ORG_NAME);
        when(organizationManager.resolveTenantDomain(ORG_ID)).thenReturn(ORG_HANDLE);

        Response response = oAuth2IntrospectionEndpoint.introspect(TOKEN, BEARER_TOKEN_TYPE_HINT, null);

        HashMap<String, Object> map = new Gson().fromJson((String) response.getEntity(),
                new TypeToken<HashMap<String, Object>>() { }.getType());

        assertEquals(ORG_ID, map.get(IntrospectionResponse.ORG_ID));
        assertEquals(ORG_NAME, map.get(IntrospectionResponse.ORG_NAME));
        assertEquals(ORG_HANDLE, map.get(IntrospectionResponse.ORG_HANDLE));
    }

    @Test
    public void testResolveTenantDomainThrowsException() throws Exception {

        when(mockedTokenService.buildIntrospectionResponse(any(OAuth2TokenValidationRequestDTO.class)))
                .thenReturn(mockedIntrospectionResponse);
        when(mockedIntrospectionResponse.getError()).thenReturn(null);
        when(mockedIntrospectionResponse.getAuthorizedUser()).thenReturn(authenticatedUser);
        mockedIntrospectionResponse.setAuthorizedUser(authenticatedUser);

        when(authenticatedUser.getAccessingOrganization()).thenReturn(ORG_ID);
        authenticatedUser.setAccessingOrganization(ORG_ID);

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManager);
        when(organizationManager.getOrganizationNameById(ORG_ID)).thenReturn(ORG_NAME);
        when(organizationManager.resolveTenantDomain(ORG_ID))
                .thenThrow(new OrganizationManagementException("Error resolving tenant domain"));

        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        Response response = oAuth2IntrospectionEndpoint.introspect(TOKEN, BEARER_TOKEN_TYPE_HINT, null);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
        HashMap<String, Object> map = new Gson().fromJson((String) response.getEntity(),
                new TypeToken<HashMap<String, Object>>() { }.getType());
        assertEquals("Error occurred while building the introspection response.", map.get("error"));
    }

    private void mockOAuthServerConfiguration(MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration)
            throws Exception {

        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        lenient().when(mockOAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        lenient().when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(
                invocation -> invocation.getArguments()[0]);
    }

    @DataProvider(name = "provideTokenInfo")
    public Object[][] provideTokenInfo() {

        return new Object[][]{
                {BEARER_TOKEN_TYPE_HINT, OPAQUE_TOKEN_TYPE},
                {BEARER_TOKEN_TYPE_HINT, JWT_TOKEN_TYPE}
        };
    }
}

