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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.user;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoEndpointConfig;
import org.wso2.carbon.identity.oauth.user.UserInfoAccessTokenValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoRequestValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Method;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * This class does unit test coverage for OpenIDConnectUserEndpoint class
 */
@PrepareForTest({UserInfoEndpointConfig.class, OAuth2Util.class, OAuthServerConfiguration.class, OAuthASResponse.class})
public class OpenIDConnectUserEndpointTest extends PowerMockIdentityBaseTest {

    @Mock
    OAuthServerConfiguration oauthServerConfigurationMock;

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    UserInfoRequestValidator requestValidator;

    @Mock
    UserInfoEndpointConfig userInfoEndpointConfig;

    @Mock
    UserInfoAccessTokenValidator tokenValidator;

    @Mock
    OAuth2TokenValidationResponseDTO tokenResponse;

    @Mock
    OAuthAppDO appDO;

    @Mock
    UserInfoResponseBuilder userInfoResponseBuilder;

    private OpenIDConnectUserEndpoint openIDConnectUserEndpoint;

    @BeforeTest
    public void setUp() throws Exception {
        openIDConnectUserEndpoint = new OpenIDConnectUserEndpoint();
    }

    @DataProvider(name = "provideDataForGetUserClaims")
    public Object[][] provideDataGetUserClaims() {
        String authResponse = "{\"token_type\":\"Bearer\",\"expires_in\":2061,\"access_token\":\"ca19a540f544777860e44e75f605d927\"}";
        return new Object[][]{
                {authResponse, null, OAuthError.ResourceResponse.INSUFFICIENT_SCOPE, HttpServletResponse.SC_FORBIDDEN},
                {"", null, OAuthError.ResourceResponse.INSUFFICIENT_SCOPE, HttpServletResponse.SC_FORBIDDEN},
                {"", null, OAuthError.ResourceResponse.INVALID_TOKEN, HttpServletResponse.SC_UNAUTHORIZED},
                {"", null, OAuthError.ResourceResponse.INVALID_REQUEST, HttpServletResponse.SC_BAD_REQUEST},
                {"", null, null, HttpServletResponse.SC_BAD_REQUEST},
        };
    }

    /**
     * Here handleError & setServiceProviderTenantId private methods also covered by this method.
     * @param authResponse
     * @param errorMessage
     * @param errorCode
     * @param expectedStatus
     * @throws Exception
     */
    @Test(dataProvider = "provideDataForGetUserClaims")
    public void testGetUserClaims(String authResponse, String errorMessage, String errorCode,
                                  int expectedStatus) throws Exception {

        String clientID = "rgfKVdnMQnJlSSr_pKFTxj3apiwYa";

        UserInfoEndpointException ex = new UserInfoEndpointException(errorCode, errorMessage);
        Class<?> clazz = OpenIDConnectUserEndpoint.class;
        Object setHandleError = clazz.newInstance();
        Method handleError = setHandleError.getClass().
                getDeclaredMethod("handleError", UserInfoEndpointException.class);
        handleError.setAccessible(true);
        Response errorResponse = (Response)
                handleError.invoke(setHandleError, ex);

        assertEquals(errorResponse.getStatus(), expectedStatus,"Error response values are not same");

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(3600L);
        when(userInfoResponseBuilder.getResponseString(tokenResponse)).thenReturn(authResponse);
        when(userInfoEndpointConfig.getUserInfoResponseBuilder()).thenReturn(userInfoResponseBuilder);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantDomainOfOauthApp(appDO)).thenReturn("test");
        when(OAuth2Util.getTenantId(anyString())).thenReturn(-1234);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(appDO);
        when(OAuth2Util.getClientIdForAccessToken(anyString())).thenReturn(clientID);

        when(tokenValidator.validateToken(anyString())).thenReturn(tokenResponse);
        when(userInfoEndpointConfig.getUserInfoAccessTokenValidator()).thenReturn(tokenValidator);
        when(userInfoEndpointConfig.getUserInfoRequestValidator()).thenReturn(requestValidator);
        mockStatic(UserInfoEndpointConfig.class);
        when(UserInfoEndpointConfig.getInstance()).thenReturn(userInfoEndpointConfig);

        Response response = openIDConnectUserEndpoint.getUserClaims(httpServletRequest);
        assertNotNull(response.getStatus());
        assertEquals(response.getStatus(), HttpServletResponse.SC_OK);

        MultivaluedMap<String, Object> metadata = response.getMetadata();
        String metadataValue1 = metadata.get(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL).toString();
        String metadataValue2 = metadata.get(OAuthConstants.HTTP_RESP_HEADER_PRAGMA).toString();
        assertEquals(metadataValue1, "[no-store]", "Values are not equal");
        assertEquals(metadataValue2, "[no-cache]", "Values are not equal");
        assertNotNull(response);
        assertEquals(response.getEntity().toString(), authResponse, "Response values are not same");

        openIDConnectUserEndpoint.getUserClaimsPost(httpServletRequest);
    }

}
