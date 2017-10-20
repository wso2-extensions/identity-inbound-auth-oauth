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
package org.wso2.carbon.identity.oauth2;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

/**
 * This class tests the OAuth2Service class.
 */
@PrepareForTest({OAuth2Util.class, AuthorizationHandlerManager.class, OAuth2Service.class, IdentityTenantUtil.class,
        OAuthServerConfiguration.class})
public class OAuth2ServiceTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;

    @Mock
    private AuthorizationHandlerManager authorizationHandlerManager;

    @Mock
    OAuth2AuthorizeRespDTO mockedOAuth2AuthorizeRespDTO;

    @Mock
    OAuthAppDAO oAuthAppDAO;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    AuthenticatedUser authenticatedUser;

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    OAuth2Service oAuth2Service;
    static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";

    @BeforeMethod
    public void setUp() throws Exception {
        oAuth2Service = new OAuth2Service();
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    /**
     * DataProvider: grantType, callbackUrl, tenantDomain, callbackURI
     */
    @DataProvider(name = "ValidateClientInfoDataProvider")
    public Object[][] validateClientDataProvider() {
        return new Object[][]{
                {null, null, null, null},
                {"dummyGrantType", "dummyCallBackUrl", "carbon.super", null},
                {"dummyGrantType", "dummyCallBackUrl", "carbon.super", "dummyCallBackURI"},
                {"dummyGrantType", "regexp=dummyCallBackUrl", "carbon.super", "dummyCallBackURI"},
                {"dummyGrantType", "regexp=dummyCallBackUrl", "carbon.super", "dummyCallBackUrl"},
                {"dummyGrantType", "dummyCallBackUrl", "carbon.super", "dummyCallBackUrl"}
        };
    }

    @Test
    public void testAuthorize() throws Exception {
        mockStatic(AuthorizationHandlerManager.class);
        when(AuthorizationHandlerManager.getInstance()).thenReturn(authorizationHandlerManager);
        when(authorizationHandlerManager.handleAuthorization((OAuth2AuthorizeReqDTO) anyObject())).
                thenReturn(mockedOAuth2AuthorizeRespDTO);
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(300L);
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
        assertNotNull(oAuth2AuthorizeRespDTO);
    }

    @Test
    public void testAuthorizeWithException() throws IdentityOAuth2Exception {
        String callbackUrl = "dummyCallBackUrl";
        mockStatic(AuthorizationHandlerManager.class);
        when(oAuth2AuthorizeReqDTO.getCallbackUrl()).thenReturn(callbackUrl);
        when(AuthorizationHandlerManager.getInstance()).thenThrow(new IdentityOAuth2Exception
                ("Error while creating AuthorizationHandlerManager instance"));
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO = oAuth2Service.authorize(oAuth2AuthorizeReqDTO);
        assertNotNull(oAuth2AuthorizeRespDTO);
    }

    @Test(dataProvider = "ValidateClientInfoDataProvider")
    public void testValidateClientInfo(String grantType, String callbackUrl, String tenantDomain, String callbackURI)
            throws Exception {
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenReturn(oAuthAppDO);
        when(oAuthAppDO.getGrantTypes()).thenReturn(grantType);
        when(oAuthAppDO.getCallbackUrl()).thenReturn(callbackUrl);
        when(oAuthAppDO.getUser()).thenReturn(authenticatedUser);
        when(authenticatedUser.getTenantDomain()).thenReturn(tenantDomain);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(1);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(clientId, callbackURI);
        assertNotNull(oAuth2ClientValidationResponseDTO);
    }

    @Test
    public void testInvalidOAuthClientException() throws Exception {
        String callbackUrI = "dummyCallBackURI";
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenThrow
                (new InvalidOAuthClientException("Cannot find an application associated with the given consumer key"));
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(clientId, callbackUrI);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), "invalid_client");
        assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
    }

    @Test
    public void testIdentityOAuth2Exception() throws Exception {
        String callbackUrI = "dummyCallBackURI";
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(clientId)).thenThrow
                (new IdentityOAuth2Exception("Error while retrieving the app information"));
        OAuth2ClientValidationResponseDTO oAuth2ClientValidationResponseDTO = oAuth2Service.
                validateClientInfo(clientId, callbackUrI);
        assertNotNull(oAuth2ClientValidationResponseDTO);
        assertEquals(oAuth2ClientValidationResponseDTO.getErrorCode(), "server_error");
        assertFalse(oAuth2ClientValidationResponseDTO.isValidClient());
    }

}
