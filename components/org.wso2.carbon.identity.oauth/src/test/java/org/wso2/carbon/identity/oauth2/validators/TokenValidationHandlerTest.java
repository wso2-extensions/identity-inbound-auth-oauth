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

package org.wso2.carbon.identity.oauth2.validators;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.sql.Timestamp;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({OAuthServerConfiguration.class, TokenValidationHandler.class, UserCoreUtil.class,
        AccessTokenDO.class, OAuth2Util.class})
public class TokenValidationHandlerTest  extends PowerMockTestCase {

    AccessTokenDO accessTokenDO;

    @Mock
    private TokenValidationHandler mockTokenValidationHandler;

    @Mock
    private OAuth2TokenValidationRequestDTO mockOAuth2TokenValidationRequestDTO;

    @Mock
    private OAuth2TokenValidationRequestDTO.OAuth2AccessToken mockAuth2AccessToken;

    @Mock
    private OAuth2TokenValidator mockOAuth2TokenValidator;

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Test
    public void testGetInstance() throws Exception {
        whenNew(TokenValidationHandler.class).withNoArguments().thenReturn(mockTokenValidationHandler);
        assertNotNull(TokenValidationHandler.getInstance());
    }

    @Test
    public void testAddTokenValidator() throws Exception {
        mockOAuthServerConfiguration();
        TokenValidationHandler.getInstance().addTokenValidator("type", mockOAuth2TokenValidator);
    }

    @Test
    public void testValidate() throws Exception {
        mockOAuthServerConfiguration();
        TokenValidationHandler.getInstance().validate(new OAuth2TokenValidationRequestDTO());
        assertNotNull(TokenValidationHandler.getInstance().validate(new OAuth2TokenValidationRequestDTO()
        ), "Error while calling validate()");
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValid() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        when(mockOAuth2TokenValidator.validateScope(any(OAuth2TokenValidationMessageContext.class))).thenReturn(true);
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        accessTokenDO.setAuthzUser(authenticatedUser);
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn
                ("tenant@tenantdomain@carbon.super");
        assertNotNull(TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO), "Error while calling findOAuthConsumerIfTokenIsValid()");
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidAccessTokenNull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid(),
                "IllegalArgumentException due to access token being null");
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidAccessTokenIdentifierNull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        when(mockOAuth2TokenValidationRequestDTO.getAccessToken()).thenReturn(mockAuth2AccessToken);
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid(),
                "IllegalArgumentException due to access token identifier being null");
    }

    @Test(priority = -1)
    public void testFindOAuthConsumerIfTokenIsValidOAuth2TokenValidatorNull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        when(mockOAuth2TokenValidationRequestDTO.getAccessToken()).thenReturn(mockAuth2AccessToken);
        when(mockAuth2AccessToken.getIdentifier()).thenReturn("identifier");
        when(mockAuth2AccessToken.getTokenType()).thenReturn("type");
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid(),
                "IllegalArgumentException due to token validator being null");
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidAccessTokenDONull() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        TokenValidationHandler classUnderTest = spy(TokenValidationHandler.getInstance());
        doThrow(new IllegalArgumentException()).when(classUnderTest, "findAccessToken", anyString());
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        classUnderTest.findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidHasAccessTokenExpiredTrue() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        findAccessToken();
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidValidateAccessDelegationFalse() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(false);
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidValidateScopeFalse() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValidValidateAccessTokenFalse() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        when(mockOAuth2TokenValidator.validateScope(any(OAuth2TokenValidationMessageContext.class))).thenReturn(true);
        TokenValidationHandler.getInstance().findOAuthConsumerIfTokenIsValid
                (mockOAuth2TokenValidationRequestDTO);
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testBuildIntrospectionResponse() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        accessTokenDO.setIssuedTime(timestamp);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        accessTokenDO.setAuthzUser(authenticatedUser);
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn
                ("tenant@tenantdomain@carbon.super");
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        when(mockOAuth2TokenValidator.validateScope(any(OAuth2TokenValidationMessageContext.class))).thenReturn(true);
        assertNotNull(TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO), "Error while calling buildIntrospectionResponse()");
    }

    @Test
    public void testBuildIntrospectionResponseAccessTokenNull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid(),
                "IllegalArgumentException due to access token being null");
    }

    @Test
    public void testBuildIntrospectionResponseAccessTokenIdentifierNull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        when(mockOAuth2TokenValidationRequestDTO.getAccessToken()).thenReturn(mockAuth2AccessToken);
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid(),
                "IllegalArgumentException due to access token identifier being null");
    }

    @Test(priority = -2)
    public void testBuildIntrospectionResponseOAuth2TokenValidatorNull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        when(mockOAuth2TokenValidationRequestDTO.getAccessToken()).thenReturn(mockAuth2AccessToken);
        when(mockAuth2AccessToken.getIdentifier()).thenReturn("identifier");
        when(mockAuth2AccessToken.getTokenType()).thenReturn("type");
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid(),
                "IllegalArgumentException due to token validator being null");
    }

    @Test
    public void testBuildIntrospectionResponseValidateAccessTokenFalse() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        findAccessTokenValidator();
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(false);
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testBuildIntrospectionResponseAccessTokenDONull() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        findAccessTokenValidator();
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        TokenValidationHandler classUnderTest = spy(TokenValidationHandler.getInstance());
        doThrow(new IllegalArgumentException()).when(classUnderTest, "findAccessToken", anyString());
        classUnderTest.buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testBuildIntrospectionResponseHasAccessTokenExpiredTrue() throws Exception {
        mockOAuthServerConfiguration();
        findAccessTokenValidator();
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        findAccessToken();
        accessTokenDO.setValidityPeriod(1);
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertNotNull(TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO));
    }

    @Test
    public void testBuildIntrospectionResponseValidateAccessDelegation() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        findAccessTokenValidator();
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        accessTokenDO.setIssuedTime(timestamp);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        accessTokenDO.setAuthzUser(authenticatedUser);
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn
                ("tenant@tenantdomain@carbon.super");
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(false);
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    @Test
    public void testBuildIntrospectionResponseValidateScope() throws Exception {
        mockOAuthServerConfiguration();
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        findAccessTokenValidator();
        when(mockOAuth2TokenValidator.validateAccessToken(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        findAccessToken();
        accessTokenDO.setValidityPeriod(-1);
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        accessTokenDO.setIssuedTime(timestamp);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        accessTokenDO.setAuthzUser(authenticatedUser);
        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn
                ("tenant@tenantdomain@carbon.super");
        when(mockOAuth2TokenValidator.validateAccessDelegation(any(OAuth2TokenValidationMessageContext.class))).
                thenReturn(true);
        when(mockOAuth2TokenValidator.validateScope(any(OAuth2TokenValidationMessageContext.class))).thenReturn(false);
        TokenValidationHandler.getInstance().buildIntrospectionResponse
                (mockOAuth2TokenValidationRequestDTO);
        assertFalse(oAuth2TokenValidationResponseDTO.isValid());
    }

    private void mockOAuthServerConfiguration() {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
    }

    private void findAccessTokenValidator() throws Exception {
        when(mockOAuth2TokenValidationRequestDTO.getAccessToken()).thenReturn(mockAuth2AccessToken);
        when(mockAuth2AccessToken.getIdentifier()).thenReturn("identifier");
        when(mockAuth2AccessToken.getTokenType()).thenReturn("type");
        TokenValidationHandler.getInstance().addTokenValidator("type", mockOAuth2TokenValidator);
    }

    private void findAccessToken() throws Exception {
        mockStatic(OAuth2Util.class);
        accessTokenDO = new AccessTokenDO();
        when(OAuth2Util.getAccessTokenDOfromTokenIdentifier(anyString())).thenReturn(accessTokenDO);
    }

}


