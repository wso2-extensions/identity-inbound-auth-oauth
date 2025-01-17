/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.rar.dao.AuthorizationDetailsDAO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;
import org.wso2.carbon.identity.oauth2.rar.model.ValidationResult;
import org.wso2.carbon.identity.oauth2.rar.utils.AuthorizationDetailsBaseTest;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.SQLException;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.oauth2.TestConstants.ACESS_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.CLIENT_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_APP_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_CONSENT_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_TYPE;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_USER_ID;

/**
 * Test class for {@link AuthorizationDetailsService}.
 */
@WithCarbonHome
public class AuthorizationDetailsServiceTest extends AuthorizationDetailsBaseTest {

    private AuthorizationDetailsDAO authorizationDetailsDAOMock;
    private MockedStatic<OAuth2Util> oAuth2UtilMock;

    private AuthorizationDetailsService uut;

    @BeforeClass
    public void setUp() throws SQLException {

        this.oAuth2UtilMock = Mockito.mockStatic(OAuth2Util.class);
        this.oAuth2UtilMock.when(() -> OAuth2Util.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationResourceId(TEST_APP_ID);
        this.oAuth2UtilMock.when(() -> OAuth2Util.getServiceProvider(CLIENT_ID)).thenReturn(serviceProvider);
    }

    @AfterClass
    public void tearDown() {

        if (this.oAuth2UtilMock != null && !this.oAuth2UtilMock.isClosed()) {
            this.oAuth2UtilMock.close();
        }
    }

    @BeforeMethod()
    public void setUpMethod()
            throws SQLException, IdentityOAuth2ServerException, AuthorizationDetailsProcessingException {

        this.authorizationDetailsDAOMock = Mockito.mock(AuthorizationDetailsDAO.class);
        when(this.authorizationDetailsDAOMock.getConsentIdByUserIdAndAppId(TEST_USER_ID, TEST_APP_ID, TENANT_ID))
                .thenReturn(TEST_CONSENT_ID);

        when(this.authorizationDetailsDAOMock.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TENANT_ID))
                .thenReturn(Collections.singleton(new AuthorizationDetailsConsentDTO(TEST_CONSENT_ID,
                        this.authorizationDetail, true, TENANT_ID)));

        when(this.authorizationDetailsDAOMock.getAccessTokenAuthorizationDetails(ACESS_TOKEN_ID, TENANT_ID))
                .thenReturn(Collections.singleton(new AuthorizationDetailsTokenDTO(ACESS_TOKEN_ID,
                        this.authorizationDetail, TENANT_ID)));

        AuthorizationDetailsProcessor processor = Mockito.mock(AuthorizationDetailsProcessor.class);
        when(processor.isEqualOrSubset(any(AuthorizationDetail.class), any(AuthorizationDetails.class)))
                .thenReturn(true);
        when(processor.enrich(any(AuthorizationDetailsContext.class))).thenReturn(this.authorizationDetail);
        when(processor.getType()).thenReturn(TEST_TYPE);
        when(processor.validate(any(AuthorizationDetailsContext.class))).thenReturn(ValidationResult.valid());

        this.processorFactoryMock = Mockito.mock(AuthorizationDetailsProcessorFactory.class);
        when(this.processorFactoryMock.getAuthorizationDetailsProcessorByType(TEST_TYPE))
                .thenReturn(Optional.of(processor));

        uut = new AuthorizationDetailsService(this.processorFactoryMock, this.authorizationDetailsDAOMock);
    }

    @BeforeMethod(onlyForGroups = {"error-flow-tests"}, dependsOnMethods = {"setUpMethod"})
    public void setUpErrorMethod() throws SQLException {

        when(this.authorizationDetailsDAOMock.addUserConsentedAuthorizationDetails(anySet()))
                .thenThrow(SQLException.class);
        when(this.authorizationDetailsDAOMock.deleteUserConsentedAuthorizationDetails(anyString(), anyInt()))
                .thenThrow(SQLException.class);
        when(this.authorizationDetailsDAOMock.getUserConsentedAuthorizationDetails(anyString(), anyInt()))
                .thenThrow(SQLException.class);
        when(this.authorizationDetailsDAOMock.getAccessTokenAuthorizationDetails(anyString(), anyInt()))
                .thenThrow(SQLException.class);
        when(this.authorizationDetailsDAOMock.addAccessTokenAuthorizationDetails(anySet()))
                .thenThrow(SQLException.class);
        when(this.authorizationDetailsDAOMock.deleteAccessTokenAuthorizationDetails(anyString(), anyInt()))
                .thenThrow(SQLException.class);

        uut = new AuthorizationDetailsService(this.processorFactoryMock, this.authorizationDetailsDAOMock);
    }

    @Test
    public void shouldNotAddUserConsentedAuthorizationDetails_ifNotRichAuthorizationRequest()
            throws OAuthSystemException, SQLException {

        uut.storeOrUpdateUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID,
                new OAuth2Parameters(), authorizationDetails);

        verify(authorizationDetailsDAOMock, times(0)).addUserConsentedAuthorizationDetails(anySet());
    }

    @Test
    public void shouldNotAddUserConsentedAuthorizationDetails_whenConsentIsNotFound()
            throws OAuthSystemException, SQLException {

        final OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setAuthorizationDetails(authorizationDetails);

        uut.storeOrUpdateUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID,
                oAuth2Parameters, authorizationDetails);

        verify(authorizationDetailsDAOMock, times(0)).addUserConsentedAuthorizationDetails(anySet());
    }

    @Test
    public void shouldAddUserConsentedAuthorizationDetails_ifRichAuthorizationRequest()
            throws OAuthSystemException, SQLException {

        when(this.authorizationDetailsDAOMock.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TENANT_ID))
                .thenReturn(Collections.emptySet());

        uut.storeOrUpdateUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID,
                oAuth2Parameters, authorizationDetails);

        verify(authorizationDetailsDAOMock, times(1)).addUserConsentedAuthorizationDetails(anySet());
    }

    @Test
    public void shouldNotDeleteUserConsentedAuthorizationDetails_ifNotRichAuthorizationRequest()
            throws OAuthSystemException, SQLException {

        uut.deleteUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID, new OAuth2Parameters());

        verify(authorizationDetailsDAOMock, times(0)).deleteUserConsentedAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldNotDeleteUserConsentedAuthorizationDetails_whenConsentIsNotFound()
            throws OAuthSystemException, SQLException {

        final OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setAuthorizationDetails(authorizationDetails);

        uut.deleteUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID, oAuth2Parameters);

        verify(authorizationDetailsDAOMock, times(0)).deleteUserConsentedAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldDeleteUserConsentedAuthorizationDetails_ifRichAuthorizationRequest()
            throws OAuthSystemException, SQLException {

        uut.deleteUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID, oAuth2Parameters);

        verify(authorizationDetailsDAOMock, times(1)).deleteUserConsentedAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldReplaceUserConsentedAuthorizationDetails_ifRichAuthorizationRequest()
            throws OAuthSystemException, SQLException {

        when(this.authorizationDetailsDAOMock.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TENANT_ID))
                .thenReturn(Collections.emptySet());
        uut.replaceUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID,
                oAuth2Parameters, authorizationDetails);

        verify(authorizationDetailsDAOMock, times(1))
                .deleteUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TENANT_ID);
        verify(authorizationDetailsDAOMock, times(1)).addUserConsentedAuthorizationDetails(anySet());
    }

    @Test
    public void shouldReturnTrue_ifNotRichAuthorizationRequest() throws IdentityOAuth2Exception {

        assertTrue(uut.isUserAlreadyConsentedForAuthorizationDetails(authenticatedUser, new OAuth2Parameters()));
    }

    @Test
    public void shouldReturnFalse_ifAuthorizationDetailsAlreadyConsented() throws IdentityOAuth2Exception {

        assertFalse(uut.isUserAlreadyConsentedForAuthorizationDetails(authenticatedUser, oAuth2Parameters));
    }

    @Test
    public void shouldReturnNull_whenConsentIsInvalid() throws IdentityOAuth2Exception {

        AuthenticatedUser invalidUser = new AuthenticatedUser();
        invalidUser.setUserId("invalid-user-id");

        assertNull(uut.getUserConsentedAuthorizationDetails(invalidUser, CLIENT_ID, TENANT_ID));
    }

    @Test
    public void shouldReturnUserConsentedAuthorizationDetails_whenConsentIsValid() throws IdentityOAuth2Exception {

        final AuthorizationDetails authorizationDetails =
                uut.getUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID, TENANT_ID);

        assertEquals(1, authorizationDetails.getDetails().size());
        authorizationDetails.stream().forEach(detail -> assertEquals(TEST_TYPE, detail.getType()));

        final AuthorizationDetails authorizationDetails1 =
                uut.getUserConsentedAuthorizationDetails(authenticatedUser, oAuth2Parameters);

        assertEquals(1, authorizationDetails1.getDetails().size());
        authorizationDetails1.stream().forEach(detail -> assertEquals(TEST_TYPE, detail.getType()));
    }

    @Test
    public void shouldReturnEmptyAuthorizationDetails_whenAccessTokenIsNotFound() throws IdentityOAuth2Exception {

        assertTrue(uut.getAccessTokenAuthorizationDetails("invalid-access-token", TENANT_ID)
                .getDetails().isEmpty());
    }

    @Test
    public void shouldReturnAccessTokenAuthorizationDetails_whenTokenIsValid() throws IdentityOAuth2Exception {

        AuthorizationDetails authorizationDetails = uut.getAccessTokenAuthorizationDetails(ACESS_TOKEN_ID, TENANT_ID);

        assertEquals(1, authorizationDetails.getDetails().size());
        authorizationDetails.stream().forEach(ad -> assertEquals(TEST_TYPE, ad.getType()));
    }

    @Test
    public void shouldNotAddAccessTokenAuthorizationDetails_ifNotRichAuthorizationRequest()
            throws SQLException, IdentityOAuth2Exception {

        uut.storeAccessTokenAuthorizationDetails(accessTokenDO, new OAuthAuthzReqMessageContext(null));

        verify(authorizationDetailsDAOMock, times(0)).addAccessTokenAuthorizationDetails(anySet());
    }

    @Test
    public void shouldAddAccessTokenAuthorizationDetails_ifRichAuthorizationRequest()
            throws SQLException, IdentityOAuth2Exception {

        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext = new OAuthAuthzReqMessageContext(null);
        oAuthAuthzReqMessageContext.setApprovedAuthorizationDetails(authorizationDetails);

        uut.storeAccessTokenAuthorizationDetails(accessTokenDO, oAuthAuthzReqMessageContext);

        verify(authorizationDetailsDAOMock, times(1)).addAccessTokenAuthorizationDetails(anySet());
    }

    @Test
    public void shouldNotReplaceAccessTokenAuthorizationDetails_ifNotRichAuthorizationRequest()
            throws SQLException, IdentityOAuth2Exception {

        uut.storeOrReplaceAccessTokenAuthorizationDetails(accessTokenDO, accessTokenDO,
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO()));

        verify(authorizationDetailsDAOMock, times(0)).addAccessTokenAuthorizationDetails(anySet());
        verify(authorizationDetailsDAOMock, times(0)).deleteAccessTokenAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldNotDeleteAccessTokenAuthorizationDetails_whenOldAccessTokenIsMissing()
            throws SQLException, IdentityOAuth2Exception {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        messageContext.setAuthorizationDetails(authorizationDetails);

        uut.storeOrReplaceAccessTokenAuthorizationDetails(accessTokenDO, null, messageContext);

        verify(authorizationDetailsDAOMock, times(1)).addAccessTokenAuthorizationDetails(anySet());
        verify(authorizationDetailsDAOMock, times(0)).deleteAccessTokenAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldReplaceAccessTokenAuthorizationDetails_whenOldAccessTokenIsPresent()
            throws SQLException, IdentityOAuth2Exception {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        messageContext.setAuthorizationDetails(authorizationDetails);

        uut.storeOrReplaceAccessTokenAuthorizationDetails(accessTokenDO, accessTokenDO, messageContext);

        verify(authorizationDetailsDAOMock, times(1)).addAccessTokenAuthorizationDetails(anySet());
        verify(authorizationDetailsDAOMock, times(1)).deleteAccessTokenAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldReplaceAccessTokenAuthorizationDetails_ifRichAuthorizationRequest()
            throws SQLException, IdentityOAuth2Exception {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        messageContext.setAuthorizationDetails(authorizationDetails);

        final String oldAccessTokenId = "b8488717-267c-4f45-b039-f31a8efe7cac";
        uut.replaceAccessTokenAuthorizationDetails(oldAccessTokenId, accessTokenDO, messageContext);

        verify(authorizationDetailsDAOMock, times(1))
                .deleteAccessTokenAuthorizationDetails(oldAccessTokenId, TENANT_ID);
        verify(authorizationDetailsDAOMock, times(1)).addAccessTokenAuthorizationDetails(anySet());
    }

    @Test
    public void shouldDeleteAccessTokenAuthorizationDetails_ifAccessTokenIsValid()
            throws SQLException, IdentityOAuth2Exception {

        uut.deleteAccessTokenAuthorizationDetails(ACESS_TOKEN_ID, TENANT_ID);

        verify(authorizationDetailsDAOMock, times(1)).deleteAccessTokenAuthorizationDetails(anyString(), anyInt());
    }

    @Test
    public void shouldReturnEmptyAuthorizationDetails_ifNotRichAuthorizationRequest() throws IdentityOAuth2Exception {

        assertTrue(uut.getConsentRequiredAuthorizationDetails(authenticatedUser, new OAuth2Parameters())
                .getDetails().isEmpty());
    }

    @Test
    public void shouldReturnEmptyAuthorizationDetails_ifProcessorIsMissing() throws IdentityOAuth2Exception {

        assertTrue(uut.getConsentRequiredAuthorizationDetails(authenticatedUser, new OAuth2Parameters())
                .getDetails().isEmpty());
    }

    @Test
    public void shouldReturnConsentRequiredAuthorizationDetails() throws IdentityOAuth2Exception {

        final String testTypeV2 = "test_type_v2";
        AuthorizationDetail authorizationDetail = new AuthorizationDetail();
        authorizationDetail.setType(testTypeV2);

        Set<AuthorizationDetail> detailSet =
                Stream.of(authorizationDetails.getDetails(), Collections.singleton(authorizationDetail))
                        .flatMap(Set::stream)
                        .collect(toSet());

        oAuth2Parameters.setAuthorizationDetails(new AuthorizationDetails(detailSet));

        uut.getConsentRequiredAuthorizationDetails(authenticatedUser, oAuth2Parameters)
                .stream()
                .forEach(ad -> assertEquals(testTypeV2, ad.getType()));
    }

    @Test(groups = {"error-flow-tests"}, expectedExceptions = {OAuthSystemException.class})
    public void shouldThrowOAuthSystemException_onUserConsentAuthorizationDetailsInsertionFailure()
            throws OAuthSystemException {

        uut.storeOrUpdateUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID,
                oAuth2Parameters, authorizationDetails);
    }

    @Test(groups = {"error-flow-tests"}, expectedExceptions = {OAuthSystemException.class})
    public void shouldThrowOAuthSystemException_onUserConsentAuthorizationDetailsDeletionFailure()
            throws OAuthSystemException {

        uut.deleteUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID, oAuth2Parameters);
    }

    @Test(groups = {"error-flow-tests"}, expectedExceptions = {IdentityOAuth2Exception.class})
    public void shouldThrowIdentityOAuth2Exception_onUserConsentAuthorizationDetailsRetrievalFailure()
            throws IdentityOAuth2Exception {

        uut.getUserConsentedAuthorizationDetails(authenticatedUser, CLIENT_ID, TENANT_ID);
    }

    @Test(groups = {"error-flow-tests"}, expectedExceptions = {IdentityOAuth2Exception.class})
    public void shouldThrowIdentityOAuth2Exception_onAccessTokenAuthorizationDetailsRetrievalFailure()
            throws IdentityOAuth2Exception {

        uut.getAccessTokenAuthorizationDetails(ACESS_TOKEN_ID, TENANT_ID);
    }

    @Test(groups = {"error-flow-tests"}, expectedExceptions = {IdentityOAuth2Exception.class})
    public void shouldThrowIdentityOAuth2Exception_onAccessTokenAuthorizationDetailsInsertionFailure()
            throws IdentityOAuth2Exception {

        uut.storeAccessTokenAuthorizationDetails(accessTokenDO, authorizationDetails);
    }

    @Test(groups = {"error-flow-tests"}, expectedExceptions = {IdentityOAuth2Exception.class})
    public void shouldThrowIdentityOAuth2Exception_onAccessTokenAuthorizationDetailsDeletionFailure()
            throws IdentityOAuth2Exception {

        uut.deleteAccessTokenAuthorizationDetails(ACESS_TOKEN_ID, TENANT_ID);
    }
}
