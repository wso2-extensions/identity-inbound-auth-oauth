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

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * This class contains tests for UserInfoJSONResponseBuilder.
 */
@Listeners(MockitoTestNGListener.class)
public class UserInfoJSONResponseBuilderTest extends UserInfoResponseBaseTest {

    private UserInfoJSONResponseBuilder userInfoJSONResponseBuilder;

    Connection con = null;

    @Mock
    private RequestObjectService requestObjectService;

    @BeforeClass
    public void setUpTest() throws Exception {

        OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(new ScopeClaimMappingDAOImpl());
        OAuth2ServiceComponentHolder.getInstance().setTokenProvider(new DefaultTokenProvider());
        userInfoJSONResponseBuilder = new UserInfoJSONResponseBuilder();
        TestUtils.initiateH2Base();
        con = TestUtils.getConnection();
    }

    private void setUpRequestObjectService() throws RequestObjectException {

        List<RequestedClaim> requestedClaims = Collections.emptyList();
        lenient().when(requestObjectService.getRequestedClaimsForIDToken(anyString())).
                thenReturn(requestedClaims);
        lenient().when(requestObjectService.getRequestedClaimsForUserInfo(anyString())).
                thenReturn(requestedClaims);
        OpenIDConnectServiceComponentHolder.getInstance()
                .getOpenIDConnectClaimFilters()
                .add(new OpenIDConnectClaimFilterImpl());
        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
    }

    private void mockDataSource(MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager) throws SQLException {

        DataSource dataSource = mock(DataSource.class);
        JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);
        lenient().when(dataSource.getConnection()).thenReturn(con);
        jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
        lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
    }

    @DataProvider(name = "responseStringInputs")
    public Object[][] responseStringInputs() {

        return getOidcScopeFilterTestData();
    }

    @Test(dataProvider = "responseStringInputs")
    public void testGetResponseString(Map<String, Object> inputClaims,
                                      Map<String, List<String>> oidcScopeMap,
                                      boolean getClaimsFromCache,
                                      String[] requestedScopes,
                                      Map<String, Object> expectedClaims) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                         mockStatic(AuthorizationGrantCache.class);
                 MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {
                setUpRequestObjectService();
                prepareForResponseClaimTest(inputClaims, oidcScopeMap, getClaimsFromCache,
                        authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util, identityTenantUtil,
                        userInfoEndpointConfig);
                mockDataSource(jdbcPersistenceManager);
                mockObjectsRelatedToTokenValidation(oAuth2Util);

                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn(AUTHORIZED_USER_ID);

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
                authenticatedUser.setTenantDomain(TENANT_DOT_COM);
                authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
                authenticatedUser.setUserId(AUTHORIZED_USER_ID);
                authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
                mockAccessTokenDOInOAuth2Util(authenticatedUser, oAuth2Util);

                String responseString =
                        userInfoJSONResponseBuilder.getResponseString(
                                getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED, requestedScopes));

                Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
                assertNotNull(claimsInResponse);
                assertFalse(claimsInResponse.isEmpty());
                assertNotNull(claimsInResponse.get(sub));

                for (Map.Entry<String, Object> expectClaimEntry : expectedClaims.entrySet()) {
                    assertTrue(claimsInResponse.containsKey(expectClaimEntry.getKey()));
                    assertNotNull(claimsInResponse.get(expectClaimEntry.getKey()));
                    assertEquals(expectClaimEntry.getValue(), claimsInResponse.get(expectClaimEntry.getKey()));
                }

            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    @Test
    public void testEssentialClaims() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);) {

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);

            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {

                final Map<String, Object> inputClaims = new HashMap<>();
                inputClaims.put(firstName, FIRST_NAME_VALUE);
                inputClaims.put(lastName, LAST_NAME_VALUE);
                inputClaims.put(email, EMAIL_VALUE);

                final Map<String, List<String>> oidcScopeMap = new HashMap<>();
                oidcScopeMap.put(OIDC_SCOPE, Collections.singletonList(firstName));

                prepareForResponseClaimTest(inputClaims, oidcScopeMap, false,
                        authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util, identityTenantUtil,
                        userInfoEndpointConfig);
                List<String> essentialClaims = Collections.singletonList(email);

                setUpRequestObjectService();

                // Mock for essential claims.
                oAuth2Util.when(() -> OAuth2Util.getEssentialClaims(anyString(), anyString()))
                        .thenReturn(essentialClaims);
                when(authorizationGrantCacheEntry.getEssentialClaims()).thenReturn(ESSENTIAL_CLAIM_JSON);
                mockDataSource(jdbcPersistenceManager);
                mockObjectsRelatedToTokenValidation(oAuth2Util);

                frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                        .thenReturn(AUTHORIZED_USER_ID);

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
                authenticatedUser.setTenantDomain(TENANT_DOT_COM);
                authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
                authenticatedUser.setUserId(AUTHORIZED_USER_ID);
                authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
                mockAccessTokenDOInOAuth2Util(authenticatedUser, oAuth2Util);

                String responseString =
                        userInfoJSONResponseBuilder.getResponseString(
                                getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

                Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
                assertNotNull(claimsInResponse);
                assertNotNull(claimsInResponse.get(sub));

                // Assert that claims not in scope were not sent
                assertNull(claimsInResponse.get(lastName));

                // Assert claim in scope was sent
                assertNotNull(claimsInResponse.get(firstName));
                assertEquals(claimsInResponse.get(firstName), FIRST_NAME_VALUE);

                // Assert whether essential claims are available even though they were not in requested scope.
                assertNotNull(claimsInResponse.get(email));
                assertEquals(claimsInResponse.get(email), EMAIL_VALUE);
            }
        }
    }

    @Test
    public void testUpdateAtClaim() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);

            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                         mockStatic(AuthorizationGrantCache.class);
                 MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {
                String updateAtValue = "1509556412";
                testLongClaimInUserInfoResponse(UPDATED_AT, updateAtValue, jdbcPersistenceManager, frameworkUtils,
                        authorizationGrantCache, claimUtil, oAuth2Util, identityTenantUtil, userInfoEndpointConfig);
            }
        }
    }

    @Test
    public void testEmailVerified() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);

            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                         mockStatic(AuthorizationGrantCache.class);
                 MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {
                String emailVerifiedClaimValue = "true";
                testBooleanClaimInUserInfoResponse(EMAIL_VERIFIED, emailVerifiedClaimValue, jdbcPersistenceManager,
                        frameworkUtils, authorizationGrantCache, claimUtil, oAuth2Util, identityTenantUtil,
                        userInfoEndpointConfig);
            }
        }
    }

    @Test
    public void testPhoneNumberVerified() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                         mockStatic(AuthorizationGrantCache.class);
                 MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {
                String phoneNumberVerifiedClaimValue = "true";
                testBooleanClaimInUserInfoResponse(PHONE_NUMBER_VERIFIED, phoneNumberVerifiedClaimValue,
                        jdbcPersistenceManager, frameworkUtils, authorizationGrantCache,
                        claimUtil, oAuth2Util, identityTenantUtil, userInfoEndpointConfig);
            }
        }
    }

    private void testBooleanClaimInUserInfoResponse(String claimUri, String claimValue,
                                                    MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                                    MockedStatic<FrameworkUtils> frameworkUtils,
                                                    MockedStatic<AuthorizationGrantCache> authorizationGrantCache,
                                                    MockedStatic<ClaimUtil> claimUtil,
                                                    MockedStatic<OAuth2Util> oAuth2Util,
                                                    MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                                    MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig)
            throws Exception {

        initSingleClaimTest(claimUri, claimValue, authorizationGrantCache, frameworkUtils,
                claimUtil, oAuth2Util, identityTenantUtil, userInfoEndpointConfig);

        setUpRequestObjectService();
        mockDataSource(jdbcPersistenceManager);
        mockObjectsRelatedToTokenValidation(oAuth2Util);

        frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                .thenReturn(AUTHORIZED_USER_ID);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOT_COM);
        authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
        authenticatedUser.setUserId(AUTHORIZED_USER_ID);
        authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
        mockAccessTokenDOInOAuth2Util(authenticatedUser, oAuth2Util);

        String responseString =
                userInfoJSONResponseBuilder.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
        assertSubjectClaimPresent(claimsInResponse);
        assertNotNull(claimsInResponse.get(claimUri));
        // Assert whether the returned claim is of Boolean type
        assertEquals(claimsInResponse.get(claimUri), Boolean.parseBoolean(claimValue));
    }

    private void testLongClaimInUserInfoResponse(String claimUri, String claimValue,
                                                 MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                                 MockedStatic<FrameworkUtils> frameworkUtils,
                                                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache,
                                                 MockedStatic<ClaimUtil> claimUtil, MockedStatic<OAuth2Util> oAuth2Util,
                                                 MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig)
            throws Exception {

        initSingleClaimTest(claimUri, claimValue, authorizationGrantCache, frameworkUtils,
                claimUtil, oAuth2Util, identityTenantUtil, userInfoEndpointConfig);
        setUpRequestObjectService();
        mockDataSource(jdbcPersistenceManager);
        mockObjectsRelatedToTokenValidation(oAuth2Util);
        frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                .thenReturn(AUTHORIZED_USER_ID);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOT_COM);
        authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
        authenticatedUser.setUserId(AUTHORIZED_USER_ID);
        authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
        mockAccessTokenDOInOAuth2Util(authenticatedUser, oAuth2Util);

        String responseString =
                userInfoJSONResponseBuilder.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
        assertSubjectClaimPresent(claimsInResponse);
        assertNotNull(claimsInResponse.get(claimUri));
        assertTrue(claimsInResponse.get(claimUri) instanceof Integer || claimsInResponse.get(claimUri) instanceof Long);
    }

    @DataProvider(name = "subjectClaimDataProvider")
    public Object[][] provideSubjectData() {

        return getSubjectClaimTestData();
    }

    @Test(dataProvider = "subjectClaimDataProvider")
    public void testSubjectClaim(Map<String, Object> inputClaims,
                                 Object authorizedUser,
                                 boolean appendTenantDomain,
                                 boolean appendUserStoreDomain, boolean isPairwiseSubject,
                                 String expectedSubjectValue, String expectedPPID) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                         mockStatic(AuthorizationGrantCache.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {
                setUpRequestObjectService();
                AuthenticatedUser authzUser = (AuthenticatedUser) authorizedUser;
                prepareForSubjectClaimTest(authzUser, inputClaims, appendTenantDomain, appendUserStoreDomain,
                        isPairwiseSubject, authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util,
                        identityTenantUtil, userInfoEndpointConfig);
                updateAuthenticatedSubjectIdentifier(authzUser, appendTenantDomain, appendUserStoreDomain, inputClaims);
                when(userInfoJSONResponseBuilder.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                        .thenReturn(inputClaims);
                Mockito.when(IdentityTenantUtil.getTenantId(isNull())).thenReturn(-1234);
                mockDataSource(jdbcPersistenceManager);
                mockObjectsRelatedToTokenValidation(oAuth2Util);
                String responseString =
                        userInfoJSONResponseBuilder
                                .getResponseString(getTokenResponseDTO((authzUser).toFullQualifiedUsername()));

                Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
                assertSubjectClaimPresent(claimsInResponse);
                assertEquals(claimsInResponse.get(sub), isPairwiseSubject ? expectedPPID : expectedSubjectValue);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    @Test(dataProvider = "subjectClaimDataProvider")
    public void testSubjectClaimWithAlteredApplicationConfigs(Map<String, Object> inputClaims,
                                                              Object authorizedUser,
                                                              boolean appendTenantDomain,
                                                              boolean appendUserStoreDomain, boolean isPairwiseSubject,
                                                              String expectedSubjectValue, String expectedPPID)
            throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration =
                     mockStatic(OAuthServerConfiguration.class);) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);

            try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                         mockStatic(JDBCPersistenceManager.class);
                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                         mockStatic(AuthorizationGrantCache.class);
                 MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
                 MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                         mockStatic(UserInfoEndpointConfig.class);) {
                setUpRequestObjectService();
                AuthenticatedUser authzUser = (AuthenticatedUser) authorizedUser;
                prepareForSubjectClaimTest(authzUser, inputClaims, !appendTenantDomain, !appendUserStoreDomain,
                        isPairwiseSubject, authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util,
                        identityTenantUtil, userInfoEndpointConfig);
                authzUser.setAuthenticatedSubjectIdentifier(expectedSubjectValue,
                        applicationManagementService.getServiceProviderByClientId(CLIENT_ID,
                                IdentityApplicationConstants.OAuth2.NAME, SUPER_TENANT_DOMAIN_NAME));

                when(userInfoJSONResponseBuilder.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                        .thenReturn(inputClaims);
                Mockito.when(IdentityTenantUtil.getTenantId(isNull())).thenReturn(-1234);
                mockDataSource(jdbcPersistenceManager);
                mockObjectsRelatedToTokenValidation(oAuth2Util);
                String responseString =
                        userInfoJSONResponseBuilder
                                .getResponseString(getTokenResponseDTO((authzUser).toFullQualifiedUsername()));

                Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
                assertSubjectClaimPresent(claimsInResponse);
                assertEquals(claimsInResponse.get(sub), isPairwiseSubject ? expectedPPID : expectedSubjectValue);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }
}
