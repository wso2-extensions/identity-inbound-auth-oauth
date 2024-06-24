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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
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
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Test class to test UserInfoJWTResponse.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class UserInfoJWTResponseTest extends UserInfoResponseBaseTest {

    private UserInfoJWTResponse userInfoJWTResponse;
    Connection con = null;
    MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    @BeforeClass
    public void setup() throws Exception {

        OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(new ScopeClaimMappingDAOImpl());
        TestUtils.initiateH2Base();
        con = TestUtils.getConnection();
        userInfoJWTResponse = new UserInfoJWTResponse();

        RequestObjectService requestObjectService = Mockito.mock(RequestObjectService.class);
        List<RequestedClaim> requestedClaims = Collections.EMPTY_LIST;
        when(requestObjectService.getRequestedClaimsForIDToken(anyString())).
                thenReturn(requestedClaims);
        when(requestObjectService.getRequestedClaimsForUserInfo(anyString())).
                thenReturn(requestedClaims);
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters()
                .add(new OpenIDConnectClaimFilterImpl());
        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
    }

    @BeforeMethod
    public void setUpMethod() {

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
    }

    @AfterMethod
    public void tearDown() {

        oAuthServerConfiguration.close();
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

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);
             MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                     mockStatic(UserInfoEndpointConfig.class);) {
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) authorizedUser;
            prepareForSubjectClaimTest(authenticatedUser, inputClaims, appendTenantDomain, appendUserStoreDomain,
                    isPairwiseSubject, authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util,
                    identityTenantUtil, userInfoEndpointConfig);
            updateAuthenticatedSubjectIdentifier(authenticatedUser, appendTenantDomain, appendUserStoreDomain,
                    inputClaims);

            mockObjectsRelatedToTokenValidation(oAuth2Util);

            frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                    .thenReturn(authenticatedUser.getUserId());
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(isNull())).thenReturn(-1234);
            userInfoJWTResponse = spy(new UserInfoJWTResponse());
            when(userInfoJWTResponse.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                    .thenReturn(inputClaims);
            DataSource dataSource = mock(DataSource.class);
            JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);
            lenient().when(dataSource.getConnection()).thenReturn(con);
            jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
            lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
            String responseString =
                    userInfoJWTResponse
                            .getResponseString(getTokenResponseDTO(authenticatedUser.toFullQualifiedUsername()));

            JWT jwt = JWTParser.parse(responseString);
            assertNotNull(jwt);
            assertNotNull(jwt.getJWTClaimsSet());
            assertNotNull(jwt.getJWTClaimsSet().getSubject());
            assertEquals(jwt.getJWTClaimsSet().getSubject(), isPairwiseSubject ? expectedPPID : expectedSubjectValue);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test(dataProvider = "subjectClaimDataProvider")
    public void testSubjectClaimWithAlteredApplicationConfigs(Map<String, Object> inputClaims,
                                                              Object authorizedUser,
                                                              boolean appendTenantDomain,
                                                              boolean appendUserStoreDomain, boolean isPairwiseSubject,
                                                              String expectedSubjectValue, String expectedPPID)
            throws Exception {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);
             MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                     mockStatic(UserInfoEndpointConfig.class);) {
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) authorizedUser;
            prepareForSubjectClaimTest(authenticatedUser, inputClaims, !appendTenantDomain, !appendUserStoreDomain,
                    isPairwiseSubject, authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util,
                    identityTenantUtil, userInfoEndpointConfig);
            authenticatedUser.setAuthenticatedSubjectIdentifier(expectedSubjectValue,
                    applicationManagementService.getServiceProviderByClientId(CLIENT_ID,
                            IdentityApplicationConstants.OAuth2.NAME, SUPER_TENANT_DOMAIN_NAME));
            mockObjectsRelatedToTokenValidation(oAuth2Util);

            frameworkUtils.when(() -> FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                    .thenReturn(authenticatedUser.getUserId());
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(isNull())).thenReturn(-1234);
            userInfoJWTResponse = spy(new UserInfoJWTResponse());
            when(userInfoJWTResponse.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                    .thenReturn(inputClaims);
            DataSource dataSource = mock(DataSource.class);
            JDBCPersistenceManager mockJdbcPersistenceManager = mock(JDBCPersistenceManager.class);
            lenient().when(dataSource.getConnection()).thenReturn(con);
            jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
            lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
            String responseString =
                    userInfoJWTResponse
                            .getResponseString(getTokenResponseDTO(authenticatedUser.toFullQualifiedUsername()));

            JWT jwt = JWTParser.parse(responseString);
            assertNotNull(jwt);
            assertNotNull(jwt.getJWTClaimsSet());
            assertNotNull(jwt.getJWTClaimsSet().getSubject());
            assertEquals(jwt.getJWTClaimsSet().getSubject(), isPairwiseSubject ? expectedPPID : expectedSubjectValue);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testUpdateAtClaim() throws Exception {

        try (MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager = mockStatic(JDBCPersistenceManager.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);
             MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                     mockStatic(UserInfoEndpointConfig.class);) {
            userInfoJWTResponse = new UserInfoJWTResponse();
            String updateAtValue = "1509556412";
            testLongClaimInUserInfoResponse(UPDATED_AT, updateAtValue, jdbcPersistenceManager, frameworkUtils,
                    oAuth2Util, authorizationGrantCache, claimUtil, identityTenantUtil, userInfoEndpointConfig);
        }
    }

    @Test
    public void testEmailVerified() throws Exception {

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

    @Test
    public void testPhoneNumberVerified() throws Exception {

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
                    jdbcPersistenceManager, frameworkUtils, authorizationGrantCache, claimUtil, oAuth2Util,
                    identityTenantUtil, userInfoEndpointConfig);
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
                userInfoJWTResponse.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        JWT jwt = JWTParser.parse(responseString);
        assertNotNull(jwt);
        assertNotNull(jwt.getJWTClaimsSet());

        Map<String, Object> claimsInResponse = jwt.getJWTClaimsSet().getClaims();
        assertSubjectClaimPresent(claimsInResponse);
        assertNotNull(claimsInResponse.get(claimUri));
        assertEquals(claimsInResponse.get(claimUri), Boolean.parseBoolean(claimValue));
    }

    private void testLongClaimInUserInfoResponse(String claimUri, String claimValue,
                                                 MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager,
                                                 MockedStatic<FrameworkUtils> frameworkUtils,
                                                 MockedStatic<OAuth2Util> oAuth2Util,
                                                 MockedStatic<AuthorizationGrantCache> authorizationGrantCache,
                                                 MockedStatic<ClaimUtil> claimUtil,
                                                 MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                                 MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig)
            throws Exception {

        userInfoJWTResponse = new UserInfoJWTResponse();
        initSingleClaimTest(claimUri, claimValue, authorizationGrantCache, frameworkUtils,
                claimUtil, oAuth2Util, identityTenantUtil, userInfoEndpointConfig);
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
                userInfoJWTResponse.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        JWT jwt = JWTParser.parse(responseString);
        assertNotNull(jwt);
        assertNotNull(jwt.getJWTClaimsSet());

        Map<String, Object> claimsInResponse = jwt.getJWTClaimsSet().getClaims();
        assertSubjectClaimPresent(claimsInResponse);
        assertNotNull(claimsInResponse.get(claimUri));
        assertTrue(claimsInResponse.get(claimUri) instanceof Integer || claimsInResponse.get(claimUri) instanceof Long);
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

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager =
                     mockStatic(JDBCPersistenceManager.class);
             MockedStatic<AuthorizationGrantCache> authorizationGrantCache =
                     mockStatic(AuthorizationGrantCache.class);
             MockedStatic<ClaimUtil> claimUtil = mockStatic(ClaimUtil.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig =
                     mockStatic(UserInfoEndpointConfig.class);) {
            prepareForResponseClaimTest(inputClaims, oidcScopeMap, getClaimsFromCache, authorizationGrantCache,
                    frameworkUtils, claimUtil, oAuth2Util, identityTenantUtil, userInfoEndpointConfig);
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
                    userInfoJWTResponse.getResponseString(
                            getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED, requestedScopes));

            JWT jwt = JWTParser.parse(responseString);
            JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getSubject());

            for (Map.Entry<String, Object> expectedClaimEntry : expectedClaims.entrySet()) {
                assertTrue(jwtClaimsSet.getClaims().containsKey(expectedClaimEntry.getKey()));
                assertNotNull(jwtClaimsSet.getClaim(expectedClaimEntry.getKey()));
                assertEquals(
                        expectedClaimEntry.getValue(),
                        jwtClaimsSet.getClaim(expectedClaimEntry.getKey())
                            );
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void mockDataSource(MockedStatic<JDBCPersistenceManager> jdbcPersistenceManager) throws SQLException {

        DataSource dataSource = Mockito.mock(DataSource.class);
        JDBCPersistenceManager mockJdbcPersistenceManager = Mockito.mock(JDBCPersistenceManager.class);
        lenient().when(dataSource.getConnection()).thenReturn(con);
        jdbcPersistenceManager.when(JDBCPersistenceManager::getInstance).thenReturn(mockJdbcPersistenceManager);
        lenient().when(mockJdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
    }
}
