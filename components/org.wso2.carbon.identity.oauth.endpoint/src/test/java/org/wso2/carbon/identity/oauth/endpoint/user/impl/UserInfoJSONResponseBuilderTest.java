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
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * This class contains tests for UserInfoJSONResponseBuilder.
 */
@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, IdentityTenantUtil.class,
        AuthorizationGrantCache.class, ClaimUtil.class, IdentityUtil.class, UserInfoEndpointConfig.class,
        JDBCPersistenceManager.class})
@PowerMockIgnore({"javax.management.*"})
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

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private void setUpRequestObjectService() throws RequestObjectException {

        List<RequestedClaim> requestedClaims = Collections.emptyList();
        when(requestObjectService.getRequestedClaimsForIDToken(anyString())).
                thenReturn(requestedClaims);
        when(requestObjectService.getRequestedClaimsForUserInfo(anyString())).
                thenReturn(requestedClaims);
        OpenIDConnectServiceComponentHolder.getInstance()
                .getOpenIDConnectClaimFilters()
                .add(new OpenIDConnectClaimFilterImpl());
        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
    }

    private void mockDataSource() throws SQLException {

        mockStatic(JDBCPersistenceManager.class);
        DataSource dataSource = Mockito.mock(DataSource.class);
        JDBCPersistenceManager jdbcPersistenceManager = Mockito.mock(JDBCPersistenceManager.class);
        Mockito.when(dataSource.getConnection()).thenReturn(con);
        Mockito.when(jdbcPersistenceManager.getInstance()).thenReturn(jdbcPersistenceManager);
        Mockito.when(jdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
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

        try {
            setUpRequestObjectService();
            prepareForResponseClaimTest(inputClaims, oidcScopeMap, getClaimsFromCache);
            mockDataSource();
            mockObjectsRelatedToTokenValidation();
            mockStatic(FrameworkUtils.class);
            when(FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                    .thenReturn(AUTHORIZED_USER_ID);

            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
            authenticatedUser.setTenantDomain(TENANT_DOT_COM);
            authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
            authenticatedUser.setUserId(AUTHORIZED_USER_ID);
            authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
            mockAccessTokenDOInOAuth2Util(authenticatedUser);

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

    @Test
    public void testEssentialClaims() throws Exception {

        final Map<String, Object> inputClaims = new HashMap<>();
        inputClaims.put(firstName, FIRST_NAME_VALUE);
        inputClaims.put(lastName, LAST_NAME_VALUE);
        inputClaims.put(email, EMAIL_VALUE);

        final Map<String, List<String>> oidcScopeMap = new HashMap<>();
        oidcScopeMap.put(OIDC_SCOPE, Collections.singletonList(firstName));

        List<String> essentialClaims = Collections.singletonList(email);
        prepareForResponseClaimTest(inputClaims, oidcScopeMap, false);

        setUpRequestObjectService();

        // Mock for essential claims.
        when(OAuth2Util.getEssentialClaims(anyString(), anyString())).thenReturn(essentialClaims);
        when(authorizationGrantCacheEntry.getEssentialClaims()).thenReturn(ESSENTIAL_CLAIM_JSON);
        mockDataSource();
        mockObjectsRelatedToTokenValidation();

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                .thenReturn(AUTHORIZED_USER_ID);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOT_COM);
        authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
        authenticatedUser.setUserId(AUTHORIZED_USER_ID);
        authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
        mockAccessTokenDOInOAuth2Util(authenticatedUser);

        String responseString =
                userInfoJSONResponseBuilder.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

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

    @Test
    public void testUpdateAtClaim() throws Exception {

        String updateAtValue = "1509556412";
        testLongClaimInUserInfoResponse(UPDATED_AT, updateAtValue);
    }

    @Test
    public void testEmailVerified() throws Exception {

        String emailVerifiedClaimValue = "true";
        testBooleanClaimInUserInfoResponse(EMAIL_VERIFIED, emailVerifiedClaimValue);
    }

    @Test
    public void testPhoneNumberVerified() throws Exception {

        String phoneNumberVerifiedClaimValue = "true";
        testBooleanClaimInUserInfoResponse(PHONE_NUMBER_VERIFIED, phoneNumberVerifiedClaimValue);
    }

    private void testBooleanClaimInUserInfoResponse(String claimUri, String claimValue) throws Exception {

        initSingleClaimTest(claimUri, claimValue);

        setUpRequestObjectService();
        mockDataSource();
        mockObjectsRelatedToTokenValidation();

        mockStatic(FrameworkUtils.class);
        Mockito.when(FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                .thenReturn(AUTHORIZED_USER_ID);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOT_COM);
        authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
        authenticatedUser.setUserId(AUTHORIZED_USER_ID);
        authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
        mockAccessTokenDOInOAuth2Util(authenticatedUser);

        String responseString =
                userInfoJSONResponseBuilder.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
        assertSubjectClaimPresent(claimsInResponse);
        assertNotNull(claimsInResponse.get(claimUri));
        // Assert whether the returned claim is of Boolean type
        assertEquals(claimsInResponse.get(claimUri), Boolean.parseBoolean(claimValue));
    }

    private void testLongClaimInUserInfoResponse(String claimUri, String claimValue) throws Exception {

        initSingleClaimTest(claimUri, claimValue);
        setUpRequestObjectService();
        mockDataSource();
        mockObjectsRelatedToTokenValidation();
        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.resolveUserIdFromUsername(anyInt(), anyString(), anyString()))
                .thenReturn(AUTHORIZED_USER_ID);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(AUTHORIZED_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOT_COM);
        authenticatedUser.setUserStoreDomain(JDBC_DOMAIN);
        authenticatedUser.setUserId(AUTHORIZED_USER_ID);
        authenticatedUser.setAuthenticatedSubjectIdentifier(AUTHORIZED_USER_ID);
        mockAccessTokenDOInOAuth2Util(authenticatedUser);

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

        try {
            setUpRequestObjectService();
            AuthenticatedUser authzUser = (AuthenticatedUser) authorizedUser;
            prepareForSubjectClaimTest(authzUser, inputClaims, appendTenantDomain, appendUserStoreDomain,
                    isPairwiseSubject);
            updateAuthenticatedSubjectIdentifier(authzUser, appendTenantDomain, appendUserStoreDomain, inputClaims);
            when(userInfoJSONResponseBuilder.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                    .thenReturn(inputClaims);
            Mockito.when(IdentityTenantUtil.getTenantId(isNull())).thenReturn(-1234);
            mockDataSource();
            mockObjectsRelatedToTokenValidation();
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

    @Test(dataProvider = "subjectClaimDataProvider")
    public void testSubjectClaimWithAlteredApplicationConfigs(Map<String, Object> inputClaims,
                                                              Object authorizedUser,
                                                              boolean appendTenantDomain,
                                                              boolean appendUserStoreDomain, boolean isPairwiseSubject,
                                                              String expectedSubjectValue, String expectedPPID)
            throws Exception {

        try {
            setUpRequestObjectService();
            AuthenticatedUser authzUser = (AuthenticatedUser) authorizedUser;
            prepareForSubjectClaimTest(authzUser, inputClaims, !appendTenantDomain, !appendUserStoreDomain,
                    isPairwiseSubject);
            authzUser.setAuthenticatedSubjectIdentifier(expectedSubjectValue,
                    applicationManagementService.getServiceProviderByClientId(CLIENT_ID,
                            IdentityApplicationConstants.OAuth2.NAME, SUPER_TENANT_DOMAIN_NAME));

            when(userInfoJSONResponseBuilder.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                    .thenReturn(inputClaims);
            Mockito.when(IdentityTenantUtil.getTenantId(isNull())).thenReturn(-1234);
            mockDataSource();
            mockObjectsRelatedToTokenValidation();
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
