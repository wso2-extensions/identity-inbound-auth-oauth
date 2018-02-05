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
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * This class contains tests for UserInfoJSONResponseBuilder.
 */
@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, IdentityTenantUtil.class, RegistryService.class,
        AuthorizationGrantCache.class, ClaimUtil.class, IdentityUtil.class, UserInfoEndpointConfig.class})
public class UserInfoJSONResponseBuilderTest extends UserInfoResponseBaseTest {

    private UserInfoJSONResponseBuilder userInfoJSONResponseBuilder;

    @BeforeTest
    public void setUpTest() {
        userInfoJSONResponseBuilder = new UserInfoJSONResponseBuilder();
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
            prepareForResponseClaimTest(inputClaims, oidcScopeMap, getClaimsFromCache);
            String responseString =
                    userInfoJSONResponseBuilder.getResponseString(
                            getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED, requestedScopes));

            Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
            assertNotNull(claimsInResponse);
            assertFalse(claimsInResponse.isEmpty());
            assertNotNull(claimsInResponse.get(SUB));

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
        inputClaims.put(FIRST_NAME, FIRST_NAME_VALUE);
        inputClaims.put(LAST_NAME, LAST_NAME_VALUE);
        inputClaims.put(EMAIL, EMAIL_VALUE);

        final Map<String, List<String>> oidcScopeMap = new HashMap<>();
        oidcScopeMap.put(OIDC_SCOPE, Collections.singletonList(FIRST_NAME));

        List<String> essentialClaims = Collections.singletonList(EMAIL);
        prepareForResponseClaimTest(inputClaims, oidcScopeMap, false);

        // Mock for essential claims.
        when(OAuth2Util.getEssentialClaims(anyString(), anyString())).thenReturn(essentialClaims);
        when(authorizationGrantCacheEntry.getEssentialClaims()).thenReturn(ESSENTIAL_CLAIM_JSON);

        String responseString =
                userInfoJSONResponseBuilder.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
        assertNotNull(claimsInResponse);
        assertNotNull(claimsInResponse.get(SUB));

        // Assert that claims not in scope were not sent
        assertNull(claimsInResponse.get(LAST_NAME));

        // Assert claim in scope was sent
        assertNotNull(claimsInResponse.get(FIRST_NAME));
        assertEquals(claimsInResponse.get(FIRST_NAME), FIRST_NAME_VALUE);

        // Assert whether essential claims are available even though they were not in requested scope.
        assertNotNull(claimsInResponse.get(EMAIL));
        assertEquals(claimsInResponse.get(EMAIL), EMAIL_VALUE);
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
                                 Object authorizedUsername,
                                 boolean appendTenantDomain,
                                 boolean appendUserStoreDomain,
                                 String expectedSubjectValue) throws Exception {
        try {
            AuthenticatedUser authzUser = (AuthenticatedUser) authorizedUsername;
            prepareForSubjectClaimTest(authzUser, inputClaims, appendTenantDomain, appendUserStoreDomain);

            when(userInfoJSONResponseBuilder.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                    .thenReturn(inputClaims);

            String responseString =
                    userInfoJSONResponseBuilder.getResponseString(getTokenResponseDTO((authzUser).toFullQualifiedUsername()));

            Map<String, Object> claimsInResponse = JSONUtils.parseJSON(responseString);
            assertSubjectClaimPresent(claimsInResponse);
            assertEquals(claimsInResponse.get(SUB), expectedSubjectValue);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
