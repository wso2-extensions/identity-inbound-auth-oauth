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
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class to test UserInfoJWTResponse.
 */
@PrepareForTest({AuthorizationGrantCache.class})
public class UserInfoJWTResponseTest extends UserInfoResponseBaseTest {

    private UserInfoJWTResponse userInfoJWTResponse;

    @BeforeClass
    public void setup() {
        userInfoJWTResponse = new UserInfoJWTResponse();
    }
    @DataProvider(name = "subjectClaimDataProvider")
    public Object[][] provideSubjectData() {
        return getSubjectClaimTestData();
    }

    @Test(dataProvider = "subjectClaimDataProvider")
    public void testSubjectClaim(Map<String, Object> inputClaims,
                                 Object authorizedUser,
                                 boolean appendTenantDomain,
                                 boolean appendUserStoreDomain,
                                 String expectedSubjectValue) throws Exception {
        try {
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) authorizedUser;
            prepareForSubjectClaimTest(authenticatedUser, inputClaims, appendTenantDomain, appendUserStoreDomain);

            userInfoJWTResponse = spy(new UserInfoJWTResponse());
            when(userInfoJWTResponse.retrieveUserClaims(any(OAuth2TokenValidationResponseDTO.class)))
                    .thenReturn(inputClaims);

            String responseString =
                    userInfoJWTResponse.getResponseString(getTokenResponseDTO(authenticatedUser.toFullQualifiedUsername()));

            JWT jwt = JWTParser.parse(responseString);
            assertNotNull(jwt);
            assertNotNull(jwt.getJWTClaimsSet());
            assertNotNull(jwt.getJWTClaimsSet().getSubject());
            assertEquals(jwt.getJWTClaimsSet().getSubject(), expectedSubjectValue);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
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
                userInfoJWTResponse.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        JWT jwt = JWTParser.parse(responseString);
        assertNotNull(jwt);
        assertNotNull(jwt.getJWTClaimsSet());

        Map<String, Object> claimsInResponse = jwt.getJWTClaimsSet().getAllClaims();
        assertSubjectClaimPresent(claimsInResponse);
        assertNotNull(claimsInResponse.get(claimUri));
        assertEquals(claimsInResponse.get(claimUri), Boolean.parseBoolean(claimValue));
    }

    private void testLongClaimInUserInfoResponse(String claimUri, String claimValue) throws Exception {
        initSingleClaimTest(claimUri, claimValue);
        String responseString =
                userInfoJWTResponse.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        JWT jwt = JWTParser.parse(responseString);
        assertNotNull(jwt);
        assertNotNull(jwt.getJWTClaimsSet());

        Map<String, Object> claimsInResponse = jwt.getJWTClaimsSet().getAllClaims();
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
        try {
            prepareForResponseClaimTest(inputClaims, oidcScopeMap, getClaimsFromCache);
            String responseString =
                    userInfoJWTResponse.getResponseString(
                            getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED, requestedScopes));

            JWT jwt = JWTParser.parse(responseString);
            ReadOnlyJWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getSubject());

            for (Map.Entry<String, Object> expectedClaimEntry : expectedClaims.entrySet()) {
                assertTrue(jwtClaimsSet.getAllClaims().containsKey(expectedClaimEntry.getKey()));
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
}
