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

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.service.RegistryService;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;

/**
 * This class contains tests for UserInfoJSONResponseBuilder.
 */
@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, IdentityTenantUtil.class, RegistryService.class,
        AuthorizationGrantCache.class, ClaimUtil.class, IdentityUtil.class, UserInfoEndpointConfig.class})
public class UserInfoJSONResponseBuilderTest extends UserInfoResponseBaseTest {

    @DataProvider
    public Object[][] responseStringInputs() {
        return new Object[][]{
                {new String[]{FIRST_NAME, LAST_NAME, EMAIL}, new String[]{FIRST_NAME}, new String[]
                        {FIRST_NAME}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL}, new String[]{FIRST_NAME}, new String[]
                        {FIRST_NAME}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, SUB}, new String[]{FIRST_NAME}, new
                        String[]{FIRST_NAME}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL, PHONE_NUMBER_VERIFIED}, new String[]{FIRST_NAME,
                        PHONE_NUMBER_VERIFIED}, new String[]{FIRST_NAME + CLAIM_SEPARATOR + LAST_NAME +
                        CLAIM_SEPARATOR + PHONE_NUMBER_VERIFIED + CLAIM_SEPARATOR + EMAIL_VERIFIED}, new
                        String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL, PHONE_NUMBER_VERIFIED, EMAIL_VERIFIED}, new
                        String[]{FIRST_NAME, PHONE_NUMBER_VERIFIED, EMAIL_VERIFIED}, new
                        String[]{FIRST_NAME + CLAIM_SEPARATOR + LAST_NAME + CLAIM_SEPARATOR + PHONE_NUMBER_VERIFIED +
                        CLAIM_SEPARATOR + EMAIL_VERIFIED}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL, ADDRESS_PREFIX + "address"}, new String[]{FIRST_NAME}, new
                        String[]{FIRST_NAME + CLAIM_SEPARATOR + ADDRESS_PREFIX + "address"}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL, UPDATED_AT}, new String[]{FIRST_NAME, UPDATED_AT}, new
                        String[]{FIRST_NAME + CLAIM_SEPARATOR + UPDATED_AT}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL, UPDATED_AT + ":123456789"}, new String[]{FIRST_NAME,
                        UPDATED_AT}, new String[]{FIRST_NAME + CLAIM_SEPARATOR + UPDATED_AT}, new String[]{OIDC}, false},

                {new String[]{FIRST_NAME, LAST_NAME, EMAIL}, new String[]{}, new String[]
                        {FIRST_NAME}, new String[]{OIDC, "address"}, true},
        };
    }

    @Test(dataProvider = "responseStringInputs")
    public void testGetResponseString(String[] inputClaims, String[] assertClaims, String[] scopeClaims, String[]
            scopes, boolean getClaimsFromCache) throws Exception {
        try {
            startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            mockOAuthServerConfiguration();
            mockStatic(IdentityTenantUtil.class);
            when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            spy(OAuth2Util.class);
            prepareOAuth2Util();
            prepareIdentityUtil();
            prepareUserInfoEndpointConfig();
            prepareApplicationManagementService();
            prepareRegistry(scopeClaims, scopes);
            prepareAuthorizationGrantCache(getClaimsFromCache);
            prepareClaimUtil(getClaims(inputClaims));
            String responseString = userInfoJSONResponseBuilder.getResponseString(prepareTokenResponseDTO());

            for (String claim : assertClaims) {
                assertTrue(responseString.contains(claim), "Expected to present " + claim + " in the response " +
                        "string");
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

}
