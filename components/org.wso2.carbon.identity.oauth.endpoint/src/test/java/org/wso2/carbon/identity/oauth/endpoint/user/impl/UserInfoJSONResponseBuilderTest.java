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

import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.ResourceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * This class contains tests for UserInfoJSONResponseBuilder.
 */
@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, IdentityTenantUtil.class, RegistryService.class,
        AuthorizationGrantCache.class, ClaimUtil.class, IdentityUtil.class, UserInfoEndpointConfig.class})
public class UserInfoJSONResponseBuilderTest extends PowerMockTestCase {

    @Mock
    private RegistryService registryService;
    @Mock
    private UserRegistry userRegistry;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private AuthorizationGrantCache authorizationGrantCache;
    @Mock
    private AuthorizationGrantCacheEntry authorizationGrantCacheEntry;
    @Mock
    private UserInfoEndpointConfig userInfoEndpointConfig;
    @Mock
    ApplicationManagementService applicationManagementService;
    private Resource resource;
    private UserInfoJSONResponseBuilder userInfoJSONResponseBuilder;
    private final String FIRST_NAME = "first_name";
    private final String LAST_NAME = "LAST_NAME";
    private final String OIDC = "oidc";
    private final String EMAIL = "email";
    private final String SUB = "sub";
    private static final String UPDATED_AT = "updated_at";
    private static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String ADDRESS = "address";
    private static final String ADDRESS_PREFIX = "address.";
    private static final String CLAIM_SEPARATOR = ",";

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @BeforeClass
    public void setUp() {
        userInfoJSONResponseBuilder = new UserInfoJSONResponseBuilder();
        resource = new ResourceImpl();
    }

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
                Assert.assertTrue(responseString.contains(claim), "Expected to present " + claim + " in the response " +
                        "string");
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void mockOAuthServerConfiguration() throws Exception {
        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    private void startTenantFlow(String tenantDomain) {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
    }

    private void prepareRegistry(String[] claims, String[] scopes) throws Exception {
        Properties registryResourceProperties = new Properties();
        for (String scope : scopes) {
            List propertyValues = new ArrayList();
            for (String claim : claims) {
                propertyValues.add(claim);
            }
            registryResourceProperties.put(scope, propertyValues);
        }
        OAuth2ServiceComponentHolder.setRegistryService(registryService);
        when(registryService.getConfigSystemRegistry(anyInt())).thenReturn(userRegistry);
        resource.setProperties(registryResourceProperties);
        when(userRegistry.get(anyString())).thenReturn(resource);
    }

    private OAuth2TokenValidationResponseDTO prepareTokenResponseDTO() {
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken authorizationContextToken =
                oAuth2TokenValidationResponseDTO.new AuthorizationContextToken("JWT", "1234567890");
        oAuth2TokenValidationResponseDTO.setAuthorizationContextToken(authorizationContextToken);
        oAuth2TokenValidationResponseDTO.setScope(new String[]{OIDC});

        return oAuth2TokenValidationResponseDTO;
    }

    private void prepareAuthorizationGrantCache(boolean getClaimsFromCache) {
        mockStatic(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class))).thenReturn
                (authorizationGrantCacheEntry);
        Map userAttributes = new HashMap();
        if (getClaimsFromCache) {
            userAttributes.put("cachedClaim1", "cachedClaim1Value1");
            userAttributes.put("cachedClaim2", "cachedClaim1Value2");
        }
        when(authorizationGrantCacheEntry.getUserAttributes()).thenReturn(userAttributes);
    }

    private void prepareClaimUtil(Map claims) throws Exception {
        mockStatic(ClaimUtil.class);
        when(ClaimUtil.getClaimsFromUserStore(any(OAuth2TokenValidationResponseDTO.class))).thenReturn(claims);
    }

    private void prepareOAuth2Util() throws Exception {
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getClientIdForAccessToken(anyString())).thenReturn("mock_client_id");
        ArrayList userAttributesFromCache = new ArrayList();
        userAttributesFromCache.add("cachedClaim1");
        userAttributesFromCache.add("cachedClaim2");
        when(OAuth2Util.getEssentialClaims(anyString(), anyString())).thenReturn(userAttributesFromCache);
    }

    private void prepareApplicationManagementService() throws Exception {
        ServiceProvider serviceProvider = new ServiceProvider();
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(new LocalAndOutboundAuthenticationConfig());
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setUseTenantDomainInLocalSubjectIdentifier(true);
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setUseUserstoreDomainInLocalSubjectIdentifier(true);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
    }

    private void prepareIdentityUtil() {
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
    }

    private void prepareUserInfoEndpointConfig() {
        UserInfoClaimRetriever claimsRetriever = mock(UserInfoClaimRetriever.class);
        mockStatic(UserInfoEndpointConfig.class);
        when(UserInfoEndpointConfig.getInstance()).thenReturn(userInfoEndpointConfig);
        when(claimsRetriever.getClaimsMap(any(Map.class))).thenReturn(new HashMap());
        when(userInfoEndpointConfig.getUserInfoClaimRetriever()).thenReturn(claimsRetriever);
    }

    private Map getClaims(String[] inputClaims) {
        Map claimsMap = new HashMap();
        for (String claim : inputClaims) {
            if (claim.contains(":")) {
                String[] keyValue = claim.split(":");
                claimsMap.put(keyValue[0], keyValue[1]);
            } else if (UPDATED_AT.contains(claim)) {
                claimsMap.put(claim, System.currentTimeMillis());
            } else {
                claimsMap.put(claim, claim + "_value");
            }
        }
        return claimsMap;
    }
}
