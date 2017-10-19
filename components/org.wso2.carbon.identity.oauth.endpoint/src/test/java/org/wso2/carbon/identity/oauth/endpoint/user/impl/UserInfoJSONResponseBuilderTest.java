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
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.ResourceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;

/**
 * This class contains tests for UserInfoJSONResponseBuilder.
 */
@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, IdentityTenantUtil.class, RegistryService.class,
        AuthorizationGrantCache.class, ClaimUtil.class})
public class UserInfoJSONResponseBuilderTest extends PowerMockTestCase {

    @Mock
    private RegistryService registryService;
    @Mock
    private UserRegistry userRegistry;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private IdentityTenantUtil identityTenantUtil;
    @Mock
    private AuthorizationGrantCache authorizationGrantCache;
    @Mock
    private AuthorizationGrantCacheEntry authorizationGrantCacheEntry;
    @Mock
    private ClaimUtil claimUtil;
    private Resource resource;
    private UserInfoJSONResponseBuilder userInfoJSONResponseBuilder;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @BeforeClass
    public void setUp() {
        userInfoJSONResponseBuilder = new UserInfoJSONResponseBuilder();
        resource = new ResourceImpl();
    }

    @Test
    public void testGetResponseString() throws Exception {
        try {
            startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            mockOAuthServerConfiguration();
            mockStatic(IdentityTenantUtil.class);
            when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
            spy(OAuth2Util.class);
            prepareRegistry();
            prepareAuthorizationGrantCache();
            prepareClaimUtil();

            String responseString = userInfoJSONResponseBuilder.getResponseString(prepareTokenResponseDTO());
            assertTrue(responseString.contains("first_name"));
            assertTrue(responseString.contains("first_name_value"));
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

    private void prepareRegistry() throws Exception {
        Properties registryResourceProperties = new Properties();
        List propertyValues = new ArrayList();
        propertyValues.add("first_name");
        propertyValues.add("last_name");
        registryResourceProperties.put("oidc", propertyValues);
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
        oAuth2TokenValidationResponseDTO.setScope(new String[]{"oidc", "email"});

        return oAuth2TokenValidationResponseDTO;
    }

    private void prepareAuthorizationGrantCache() {
        mockStatic(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class))).thenReturn
                (authorizationGrantCacheEntry);
        when(authorizationGrantCacheEntry.getUserAttributes()).thenReturn(new HashMap<ClaimMapping, String>());
    }

    private void prepareClaimUtil() throws Exception {
        Map claims = new HashMap();
        claims.put("first_name", "first_name_value");
        claims.put("last_name", "last_name_value");
        claims.put("email", "email@value.com");
        mockStatic(ClaimUtil.class);
        when(ClaimUtil.getClaimsFromUserStore(any(OAuth2TokenValidationResponseDTO.class))).thenReturn(claims);
    }
}
