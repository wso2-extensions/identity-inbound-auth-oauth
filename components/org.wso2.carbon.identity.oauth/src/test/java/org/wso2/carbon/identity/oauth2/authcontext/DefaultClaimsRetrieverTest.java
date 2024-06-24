/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth2.authcontext;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;

@Listeners(MockitoTestNGListener.class)
public class DefaultClaimsRetrieverTest {

    private DefaultClaimsRetriever defaultClaimsRetriever;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private OAuthComponentServiceHolder mockedOAuthComponentServiceHolder;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private UserRealm mockedUserRealm;

    @Mock
    private UserStoreManager mockedUserStoreManager;

    @Mock
    private ClaimManager mockedClaimManager;

    @Mock
    private TenantManager mockedTenantManager;

    @BeforeTest
    public void setUp() {
        defaultClaimsRetriever = new DefaultClaimsRetriever();
    }

    private ClaimMapping[] getSampleClaimMapping() {
        String coreClaimUri1;
        String testMappedAttributesCore1;

        String coreClaimUri2;
        String testMappedAttributesCore2;

        String userClaimUri1;
        String testMappedAttributesUser1;

        String userClaimUri2;
        String testMappedAttributesUser2;

        Claim claim1 = new Claim();
        Claim claim2 = new Claim();
        Claim claim3 = new Claim();
        Claim claim4 = new Claim();

        coreClaimUri1 = "testCoreClaimURI1";
        claim1.setClaimUri(coreClaimUri1);
        testMappedAttributesCore1 = "MappedAttributesCore1";

        coreClaimUri2 = "testCoreClaimURI2";
        claim2.setClaimUri(coreClaimUri2);
        testMappedAttributesCore2 = "MappedAttributesCore2";

        userClaimUri1 = "testUserClaimURI1";
        claim3.setClaimUri(userClaimUri1);
        testMappedAttributesUser1 = "MappedAttributesUser1";

        userClaimUri2 = "testUserClaimURI2";
        claim4.setClaimUri(userClaimUri2);
        testMappedAttributesUser2 = "MappedAttributesUser2";

        ClaimMapping cMap1 = new ClaimMapping(claim1, testMappedAttributesCore1);
        ClaimMapping cMap2 = new ClaimMapping(claim2, testMappedAttributesCore2);
        ClaimMapping cMap3 = new ClaimMapping(claim3, testMappedAttributesUser1);
        ClaimMapping cMap4 = new ClaimMapping(claim4, testMappedAttributesUser2);
        return new ClaimMapping[]{cMap1, cMap2, cMap3, cMap4};
    }

    @Test
    public void testInit() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            // Subject is not null.
            String consumerDialectURI = "http://wso2.org/claims";
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);
            when(mockedOAuthServerConfiguration.getConsumerDialectURI()).thenReturn(consumerDialectURI);
            defaultClaimsRetriever.init();

            // Subject is null.
            when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
            when(mockedOAuthServerConfiguration.getConsumerDialectURI()).thenReturn(null);
            defaultClaimsRetriever.init();
        }
    }

    @Test
    public void testGetClaims() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);
            lenient().when(mockedOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn((long) 3);

            oAuthComponentServiceHolder.when(
                    OAuthComponentServiceHolder::getInstance).thenReturn(mockedOAuthComponentServiceHolder);
            when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);
            mockedUserRealm = mock(UserRealm.class);
            when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
            when(mockedTenantManager.getTenantId(anyString())).thenReturn(-1234);
            when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);

            String[] claims = {"https://www.wso2.org/address", "https://www.wso2.org/email"};

            assertNotNull(defaultClaimsRetriever.getClaims("admin", claims));
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetClaimsWhenException() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);
            when(mockedOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn((long) 3);

            oAuthComponentServiceHolder.when(
                    OAuthComponentServiceHolder::getInstance).thenReturn(mockedOAuthComponentServiceHolder);
            when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);

            when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
            when(mockedTenantManager.getTenantId(anyString())).thenReturn(-1234);

            mockedUserRealm = mock(UserRealm.class);
            when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
            when(mockedUserRealm.getUserStoreManager()).thenThrow(new UserStoreException("UserStoreException"));
            when(mockedUserStoreManager.getUserClaimValue(anyString(), anyString(), anyString())).
                    thenThrow(new UserStoreException("UserStoreException"));

            String[] claims = {"https://www.wso2.org/address", "https://www.wso2.org/email"};

            assertNotNull(defaultClaimsRetriever.getClaims("admin", claims));
        }
    }

    @Test
    public void testGetDefaultClaims() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);

            oAuthComponentServiceHolder.when(
                    OAuthComponentServiceHolder::getInstance).thenReturn(mockedOAuthComponentServiceHolder);
            mockedRealmService = mock(RealmService.class);
            when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);
            when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
            when(mockedTenantManager.getTenantId(anyString())).thenReturn(-1234);

            mockedUserRealm = mock(UserRealm.class);
            when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
            mockedClaimManager = mock(ClaimManager.class);
            when(mockedUserRealm.getClaimManager()).thenReturn(mockedClaimManager);
            when(mockedClaimManager.getAllClaimMappings(anyString())).thenReturn(this.getSampleClaimMapping());
            defaultClaimsRetriever.init();
            assertNotNull(defaultClaimsRetriever.getDefaultClaims("admin"));
        }

    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetDefaultClaimsWhenException() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockedOAuthServerConfiguration);
            when(mockedOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn((long) 7);

            oAuthComponentServiceHolder.when(
                    OAuthComponentServiceHolder::getInstance).thenReturn(mockedOAuthComponentServiceHolder);
            mockedRealmService = mock(RealmService.class);
            when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);
            when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
            when(mockedTenantManager.getTenantId(anyString())).thenReturn(-1234);
            mockedUserRealm = mock(UserRealm.class);
            when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
            mockedClaimManager = mock(ClaimManager.class);
            when(mockedUserRealm.getClaimManager()).thenReturn(mockedClaimManager);
            defaultClaimsRetriever.init();
            when(mockedClaimManager.getAllClaimMappings(anyString())).
                    thenThrow(new UserStoreException("UserStoreException"));
            assertNotNull(defaultClaimsRetriever.getDefaultClaims("admin"));
        }
    }

}
