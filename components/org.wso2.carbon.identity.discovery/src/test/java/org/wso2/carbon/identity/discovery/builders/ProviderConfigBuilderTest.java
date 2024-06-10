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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.discovery.builders;

import com.nimbusds.jose.JWSAlgorithm;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.discovery.DiscoveryUtil;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.discovery.OIDProviderRequest;
import org.wso2.carbon.identity.discovery.internal.OIDCDiscoveryDataHolder;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test covering ProviderConfigBuilder class.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class ProviderConfigBuilderTest {

    private String idTokenSignatureAlgorithm = "SHA256withRSA";
    private ProviderConfigBuilder providerConfigBuilder;

    @Mock
    private ClaimMetadataManagementService mockClaimMetadataManagementService;

    @Mock
    private OIDProviderRequest mockOidProviderRequest;

    @BeforeMethod
    public void setUp() throws Exception {

        providerConfigBuilder = new ProviderConfigBuilder();
    }

    @Test
    public void testBuildOIDProviderConfig() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OIDCDiscoveryDataHolder> oidcDiscoveryDataHolder =
                     mockStatic(OIDCDiscoveryDataHolder.class)) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);) {

                OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
                mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
                oidcDiscoveryDataHolder.when(OIDCDiscoveryDataHolder::getInstance)
                        .thenReturn(mockOidcDiscoveryDataHolder);

                List<ExternalClaim> claims = new ArrayList<>();
                ExternalClaim externalClaim = new ExternalClaim("aaa", "bbb", "ccc");
                claims.add(externalClaim);

                when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString())).thenReturn(claims);

                when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);
                when(mockOAuthServerConfiguration.getUserInfoJWTSignatureAlgorithm()).thenReturn(
                        idTokenSignatureAlgorithm);

                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(idTokenSignatureAlgorithm))
                        .thenReturn(JWSAlgorithm.RS256);
                oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString()))
                        .thenReturn(JWSAlgorithm.RS256);
                when(mockOidProviderRequest.getTenantDomain()).thenReturn(
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                assertNotNull(providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest));
            }
        }
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig1() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2Util.OAuthURL> oAuthURL = mockStatic(OAuth2Util.OAuthURL.class);) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            oAuthURL.when(() -> OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(anyString()))
                    .thenThrow(new URISyntaxException("input", "URISyntaxException"));
            oAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(anyString())).thenReturn("issuer");
            when(mockOidProviderRequest.getTenantDomain()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
        }
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig2() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OIDCDiscoveryDataHolder> oidcDiscoveryDataHolder =
                     mockStatic(OIDCDiscoveryDataHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
            mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
            oidcDiscoveryDataHolder.when(OIDCDiscoveryDataHolder::getInstance).thenReturn(mockOidcDiscoveryDataHolder);

            oAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(anyString())).thenReturn("issuer");

            when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString()))
                    .thenThrow(new ClaimMetadataException("ClaimMetadataException"));
            when(mockOidProviderRequest.getTenantDomain()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
        }
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig3() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OIDCDiscoveryDataHolder> oidcDiscoveryDataHolder =
                     mockStatic(OIDCDiscoveryDataHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
            mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
            oidcDiscoveryDataHolder.when(OIDCDiscoveryDataHolder::getInstance).thenReturn(mockOidcDiscoveryDataHolder);

            List<ExternalClaim> claims = new ArrayList<>();
            ExternalClaim mockExternalClaim = new ExternalClaim("aaa", "bbb", "ccc");
            claims.add(mockExternalClaim);
            when(mockClaimMetadataManagementService.getExternalClaims(nullable(String.class),
                    nullable(String.class))).thenReturn(claims);

            when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);
            oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(idTokenSignatureAlgorithm))
                    .thenThrow(new IdentityOAuth2Exception("IdentityOAuth2Exception"));

            providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
        }
    }

    @Test
    public void testBuildOIDProviderConfig4() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OIDCDiscoveryDataHolder> oidcDiscoveryDataHolder =
                     mockStatic(OIDCDiscoveryDataHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<DiscoveryUtil> discoveryUtil = mockStatic(DiscoveryUtil.class);) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
            mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
            oidcDiscoveryDataHolder.when(OIDCDiscoveryDataHolder::getInstance).thenReturn(mockOidcDiscoveryDataHolder);

            oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(idTokenSignatureAlgorithm))
                    .thenReturn(JWSAlgorithm.RS256);
            oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString()))
                    .thenReturn(JWSAlgorithm.RS256);
            String dummyIdIssuer = "http://domain:0000/oauth2/token";
            oAuth2Util.when(OAuth2Util::getIDTokenIssuer).thenReturn(dummyIdIssuer);

            List<ExternalClaim> claims = new ArrayList<>();
            ExternalClaim externalClaim = new ExternalClaim("aaa", "bbb", "ccc");
            claims.add(externalClaim);

            when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString())).thenReturn(claims);

            when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);

            discoveryUtil.when(DiscoveryUtil::isUseEntityIdAsIssuerInOidcDiscovery).thenReturn(Boolean.FALSE);

            when(mockOidProviderRequest.getTenantDomain()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            when(mockOAuthServerConfiguration.getUserInfoJWTSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);

            OIDProviderConfigResponse response = providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
            assertNotNull(response);
            assertEquals(response.getIssuer(), dummyIdIssuer);
        }
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig5() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OIDCDiscoveryDataHolder> oidcDiscoveryDataHolder =
                     mockStatic(OIDCDiscoveryDataHolder.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
            mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
            oidcDiscoveryDataHolder.when(OIDCDiscoveryDataHolder::getInstance).thenReturn(mockOidcDiscoveryDataHolder);

            List<ExternalClaim> claims = new ArrayList<>();
            ExternalClaim externalClaim = new ExternalClaim("aaa", "bbb", "ccc");
            claims.add(externalClaim);

            when(mockClaimMetadataManagementService.getExternalClaims(nullable(String.class),
                    nullable(String.class))).thenReturn(claims);

            when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);
            String wrongAlgo = "SHA150withRSA";
            when(mockOAuthServerConfiguration.getUserInfoJWTSignatureAlgorithm()).thenReturn(wrongAlgo);

            oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(idTokenSignatureAlgorithm))
                    .thenReturn(JWSAlgorithm.RS256);
            oAuth2Util.when(() -> OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(wrongAlgo))
                    .thenThrow(new IdentityOAuth2Exception("IdentityOAuth2Exception"));

            providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
        }
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig6() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);) {
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            oAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(anyString()))
                    .thenThrow(new IdentityOAuth2Exception("Configuration not found"));
            when(mockOidProviderRequest.getTenantDomain()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
        }
    }
}
