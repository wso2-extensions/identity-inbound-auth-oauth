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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.discovery.OIDProviderRequest;
import org.wso2.carbon.identity.discovery.internal.OIDCDiscoveryDataHolder;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, OIDCDiscoveryDataHolder.class,
        ClaimMetadataManagementService.class})
public class ProviderConfigBuilderTest {

    private String idTokenSignatureAlgorithm = "SHA256withRSA";
    private ProviderConfigBuilder providerConfigBuilder;

    @Mock
    private ClaimMetadataManagementService mockClaimMetadataManagementService;

    @Mock
    private OIDProviderRequest mockOidProviderRequest;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        providerConfigBuilder = new ProviderConfigBuilder();
    }

    @Test
    public void testBuildOIDProviderConfig() throws Exception {
        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
        mockStatic(OIDCDiscoveryDataHolder.class);
        mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
        when(OIDCDiscoveryDataHolder.getInstance()).thenReturn(mockOidcDiscoveryDataHolder);

        mockStatic(OAuth2Util.class);
        mockStatic(OAuth2Util.OAuthURL.class);

        List<ExternalClaim> claims = new ArrayList<>();
        ExternalClaim externalClaim = new ExternalClaim("aaa", "bbb", "ccc");
        claims.add(externalClaim);

        when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString())).thenReturn(claims);

        when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);

        when(OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(idTokenSignatureAlgorithm)).thenReturn(JWSAlgorithm.RS256);
        assertNotNull(providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest));
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig1() throws Exception {
        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(anyString())).thenThrow(new URISyntaxException("input",
                "URISyntaxException"));

        providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig2() throws Exception {
        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
        mockStatic(OIDCDiscoveryDataHolder.class);
        mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
        when(OIDCDiscoveryDataHolder.getInstance()).thenReturn(mockOidcDiscoveryDataHolder);

        mockStatic(OAuth2Util.class);
        mockStatic(OAuth2Util.OAuthURL.class);

        when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString())).
                thenThrow(new ClaimMetadataException("ClaimMetadataException"));

        providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildOIDProviderConfig3() throws Exception {
        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        OIDCDiscoveryDataHolder mockOidcDiscoveryDataHolder = spy(new OIDCDiscoveryDataHolder());
        mockStatic(OIDCDiscoveryDataHolder.class);
        mockOidcDiscoveryDataHolder.setClaimManagementService(mockClaimMetadataManagementService);
        when(OIDCDiscoveryDataHolder.getInstance()).thenReturn(mockOidcDiscoveryDataHolder);

        mockStatic(OAuth2Util.class);
        mockStatic(OAuth2Util.OAuthURL.class);

        List<ExternalClaim> claims = new ArrayList<>();
        ExternalClaim mockExternalClaim = new ExternalClaim("aaa", "bbb", "ccc");
        claims.add(mockExternalClaim);
        when(mockClaimMetadataManagementService.getExternalClaims(anyString(), anyString())).thenReturn(claims);

        when(mockOAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn(idTokenSignatureAlgorithm);
        when(OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(idTokenSignatureAlgorithm)).
                thenThrow(new IdentityOAuth2Exception("IdentityOAuth2Exception"));

        providerConfigBuilder.buildOIDProviderConfig(mockOidProviderRequest);
    }
}
