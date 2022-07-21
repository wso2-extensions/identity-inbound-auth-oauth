/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.discovery.OIDProviderRequest;
import org.wso2.carbon.identity.discovery.internal.OIDCDiscoveryDataHolder;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;

import static org.wso2.carbon.identity.discovery.DiscoveryUtil.isUseEntityIdAsIssuerInOidcDiscovery;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_FLOW_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildServiceUrl;

/**
 * ProviderConfigBuilder builds the OIDProviderConfigResponse
 * giving the correct OprnIDConnect settings.
 * This should handle all the services to get the required data.
 */
public class ProviderConfigBuilder {

    private static final Log log = LogFactory.getLog(ProviderConfigBuilder.class);
    private static final String OIDC_CLAIM_DIALECT = "http://wso2.org/oidc/claim";

    public OIDProviderConfigResponse buildOIDProviderConfig(OIDProviderRequest request) throws
            OIDCDiscoveryEndPointException, ServerConfigurationException {
        OIDProviderConfigResponse providerConfig = new OIDProviderConfigResponse();
        String tenantDomain = request.getTenantDomain();
        if (isUseEntityIdAsIssuerInOidcDiscovery()) {
            try {
                providerConfig.setIssuer(OAuth2Util.getIdTokenIssuer(tenantDomain));
            } catch (IdentityOAuth2Exception e) {
                throw new ServerConfigurationException(String.format("Error while retrieving OIDC Id token issuer " +
                        "value for tenant domain: %s", tenantDomain), e);
            }
        } else {
            providerConfig.setIssuer(OAuth2Util.getIDTokenIssuer());
        }
        providerConfig.setAuthorizationEndpoint(OAuth2Util.OAuthURL.getOAuth2AuthzEPUrl());
        providerConfig.setTokenEndpoint(OAuth2Util.OAuthURL.getOAuth2TokenEPUrl());
        providerConfig.setUserinfoEndpoint(OAuth2Util.OAuthURL.getOAuth2UserInfoEPUrl());
        providerConfig.setRevocationEndpoint(OAuth2Util.OAuthURL.getOAuth2RevocationEPUrl());
        providerConfig.setRevocationEndpointAuthMethodsSupported(OAuth2Util.getSupportedClientAuthenticationMethods()
                .toArray(new String[0]));
        providerConfig.setResponseModesSupported(OAuth2Util.getSupportedResponseModes().toArray(new String[0]));
        providerConfig.setIntrospectionEndpointAuthMethodsSupported(OAuth2Util.getSupportedClientAuthenticationMethods()
                .toArray(new String[0]));
        providerConfig.setCodeChallengeMethodsSupported(OAuth2Util.getSupportedCodeChallengeMethods()
                .toArray(new String[0]));
        try {
            providerConfig.setIntrospectionEndpoint(OAuth2Util.OAuthURL.getOAuth2IntrospectionEPUrl(tenantDomain));
            providerConfig.setRegistrationEndpoint(OAuth2Util.OAuthURL.getOAuth2DCREPUrl(tenantDomain));
            providerConfig.setJwksUri(OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(tenantDomain));
        } catch (URISyntaxException e) {
            throw new ServerConfigurationException("Error while building tenant specific url", e);
        }
        List<String> scopes = OAuth2Util.getOIDCScopes(tenantDomain);
        providerConfig.setScopesSupported(scopes.toArray(new String[scopes.size()]));
        try {
            List<ExternalClaim> claims = OIDCDiscoveryDataHolder.getInstance().getClaimManagementService()
                    .getExternalClaims(OIDC_CLAIM_DIALECT, tenantDomain);
            String[] claimArray = new String[claims.size() + 2];
            int i;
            for (i = 0; i < claims.size(); i++) {
                claimArray[i] = claims.get(i).getClaimURI();
            }
            claimArray[i++] = "iss";
            claimArray[i] = "acr";
            providerConfig.setClaimsSupported(claimArray);
        } catch (ClaimMetadataException e) {
            throw new ServerConfigurationException("Error while retrieving OIDC claim dialect", e);
        }
        try {
            providerConfig.setIdTokenSigningAlgValuesSupported(new String[]{
                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm
                        (OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm()).getName()});
        } catch (IdentityOAuth2Exception e) {
            throw new ServerConfigurationException("Unsupported signature algorithm configured.", e);
        }

        Set<String> supportedResponseTypeNames = OAuthServerConfiguration.getInstance().getSupportedResponseTypeNames();
        providerConfig.setResponseTypesSupported(supportedResponseTypeNames.toArray(new
                String[supportedResponseTypeNames.size()]));

        providerConfig.setSubjectTypesSupported(new String[]{"public"});

        providerConfig.setCheckSessionIframe(buildServiceUrl(IdentityConstants.OAuth.CHECK_SESSION,
                IdentityUtil.getProperty(IdentityConstants.OAuth.OIDC_CHECK_SESSION_EP_URL)));
        providerConfig.setEndSessionEndpoint(buildServiceUrl(IdentityConstants.OAuth.LOGOUT,
                IdentityUtil.getProperty(IdentityConstants.OAuth.OIDC_LOGOUT_EP_URL)));

        try {
            providerConfig.setUserinfoSigningAlgValuesSupported(new String[] {
                    OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                            OAuthServerConfiguration.getInstance().getUserInfoJWTSignatureAlgorithm()).getName()
            });
        } catch (IdentityOAuth2Exception e) {
            throw new ServerConfigurationException("Unsupported signature algorithm configured.", e);
        }
        providerConfig.setTokenEndpointAuthMethodsSupported(
                OAuth2Util.getSupportedClientAuthenticationMethods().stream().toArray(String[]::new));
        providerConfig.setGrantTypesSupported(OAuth2Util.getSupportedGrantTypes().stream().toArray(String[]::new));
        providerConfig.setRequestParameterSupported(Boolean.valueOf(OAuth2Util.isRequestParameterSupported()));
        providerConfig.setClaimsParameterSupported(Boolean.valueOf(OAuth2Util.isClaimsParameterSupported()));
        providerConfig.setRequestObjectSigningAlgValuesSupported(
                OAuth2Util.getRequestObjectSigningAlgValuesSupported().stream().toArray(String[]::new));

        providerConfig.setBackchannelLogoutSupported(Boolean.TRUE);
        providerConfig.setBackchannelLogoutSessionSupported(Boolean.TRUE);

        if (OAuth2Util.getSupportedGrantTypes().contains(DEVICE_FLOW_GRANT_TYPE)) {
            providerConfig.setDeviceAuthorizationEndpoint(OAuth2Util.OAuthURL.getDeviceAuthzEPUrl());
        }
        return providerConfig;
    }
}
