/*
 * Copyright (c) 2016-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.discovery;


import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * OIDProviderConfigResponse contains the patameters to be written
 * as specified in the spec at https://openid.net/specs/openid-connect-discovery-1_0.html
 * Values are corresponding to the entries specified in the DicoveryConstants class.
 */
public class OIDProviderConfigResponse {

    private String issuer;
    private String authorizationEndpoint;
    private String pushedAuthorizationRequestEndpoint;
    private String tokenEndpoint;
    private String userinfoEndpoint;
    private String revocationEndpoint;
    private String introspectionEndpoint;
    private String jwksUri;
    private String registrationEndpoint;
    private String[] scopesSupported;
    private String[] responseTypesSupported;
    private String[] responseModesSupported;
    private String[] grantTypesSupported;
    private String[] acrValuesSupported;
    private String[] subjectTypesSupported;
    private String[] idTokenSigningAlgValuesSupported;
    private String[] idTokenEncryptionAlgValuesSupported;
    private String[] idTokenEncryptionEncValuesSupported;
    private String[] userinfoSigningAlgValuesSupported;
    private String[] userinfoEncryptionAlgValuesSupported;
    private String[] userinfoEncryptionEncValuesSupported;
    private String[] requestObjectSigningAlgValuesSupported;
    private String[] requestObjectEncryptionAlgValuesSupported;
    private String[] requestObjectEncryptionEncValuesSupported;
    private String[] revocationEndpointAuthMethodsSupported;
    private String[] revocationEndpointAuthSigningAlgValuesSupported;
    private String[] introspectionEndpointAuthMethodsSupported;
    private String[] introspectionEndpointAuthSigningAlgValuesSupported;
    private String[] tokenEndpointAuthMethodsSupported;
    private String[] tokenEndpointAuthSigningAlgValuesSupported;
    private String[] displayValuesSupported;
    private String[] claimTypesSupported;
    private String[] claimsSupported;
    private String serviceDocumentation;
    private String[] claimsLocalesSupported;
    private String[] uiLocalesSupported;
    private String claimsParameterSupported;
    private String requestParameterSupported;
    private Boolean isClaimsParameterSupported;
    private Boolean isRequestParameterSupported;
    private String requestUriParameterSupported;
    private String requireRequestUriRegistration;
    private String opPolicyUri;
    private String opTosUri;
    private String checkSessionIframe;
    private String endSessionEndpoint;
    private Boolean backchannelLogoutSupported;
    private Boolean backchannelLogoutSessionSupported;
    private String[] codeChallengeMethodsSupported;
    private String deviceAuthorizationEndpoint;
    private String webFingerEndpoint;
    private Boolean tlsClientCertificateBoundAccessTokens;
    private String mtlsTokenEndpoint;
    private String mtlsPushedAuthorizationRequestEndpoint;
    private String[] authorizationDetailsTypesSupported;
    private String[] supportedDPoPSigningAlgorithms;

    private static final String MUTUAL_TLS_ALIASES_ENABLED = "OAuth.MutualTLSAliases.Enabled";

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getPushedAuthorizationRequestEndpoint() {

        return pushedAuthorizationRequestEndpoint;
    }

    public void setPushedAuthorizationRequestEndpoint(String pushedAuthorizationRequestEndpoint) {

        this.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public String getRevocationEndpoint() {

        return revocationEndpoint;
    }

    public void setRevocationEndpoint(String revocationEndpoint) {

        this.revocationEndpoint = revocationEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String[] getScopesSupported() {
        return scopesSupported;
    }

    public void setScopesSupported(String[] scopesSupported) {
        this.scopesSupported = scopesSupported;
    }

    public String[] getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public void setResponseTypesSupported(String[] responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    public String[] getResponseModesSupported() {
        return responseModesSupported;
    }

    public void setResponseModesSupported(String[] responseModesSupported) {
        this.responseModesSupported = responseModesSupported;
    }

    public String[] getGrantTypesSupported() {
        return grantTypesSupported;
    }

    public void setGrantTypesSupported(String[] grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
    }

    public String[] getAcrValuesSupported() {
        return acrValuesSupported;
    }

    public void setAcrValuesSupported(String[] acrValuesSupported) {
        this.acrValuesSupported = acrValuesSupported;
    }

    public String[] getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public void setSubjectTypesSupported(String[] subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    public String[] getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    public void setIdTokenSigningAlgValuesSupported(String[] idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
    }

    public String[] getIdTokenEncryptionAlgValuesSupported() {
        return idTokenEncryptionAlgValuesSupported;
    }

    public void setIdTokenEncryptionAlgValuesSupported(String[] idTokenEncryptionAlgValuesSupported) {
        this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
    }

    public String[] getIdTokenEncryptionEncValuesSupported() {
        return idTokenEncryptionEncValuesSupported;
    }

    public void setIdTokenEncryptionEncValuesSupported(String[] idTokenEncryptionEncValuesSupported) {
        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
    }

    public String[] getUserinfoSigningAlgValuesSupported() {
        return userinfoSigningAlgValuesSupported;
    }

    public void setUserinfoSigningAlgValuesSupported(String[] userinfoSigningAlgValuesSupported) {
        this.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
    }

    public String[] getUserinfoEncryptionAlgValuesSupported() {
        return userinfoEncryptionAlgValuesSupported;
    }

    public void setUserinfoEncryptionAlgValuesSupported(String[] userinfoEncryptionAlgValuesSupported) {
        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
    }

    public String[] getUserinfoEncryptionEncValuesSupported() {
        return userinfoEncryptionEncValuesSupported;
    }

    public void setUserinfoEncryptionEncValuesSupported(String[] userinfoEncryptionEncValuesSupported) {
        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
    }

    public String[] getRequestObjectSigningAlgValuesSupported() {
        return requestObjectSigningAlgValuesSupported;
    }

    public void setRequestObjectSigningAlgValuesSupported(String[] requestObjectSigningAlgValuesSupported) {
        this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
    }

    public String[] getRequestObjectEncryptionAlgValuesSupported() {
        return requestObjectEncryptionAlgValuesSupported;
    }

    public void setRequestObjectEncryptionAlgValuesSupported(String[]
                                                                     requestObjectEncryptionAlgValuesSupported) {
        this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
    }

    public String[] getRequestObjectEncryptionEncValuesSupported() {
        return requestObjectEncryptionEncValuesSupported;
    }

    public void setRequestObjectEncryptionEncValuesSupported(String[]
                                                                     requestObjectEncryptionEncValuesSupported) {
        this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
    }

    public String[] getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public void setTokenEndpointAuthMethodsSupported(String[] tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    public String[] getTokenEndpointAuthSigningAlgValuesSupported() {
        return tokenEndpointAuthSigningAlgValuesSupported;
    }

    public void setTokenEndpointAuthSigningAlgValuesSupported(String[]
                                                                      tokenEndpointAuthSigningAlgValuesSupported) {
        this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
    }

    public String[] getDisplayValuesSupported() {
        return displayValuesSupported;
    }

    public void setDisplayValuesSupported(String[] displayValuesSupported) {
        this.displayValuesSupported = displayValuesSupported;
    }

    public String[] getClaimTypesSupported() {
        return claimTypesSupported;
    }

    public void setClaimTypesSupported(String[] claimTypesSupported) {
        this.claimTypesSupported = claimTypesSupported;
    }

    public String[] getClaimsSupported() {
        return claimsSupported;
    }

    public void setClaimsSupported(String[] claimsSupported) {
        this.claimsSupported = claimsSupported;
    }

    public String getServiceDocumentation() {
        return serviceDocumentation;
    }

    public void setServiceDocumentation(String serviceDocumentation) {
        this.serviceDocumentation = serviceDocumentation;
    }

    public String[] getClaimsLocalesSupported() {
        return claimsLocalesSupported;
    }

    public void setClaimsLocalesSupported(String[] claimsLocalesSupported) {
        this.claimsLocalesSupported = claimsLocalesSupported;
    }

    public String[] getUiLocalesSupported() {
        return uiLocalesSupported;
    }

    public void setUiLocalesSupported(String[] uiLocalesSupported) {
        this.uiLocalesSupported = uiLocalesSupported;
    }

    @Deprecated
    public String getClaimsParameterSupported() {
        return claimsParameterSupported;
    }

    @Deprecated
    public void setClaimsParameterSupported(String claimsParameterSupported) {
        this.claimsParameterSupported = claimsParameterSupported;
    }

    @Deprecated
    public String getRequestParameterSupported() {
        return requestParameterSupported;
    }

    @Deprecated
    public void setRequestParameterSupported(String requestParameterSupported) {
        this.requestParameterSupported = requestParameterSupported;
    }

    public Boolean isClaimsParameterSupported() {
        return isClaimsParameterSupported;
    }

    public void setClaimsParameterSupported(Boolean isClaimsParameterSupported) {
        this.isClaimsParameterSupported = isClaimsParameterSupported;
    }

    public Boolean isRequestParameterSupported() {
        return isRequestParameterSupported;
    }

    public void setRequestParameterSupported(Boolean isRequestParameterSupported) {
        this.isRequestParameterSupported = isRequestParameterSupported;
    }

    public String getRequestUriParameterSupported() {
        return requestUriParameterSupported;
    }

    public void setRequestUriParameterSupported(String requestUriParameterSupported) {
        this.requestUriParameterSupported = requestUriParameterSupported;
    }

    public String getRequireRequestUriRegistration() {
        return requireRequestUriRegistration;
    }

    public void setRequireRequestUriRegistration(String requireRequestUriRegistration) {
        this.requireRequestUriRegistration = requireRequestUriRegistration;
    }

    public String getOpPolicyUri() {
        return opPolicyUri;
    }

    public void setOpPolicyUri(String opPolicyUri) {
        this.opPolicyUri = opPolicyUri;
    }

    public String getOpTosUri() {
        return opTosUri;
    }

    public void setOpTosUri(String opTosUri) {
        this.opTosUri = opTosUri;
    }

    public String getCheckSessionIframe() {
        return checkSessionIframe;
    }

    public void setCheckSessionIframe(String checkSessionIframe) {
        this.checkSessionIframe = checkSessionIframe;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public void setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    public void setBackchannelLogoutSupported(Boolean backchannelLogoutSupported) {
        this.backchannelLogoutSupported = backchannelLogoutSupported;
    }

    public void setBackchannelLogoutSessionSupported(Boolean backchannelLogoutSessionSupported) {
        this.backchannelLogoutSessionSupported = backchannelLogoutSessionSupported;
    }

    public String getIntrospectionEndpoint() {

        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String introspectionEndpoint) {

        this.introspectionEndpoint = introspectionEndpoint;
    }

    public String[] getRevocationEndpointAuthMethodsSupported() {

        return revocationEndpointAuthMethodsSupported;
    }

    public void setRevocationEndpointAuthMethodsSupported(String[] revocationEndpointAuthMethodsSupported) {

        this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
    }

    public String[] getRevocationEndpointAuthSigningAlgValuesSupported() {

        return revocationEndpointAuthSigningAlgValuesSupported;
    }

    public void setRevocationEndpointAuthSigningAlgValuesSupported(
            String[] revocationEndpointAuthSigningAlgValuesSupported) {

        this.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported;
    }

    public String[] getIntrospectionEndpointAuthMethodsSupported() {

        return introspectionEndpointAuthMethodsSupported;
    }

    public void setIntrospectionEndpointAuthMethodsSupported(String[] introspectionEndpointAuthMethodsSupported) {

        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
    }

    public String[] getIntrospectionEndpointAuthSigningAlgValuesSupported() {

        return introspectionEndpointAuthSigningAlgValuesSupported;
    }

    public void setIntrospectionEndpointAuthSigningAlgValuesSupported(
            String[] introspectionEndpointAuthSigningAlgValuesSupported) {

        this.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported;
    }

    public String[] getCodeChallengeMethodsSupported() {

        return codeChallengeMethodsSupported;
    }

    public void setCodeChallengeMethodsSupported(String[] codeChallengeMethodsSupported) {

        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
    }

    public String getDeviceAuthorizationEndpoint() {

        return deviceAuthorizationEndpoint;
    }

    public void setDeviceAuthorizationEndpoint(String deviceAuthorizationEndpoint) {

        this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
    }

    public String getWebFingerEndpoint() {
        return webFingerEndpoint;
    }

    public void setWebFingerEndpoint(String webFingerEndpoint) {
        this.webFingerEndpoint = webFingerEndpoint;
    }

    public void setTlsClientCertificateBoundAccessTokens(Boolean tlsClientCertificateBoundAccessTokens) {

        this.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens;
    }

    public void setMtlsTokenEndpoint(String mtlsTokenEndpoint) {

        this.mtlsTokenEndpoint = mtlsTokenEndpoint;
    }

    public void setMtlsPushedAuthorizationRequestEndpoint(String mtlsPushedAuthorizationRequestEndpoint) {

        this.mtlsPushedAuthorizationRequestEndpoint = mtlsPushedAuthorizationRequestEndpoint;
    }

    public String[] getAuthorizationDetailsTypesSupported() {

        return this.authorizationDetailsTypesSupported;
    }

    public void setAuthorizationDetailsTypesSupported(String[] authorizationDetailsTypesSupported) {

        this.authorizationDetailsTypesSupported = authorizationDetailsTypesSupported;
    }

    public void setDPoPSupportedSigningAlgorithms(String[] supportedDPoPSigningAlgorithms) {

        this.supportedDPoPSigningAlgorithms = supportedDPoPSigningAlgorithms;
    }

    public Map<String, Object> getConfigMap() {
        Map<String, Object> configMap = new HashMap<String, Object>();
        configMap.put(DiscoveryConstants.ISSUER.toLowerCase(), this.issuer);
        configMap.put(DiscoveryConstants.ACR_VALUES_SUPPORTED.toLowerCase(), this.acrValuesSupported);
        configMap.put(DiscoveryConstants.AUTHORIZATION_ENDPOINT.toLowerCase(), this.authorizationEndpoint);
        configMap.put(DiscoveryConstants.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT.toLowerCase(),
                this.pushedAuthorizationRequestEndpoint);
        configMap.put(DiscoveryConstants.CLAIM_TYPES_SUPPORTED.toLowerCase(), this.claimTypesSupported);
        configMap.put(DiscoveryConstants.CLAIMS_LOCALES_SUPPORTED.toLowerCase(), this.claimsLocalesSupported);
        configMap.put(DiscoveryConstants.CLAIMS_PARAMETER_SUPPORTED.toLowerCase(), this.isClaimsParameterSupported);
        configMap.put(DiscoveryConstants.CLAIMS_SUPPORTED.toLowerCase(), this.claimsSupported);
        configMap.put(DiscoveryConstants.DISPLAY_VALUES_SUPPORTED.toLowerCase(), this.displayValuesSupported);
        configMap.put(DiscoveryConstants.GRANT_TYPES_SUPPORTED.toLowerCase(), this.grantTypesSupported);
        configMap.put(DiscoveryConstants.ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .idTokenEncryptionAlgValuesSupported);
        configMap.put(DiscoveryConstants.ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED.toLowerCase(), this
                .idTokenEncryptionEncValuesSupported);
        configMap.put(DiscoveryConstants.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .idTokenSigningAlgValuesSupported);
        configMap.put(DiscoveryConstants.JWKS_URI.toLowerCase(), this.jwksUri);
        configMap.put(DiscoveryConstants.OP_POLICY_URI.toLowerCase(), this.opPolicyUri);
        configMap.put(DiscoveryConstants.OP_TOS_URI.toLowerCase(), this.opTosUri);
        configMap.put(DiscoveryConstants.REGISTRATION_ENDPOINT.toLowerCase(), this.registrationEndpoint);
        configMap.put(DiscoveryConstants.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .requestObjectEncryptionAlgValuesSupported);
        configMap.put(DiscoveryConstants.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED.toLowerCase(), this
                .requestObjectEncryptionEncValuesSupported);
        configMap.put(DiscoveryConstants.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .requestObjectSigningAlgValuesSupported);
        configMap.put(DiscoveryConstants.REQUEST_PARAMETER_SUPPORTED.toLowerCase(), this.isRequestParameterSupported);
        configMap.put(DiscoveryConstants.REQUEST_URI_PARAMETER_SUPPORTED.toLowerCase(), this
                .requestUriParameterSupported);
        configMap.put(DiscoveryConstants.REQUIRE_REQUEST_URI_REGISTRATION.toLowerCase(), this
                .requireRequestUriRegistration);
        configMap.put(DiscoveryConstants.RESPONSE_MODES_SUPPORTED.toLowerCase(), this.responseModesSupported);
        configMap.put(DiscoveryConstants.RESPONSE_TYPES_SUPPORTED.toLowerCase(), this.responseTypesSupported);
        configMap.put(DiscoveryConstants.SCOPES_SUPPORTED.toLowerCase(), this.scopesSupported);
        configMap.put(DiscoveryConstants.SERVICE_DOCUMENTATION.toLowerCase(), this.serviceDocumentation);
        configMap.put(DiscoveryConstants.SUBJECT_TYPES_SUPPORTED.toLowerCase(), this.subjectTypesSupported);
        configMap.put(DiscoveryConstants.TOKEN_ENDPOINT.toLowerCase(), this.tokenEndpoint);
        configMap.put(DiscoveryConstants.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED.toLowerCase(), this
                .tokenEndpointAuthMethodsSupported);
        configMap.put(DiscoveryConstants.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .tokenEndpointAuthSigningAlgValuesSupported);
        configMap.put(DiscoveryConstants.UI_LOCALES_SUPPORTED.toLowerCase(), this.uiLocalesSupported);
        configMap.put(DiscoveryConstants.USERINFO_ENCRYPTION_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .userinfoEncryptionAlgValuesSupported);
        configMap.put(DiscoveryConstants.USERINFO_ENCRYPTION_ENC_VALUES_SUPPORTED.toLowerCase(), this
                .userinfoEncryptionEncValuesSupported);
        configMap.put(DiscoveryConstants.USERINFO_ENDPOINT.toLowerCase(), this.userinfoEndpoint);
        configMap.put(DiscoveryConstants.REVOCATION_ENDPOINT.toLowerCase(), this.revocationEndpoint);
        configMap.put(DiscoveryConstants.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED.toLowerCase(), this
                .revocationEndpointAuthMethodsSupported);
        configMap.put(DiscoveryConstants.INTROSPECTION_ENDPOINT.toLowerCase(), this.introspectionEndpoint);
        configMap.put(DiscoveryConstants.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED.toLowerCase(), this
                .introspectionEndpointAuthMethodsSupported);
        configMap.put(DiscoveryConstants.CHECK_SESSION_IFRAME.toLowerCase(), this.checkSessionIframe);
        configMap.put(DiscoveryConstants.END_SESSION_ENDPOINT.toLowerCase(), this.endSessionEndpoint);
        configMap.put(DiscoveryConstants.USERINFO_SIGNING_ALG_VALUES_SUPPORTED.toLowerCase(), this
                .userinfoSigningAlgValuesSupported);
        configMap.put(DiscoveryConstants.BACKCHANNEL_LOGOUT_SUPPORTED, this.backchannelLogoutSupported);
        configMap.put(DiscoveryConstants.BACKCHANNEL_LOGOUT_SESSION_SUPPORTED, this.backchannelLogoutSessionSupported);
        configMap.put(DiscoveryConstants.CODE_CHALLENGE_METHODS_SUPPORTED, this.codeChallengeMethodsSupported);
        configMap.put(DiscoveryConstants.DEVICE_AUTHORIZATION_ENDPOINT, this.deviceAuthorizationEndpoint);
        configMap.put(DiscoveryConstants.WEBFINGER_ENDPOINT.toLowerCase(), this.webFingerEndpoint);
        configMap.put(DiscoveryConstants.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKEN.toLowerCase(),
                this.tlsClientCertificateBoundAccessTokens);
        if (DiscoveryUtil.isDPoPEnabled()) {
            configMap.put(DiscoveryConstants.DPOP_SIGNING_ALGORITHMS_SUPPORTED, this.supportedDPoPSigningAlgorithms);
        }
        if (Boolean.parseBoolean(IdentityUtil.getProperty(MUTUAL_TLS_ALIASES_ENABLED))) {
            Map<String, String> mtlsAliases = new HashMap<String, String>();
            mtlsAliases.put(DiscoveryConstants.TOKEN_ENDPOINT.toLowerCase(), this.mtlsTokenEndpoint);
            mtlsAliases.put(DiscoveryConstants.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT.toLowerCase(),
                    this.mtlsPushedAuthorizationRequestEndpoint);
            configMap.put(DiscoveryConstants.MTLS_ENDPOINT_ALIASES, mtlsAliases);
        }
        configMap.put(DiscoveryConstants.AUTHORIZATION_DETAILS_TYPES_SUPPORTED,
                this.authorizationDetailsTypesSupported);
        return configMap;
    }
}
