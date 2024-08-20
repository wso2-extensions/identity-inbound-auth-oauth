/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.apache.axis2.databinding.annotation.IgnoreNullElement;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolConfigurationDTO;

import java.util.List;
import java.util.Map;


import javax.xml.bind.annotation.XmlTransient;

/**
 * OAuth consumer app dto.
 */
public class OAuthConsumerAppDTO implements InboundProtocolConfigurationDTO {

    private String oauthConsumerKey;
    private String oauthConsumerSecret;
    private String applicationName;
    private String callbackUrl;
    private String oauthVersion;
    private String username;
    private String grantTypes = "";
    private String[] scopeValidators = null;
    private boolean pkceSupportPlain;
    private boolean pkceMandatory;
    private boolean hybridFlowEnabled;
    private String hybridFlowResponseType;
    private String state;
    private long userAccessTokenExpiryTime;
    private long applicationAccessTokenExpiryTime;
    private long refreshTokenExpiryTime;
    private String[] audiences;
    private boolean bypassClientCredentials;
    private String renewRefreshTokenEnabled;
    // OIDC related properties
    private boolean isRequestObjectSignatureValidationEnabled;
    private boolean isIdTokenEncryptionEnabled;
    private String idTokenEncryptionAlgorithm;
    private String idTokenEncryptionMethod;
    private String backChannelLogoutUrl;
    private String frontchannelLogoutUrl;
    private long idTokenExpiryTime;
    private String tokenType;
    private String tokenBindingType;
    private boolean tokenRevocationWithIDPSessionTerminationEnabled;
    private boolean tokenBindingValidationEnabled;
    private Boolean useClientIdAsSubClaimForAppTokens;
    private Boolean omitUsernameInIntrospectionRespForAppTokens;
    private String tokenEndpointAuthMethod;
    private String tokenEndpointAuthSignatureAlgorithm;
    private Boolean tokenEndpointAllowReusePvtKeyJwt;
    private String sectorIdentifierURI;
    private String idTokenSignatureAlgorithm;
    private String requestObjectSignatureAlgorithm;
    private String tlsClientAuthSubjectDN;
    private boolean requirePushedAuthorizationRequests;
    private String subjectType;
    private String requestObjectEncryptionAlgorithm;
    private String requestObjectEncryptionMethod;
    private String jwksURI;
    private boolean fapiConformanceEnabled;
    private boolean subjectTokenEnabled;
    private int subjectTokenExpiryTime;
    private String[] accessTokenClaims;
    private boolean accessTokenClaimsSeparationEnabled;

    // CORS origin related properties. This will be used by the CORS management service
    @IgnoreNullElement
    @XmlTransient
    @JsonIgnore
    private List<String> allowedOrigins = null;
    
    // This will be used to store data for audit logs. This will not be persisted in the database.
    @IgnoreNullElement
    @XmlTransient
    @JsonIgnore
    private Map<String, Object> auditLogData;

    public String getJwksURI() {

        return jwksURI;
    }
    public void setJwksURI(String jwksURi) {

        this.jwksURI = jwksURi;
    }
    public long getUserAccessTokenExpiryTime() {
        return userAccessTokenExpiryTime;
    }

    public void setUserAccessTokenExpiryTime(long userAccessTokenExpiryTime) {
        this.userAccessTokenExpiryTime = userAccessTokenExpiryTime;
    }

    public long getApplicationAccessTokenExpiryTime() {
        return applicationAccessTokenExpiryTime;
    }

    public void setApplicationAccessTokenExpiryTime(long applicationAccessTokenExpiryTime) {
        this.applicationAccessTokenExpiryTime = applicationAccessTokenExpiryTime;
    }

    public long getRefreshTokenExpiryTime() {
        return refreshTokenExpiryTime;
    }

    public void setRefreshTokenExpiryTime(long refreshTokenExpiryTime) {
        this.refreshTokenExpiryTime = refreshTokenExpiryTime;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public String getOauthConsumerKey() {
        return oauthConsumerKey;
    }

    public void setOauthConsumerKey(String oauthConsumerKey) {
        this.oauthConsumerKey = oauthConsumerKey;
    }

    public String getOauthConsumerSecret() {
        return oauthConsumerSecret;
    }

    public void setOauthConsumerSecret(String oauthConsumerSecret) {
        this.oauthConsumerSecret = oauthConsumerSecret;
    }

    public String getOAuthVersion() {
        return oauthVersion;
    }

    public void setOAuthVersion(String oAuthVersion) {
        this.oauthVersion = oAuthVersion;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(String grantTypes) {

        if (grantTypes != null) {
            this.grantTypes = grantTypes;
        }
    }

    public String[] getScopeValidators() {
        return scopeValidators;
    }

    public void setScopeValidators(String[] scopeValidators) {
        this.scopeValidators = scopeValidators;
    }

    public boolean getPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public boolean getPkceMandatory() {
        return pkceMandatory;
    }

    public void setPkceMandatory(boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
    }

    public boolean isHybridFlowEnabled() {
        return hybridFlowEnabled;
    }

    public void setHybridFlowEnabled(boolean hybridFlowEnabled) {
        this.hybridFlowEnabled = hybridFlowEnabled;
    }

    public String getHybridFlowResponseType() {
        return hybridFlowResponseType;
    }

    public void setHybridFlowResponseType(String hybridFlowResponseType) {
        this.hybridFlowResponseType = hybridFlowResponseType;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getState() {
        return state;
    }

    public String[] getAudiences() {
        return audiences;
    }

    public void setAudiences(String[] audiences) {

        if (audiences != null) {
            this.audiences = audiences;
        }
    }

    public boolean isRequestObjectSignatureValidationEnabled() {
        return isRequestObjectSignatureValidationEnabled;
    }

    public void setRequestObjectSignatureValidationEnabled(boolean requestObjectSignatureValidationEnabled) {
        this.isRequestObjectSignatureValidationEnabled = requestObjectSignatureValidationEnabled;
    }

    public boolean isIdTokenEncryptionEnabled() {
        return isIdTokenEncryptionEnabled;
    }

    public String getIdTokenEncryptionAlgorithm() {
        return idTokenEncryptionAlgorithm;
    }

    public String getIdTokenEncryptionMethod() {
        return idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionAlgorithm(String idTokenEncryptionAlgorithm) {
        this.idTokenEncryptionAlgorithm = idTokenEncryptionAlgorithm;
    }

    public void setIdTokenEncryptionMethod(String idTokenEncryptionMethod) {
        this.idTokenEncryptionMethod = idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionEnabled(boolean idTokenEncryptionEnabled) {
        this.isIdTokenEncryptionEnabled = idTokenEncryptionEnabled;
    }

    public void setBackChannelLogoutUrl(String backChannelLogoutUrl) {
        this.backChannelLogoutUrl = backChannelLogoutUrl;
    }

    public String getBackChannelLogoutUrl() {
        return backChannelLogoutUrl;
    }

    public String getFrontchannelLogoutUrl() {
        return frontchannelLogoutUrl;
    }

    public void setFrontchannelLogoutUrl(String frontchannelLogoutUrl) {
        this.frontchannelLogoutUrl = frontchannelLogoutUrl;
    }

    public long getIdTokenExpiryTime() {

        return idTokenExpiryTime;
    }

    public void setIdTokenExpiryTime(long idTokenExpiryTime) {
        this.idTokenExpiryTime = idTokenExpiryTime;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isBypassClientCredentials() {
        return bypassClientCredentials;
    }

    /**
     * This method is deprecated. Use the 'isBypassClientCredentials' method instead.
     */
    @Deprecated
    public boolean getBypassClientCredentials() {
        return bypassClientCredentials;
    }

    public void setBypassClientCredentials(boolean isPublicClient) {
        this.bypassClientCredentials = isPublicClient;
    }

    public void setRenewRefreshTokenEnabled(String renewRefreshTokenEnabled) {

        this.renewRefreshTokenEnabled = renewRefreshTokenEnabled;
    }

    public String getRenewRefreshTokenEnabled() {

        return renewRefreshTokenEnabled;
    }

    public String getTokenBindingType() {

        return tokenBindingType;
    }

    public void setTokenBindingType(String tokenBindingType) {

        this.tokenBindingType = tokenBindingType;
    }

    public boolean isTokenRevocationWithIDPSessionTerminationEnabled() {

        return tokenRevocationWithIDPSessionTerminationEnabled;
    }

    public void setTokenRevocationWithIDPSessionTerminationEnabled(
            boolean tokenRevocationWithIDPSessionTerminationEnabled) {

        this.tokenRevocationWithIDPSessionTerminationEnabled = tokenRevocationWithIDPSessionTerminationEnabled;
    }

    public boolean isTokenBindingValidationEnabled() {

        return tokenBindingValidationEnabled;
    }

    public void setTokenBindingValidationEnabled(boolean tokenBindingValidationEnabled) {

        this.tokenBindingValidationEnabled = tokenBindingValidationEnabled;
    }

    public Boolean isUseClientIdAsSubClaimForAppTokens() {

        return useClientIdAsSubClaimForAppTokens;
    }

    public void setUseClientIdAsSubClaimForAppTokens(Boolean useClientIdAsSubClaimForAppTokens) {

        this.useClientIdAsSubClaimForAppTokens = useClientIdAsSubClaimForAppTokens;
    }

    public Boolean isOmitUsernameInIntrospectionRespForAppTokens() {

        return omitUsernameInIntrospectionRespForAppTokens;
    }

    public void setOmitUsernameInIntrospectionRespForAppTokens(Boolean omitUsernameInIntrospectionRespForAppTokens) {

        this.omitUsernameInIntrospectionRespForAppTokens = omitUsernameInIntrospectionRespForAppTokens;
    }

    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {

        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getTokenEndpointAuthSignatureAlgorithm() {

        return tokenEndpointAuthSignatureAlgorithm;
    }

    public void setTokenEndpointAuthSignatureAlgorithm(String tokenEndpointAuthSignatureAlgorithm) {

        this.tokenEndpointAuthSignatureAlgorithm = tokenEndpointAuthSignatureAlgorithm;
    }

    public Boolean isTokenEndpointAllowReusePvtKeyJwt() {

        return tokenEndpointAllowReusePvtKeyJwt;
    }

    public void setTokenEndpointAllowReusePvtKeyJwt(Boolean tokenEndpointAllowReusePvtKeyJwt) {

        this.tokenEndpointAllowReusePvtKeyJwt = tokenEndpointAllowReusePvtKeyJwt;
    }

    public String getSectorIdentifierURI() {

        return sectorIdentifierURI;
    }

    public void setSectorIdentifierURI(String sectorIdentifierURI) {

        this.sectorIdentifierURI = sectorIdentifierURI;
    }
    public String getRequestObjectSignatureAlgorithm() {

        return requestObjectSignatureAlgorithm;
    }

    public void setRequestObjectSignatureAlgorithm(String requestObjectSignatureAlgorithm) {

        this.requestObjectSignatureAlgorithm = requestObjectSignatureAlgorithm;
    }

    public String getTlsClientAuthSubjectDN() {

        return tlsClientAuthSubjectDN;
    }

    public void setTlsClientAuthSubjectDN(String tlsClientAuthSubjectDN) {

        this.tlsClientAuthSubjectDN = tlsClientAuthSubjectDN;
    }

    public boolean getRequirePushedAuthorizationRequests() {

        return requirePushedAuthorizationRequests;
    }

    public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {

        this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
    }

    public String getSubjectType() {

        return subjectType;
    }

    public void setSubjectType(String subjectType) {

        this.subjectType = subjectType;
    }

    public String getRequestObjectEncryptionAlgorithm() {

        return requestObjectEncryptionAlgorithm;
    }

    public void setRequestObjectEncryptionAlgorithm(String requestObjectEncryptionAlgorithm) {

        this.requestObjectEncryptionAlgorithm = requestObjectEncryptionAlgorithm;
    }

    public String getRequestObjectEncryptionMethod() {

        return requestObjectEncryptionMethod;
    }

    public void setRequestObjectEncryptionMethod(String requestObjectEncryptionMethod) {

        this.requestObjectEncryptionMethod = requestObjectEncryptionMethod;
    }
    public String getIdTokenSignatureAlgorithm() {

        return idTokenSignatureAlgorithm;
    }

    public void setIdTokenSignatureAlgorithm(String idTokenSignatureAlgorithm) {

        this.idTokenSignatureAlgorithm = idTokenSignatureAlgorithm;
    }

    public boolean isFapiConformanceEnabled() {

        return fapiConformanceEnabled;
    }

    public void setFapiConformanceEnabled(boolean fapiConformant) {

        fapiConformanceEnabled = fapiConformant;
    }

    @Override
    public String fetchProtocolName() {

        return FrameworkConstants.StandardInboundProtocols.OAUTH2;
    }

    public List<String> getAllowedOrigins() {
        
        return allowedOrigins;
    }
    
    public void setAllowedOrigins(List<String> allowedOrigins) {
        
        this.allowedOrigins = allowedOrigins;
    }
    
    public Map<String, Object> getAuditLogData() {
        
        return auditLogData;
    }
    
    public void setAuditLogData(Map<String, Object> auditLogData) {
        
        this.auditLogData = auditLogData;
    }

    public boolean isSubjectTokenEnabled() {

        return subjectTokenEnabled;
    }

    public void setSubjectTokenEnabled(boolean subjectTokenEnabled) {

        this.subjectTokenEnabled = subjectTokenEnabled;
    }

    public int getSubjectTokenExpiryTime() {

        return subjectTokenExpiryTime;
    }

    public void setSubjectTokenExpiryTime(int subjectTokenExpiryTime) {

        this.subjectTokenExpiryTime = subjectTokenExpiryTime;
    }

    public String[] getAccessTokenClaims() {

        return accessTokenClaims;
    }

    public void setAccessTokenClaims(String[] accessTokenClaims) {

        this.accessTokenClaims = accessTokenClaims;
    }

    public boolean isAccessTokenClaimsSeparationEnabled() {

        return accessTokenClaimsSeparationEnabled;
    }

    public void setAccessTokenClaimsSeparationEnabled(boolean accessTokenClaimsSeparationEnabled) {

        this.accessTokenClaimsSeparationEnabled = accessTokenClaimsSeparationEnabled;
    }
}

