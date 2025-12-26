/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.carbon.identity.oauth.dao;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundConfigurationProtocol;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.Serializable;
import java.util.Arrays;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;


import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.DEFAULT_BACKCHANNEL_LOGOUT_URL;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IS_FRAGMENT_APP;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.TENANT_CONTEXT_PATH_COMPONENT;

/**
 * OAuth application data object.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "oAuthAppDO")
@JsonTypeName("oAuthAppDO")
public class OAuthAppDO extends InboundConfigurationProtocol implements Serializable {

    private static final long serialVersionUID = -6453843721358989519L;

    @XmlTransient
    private int id;
    private String oauthConsumerKey;
    private String oauthConsumerSecret;
    private String applicationName;
    private String callbackUrl;
    private String oauthVersion;
    private String grantTypes;
    @XmlElementWrapper(name = "scopeValidators")
    @XmlElement(name = "scopeValidator")
    private String[] scopeValidators;
    private boolean pkceSupportPlain;
    private boolean pkceMandatory;
    private boolean hybridFlowEnabled;
    private String hybridFlowResponseType;
    private String state;
    private long userAccessTokenExpiryTime;
    private long applicationAccessTokenExpiryTime;
    private long refreshTokenExpiryTime;
    private long idTokenExpiryTime;
    @XmlElementWrapper(name = "audiences")
    @XmlElement(name = "audience")
    private String[] audiences = new String[0];
    private boolean bypassClientCredentials;
    private String renewRefreshTokenEnabled;
    private boolean extendRenewedRefreshTokenExpiryTime;
    // OIDC related properties.
    private boolean requestObjectSignatureValidationEnabled;
    private boolean idTokenEncryptionEnabled;
    private String idTokenEncryptionAlgorithm;
    private String idTokenEncryptionMethod;
    private String backChannelLogoutUrl;
    private String frontchannelLogoutUrl;
    @XmlTransient
    @JsonIgnore
    private AuthenticatedUser appOwner;
    private String tokenType;
    private String tokenBindingType;
    private boolean tokenRevocationWithIDPSessionTerminationEnabled;
    private boolean tokenBindingValidationEnabled;
    private String tokenEndpointAuthMethod;
    private Boolean tokenEndpointAllowReusePvtKeyJwt;
    private String tokenEndpointAuthSignatureAlgorithm;
    private String sectorIdentifierURI;
    private String idTokenSignatureAlgorithm;
    private String requestObjectSignatureAlgorithm;
    private String tlsClientAuthSubjectDN;
    private boolean requirePushedAuthorizationRequests;
    private boolean tlsClientCertificateBoundAccessTokens;
    private String subjectType;
    private String requestObjectEncryptionAlgorithm;
    private String requestObjectEncryptionMethod;
    private boolean fapiConformanceEnabled;
    private boolean subjectTokenEnabled;
    private int subjectTokenExpiryTime;
    private String[] accessTokenClaims;

    public AuthenticatedUser getAppOwner() {

        return appOwner;
    }
    public void setAppOwner(AuthenticatedUser appOwner) {

        this.appOwner = appOwner;
    }

    /**
     * @deprecated use {@link #getAppOwner()} instead.
     */
    @Deprecated
    @JsonIgnore
    public AuthenticatedUser getUser() {
        return this.getAppOwner();
    }

    /**
     * @deprecated use {@link #setAppOwner(AuthenticatedUser)} instead.
     */
    @Deprecated
    @JsonIgnore
    public void setUser(AuthenticatedUser user) {
        this.setAppOwner(user);
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

    public String getOauthVersion() {
        return oauthVersion;
    }

    public void setOauthVersion(String oauthVersion) {
        this.oauthVersion = oauthVersion;
    }

    public String getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(String grantTypes) {
        this.grantTypes = grantTypes;
    }

    public String[] getScopeValidators() {
        return scopeValidators;
    }

    public void setScopeValidators(String[] scopeValidators) {
        this.scopeValidators = scopeValidators;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public boolean isPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public boolean isPkceMandatory() {
        return pkceMandatory;
    }

    public boolean isHybridFlowEnabled() {
        return hybridFlowEnabled;
    }

    public void setHybridFlowEnabled(boolean hybridFlowEnabled) {
        this.hybridFlowEnabled = hybridFlowEnabled;
    }

    public void setPkceMandatory(boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
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

    public String[] getAudiences() {
        return audiences;
    }

    public void setAudiences(String[] audiences) {
        this.audiences = audiences;
    }

    public boolean isRequestObjectSignatureValidationEnabled() {
        return requestObjectSignatureValidationEnabled;
    }

    public void setRequestObjectSignatureValidationEnabled(boolean requestObjectSignatureValidationEnabled) {
        this.requestObjectSignatureValidationEnabled = requestObjectSignatureValidationEnabled;
    }

    public boolean isIdTokenEncryptionEnabled() {
        return idTokenEncryptionEnabled;
    }

    public void setIdTokenEncryptionEnabled(boolean idTokenEncryptionEnabled) {
        this.idTokenEncryptionEnabled = idTokenEncryptionEnabled;
    }

    public String getIdTokenEncryptionAlgorithm() {
        return idTokenEncryptionAlgorithm;
    }

    public void setIdTokenEncryptionAlgorithm(String idTokenEncryptionAlgorithm) {
        this.idTokenEncryptionAlgorithm = idTokenEncryptionAlgorithm;
    }

    public String getIdTokenEncryptionMethod() {
        return idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionMethod(String idTokenEncryptionMethod) {
        this.idTokenEncryptionMethod = idTokenEncryptionMethod;
    }

    public void setBackChannelLogoutUrl(String backChannelLogoutUrl) {

        this.backChannelLogoutUrl = backChannelLogoutUrl;
    }

    public String getBackChannelLogoutUrl() {

        if (StringUtils.isBlank(backChannelLogoutUrl)) {
            this.backChannelLogoutUrl = resolveBackChannelLogoutURLForSharedApps();
        }
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

    public void setBypassClientCredentials(boolean isPublicClient) {
        this.bypassClientCredentials = isPublicClient;
    }

    public void setRenewRefreshTokenEnabled(String renewRefreshTokenEnabled) {

        this.renewRefreshTokenEnabled = renewRefreshTokenEnabled;
    }

    public String getRenewRefreshTokenEnabled() {

        return renewRefreshTokenEnabled;
    }

    public boolean isExtendRenewedRefreshTokenExpiryTime() {

        return extendRenewedRefreshTokenExpiryTime;
    }

    public void setExtendRenewedRefreshTokenExpiryTime(boolean extendRenewedRefreshTokenExpiryTime) {

        this.extendRenewedRefreshTokenExpiryTime = extendRenewedRefreshTokenExpiryTime;
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
    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {

        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public Boolean isTokenEndpointAllowReusePvtKeyJwt() {

        return tokenEndpointAllowReusePvtKeyJwt;
    }

    public void setTokenEndpointAllowReusePvtKeyJwt(Boolean tokenEndpointAllowReusePvtKeyJwt) {

        this.tokenEndpointAllowReusePvtKeyJwt = tokenEndpointAllowReusePvtKeyJwt;
    }

    public String getTokenEndpointAuthSignatureAlgorithm() {

        return tokenEndpointAuthSignatureAlgorithm;
    }

    public void setTokenEndpointAuthSignatureAlgorithm(String tokenEndpointAuthSignatureAlgorithm) {

        this.tokenEndpointAuthSignatureAlgorithm = tokenEndpointAuthSignatureAlgorithm;
    }

    public String getSectorIdentifierURI() {

        return sectorIdentifierURI;
    }

    public void setSectorIdentifierURI(String sectorIdentifierURI) {

        this.sectorIdentifierURI = sectorIdentifierURI;
    }

    public String getIdTokenSignatureAlgorithm() {

        return idTokenSignatureAlgorithm;
    }

    public void setIdTokenSignatureAlgorithm(String idTokenSignatureAlgorithm) {

        this.idTokenSignatureAlgorithm = idTokenSignatureAlgorithm;
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

    public boolean isRequirePushedAuthorizationRequests() {

        return requirePushedAuthorizationRequests;
    }

    public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {

        this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
    }

    public boolean isTlsClientCertificateBoundAccessTokens() {

        return tlsClientCertificateBoundAccessTokens;
    }

    public void setTlsClientCertificateBoundAccessTokens(boolean tlsClientCertificateBoundAccessTokens) {

        this.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens;
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

    public boolean isFapiConformanceEnabled() {

        return fapiConformanceEnabled;
    }

    public void setFapiConformanceEnabled(boolean fapiConformant) {

        fapiConformanceEnabled = fapiConformant;
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

    /**
     * Resolves the back-channel logout URL for the shared oAuth apps in organizations.
     *
     * @return Back-channel logout URL.
     */
    private String resolveBackChannelLogoutURLForSharedApps() {

        String tenantDomain = getTenantDomain();
        try {
            if (OrganizationManagementUtil.isOrganization(tenantDomain)) {
                ServiceProvider orgApplication = getOrgApplication(oauthConsumerKey, tenantDomain);
                boolean isFragmentApp = Arrays.stream(orgApplication.getSpProperties())
                        .anyMatch(property -> IS_FRAGMENT_APP.equals(property.getName()) &&
                                Boolean.parseBoolean(property.getValue()));

                if (isFragmentApp) {
                    String rootOrganizationId = getOrganizationManager().getPrimaryOrganizationId(tenantDomain);
                    return resolveBackChannelLogoutURL(rootOrganizationId);
                }
            }
        } catch (OrganizationManagementException | URLBuilderException | IdentityApplicationManagementException e) {
            return null;
        }
        return null;
    }

    private String resolveBackChannelLogoutURL(String organizationId)
            throws URLBuilderException, OrganizationManagementException {

        String tenantDomain = getOrganizationManager().resolveTenantDomain(organizationId);
        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return ServiceURLBuilder.create()
                    .addPath(DEFAULT_BACKCHANNEL_LOGOUT_URL)
                    .setTenant(tenantDomain).build().getAbsolutePublicURL();
        }
        String context = String.format(TENANT_CONTEXT_PATH_COMPONENT, tenantDomain)
                + DEFAULT_BACKCHANNEL_LOGOUT_URL;
        return ServiceURLBuilder.create().addPath(context).build().getAbsolutePublicURL();
    }

    private OrganizationManager getOrganizationManager() {

        return OAuthComponentServiceHolder.getInstance().getOrganizationManager();
    }

    private String getTenantDomain() {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (getAppOwner() != null) {
            tenantDomain = getAppOwner().getTenantDomain();
        }
        return tenantDomain;
    }

    public static ServiceProvider getOrgApplication(String clientId, String tenantDomain)
            throws IdentityApplicationManagementException {

        return OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(
                clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
    }
}
