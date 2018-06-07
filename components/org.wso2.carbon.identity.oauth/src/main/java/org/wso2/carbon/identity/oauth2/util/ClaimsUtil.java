/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class ClaimsUtil {

    private static Log log = LogFactory.getLog(ClaimsUtil.class);

    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private final static String SP_DIALECT = "http://wso2.org/oidc/claim";

    public static boolean isInLocalDialect(Map<String, String> attributes) {
        Iterator<String> iterator = attributes.keySet().iterator();
        if (iterator.hasNext()) {
            return iterator.next().startsWith("http://wso2.org/claims/");
        }
        return false;
    }


    public static Map<String, String> convertFederatedClaimsToLocalDialect(Map<String, String> remoteClaims, ClaimMapping[]
            idPClaimMappings, String tenantDomain) {

        if (log.isDebugEnabled()) {
            StringBuilder claimUris = new StringBuilder();
            for (String key : remoteClaims.keySet()) {
                claimUris.append(key).append(",");
            }
            log.debug("Converting federated user claims to local dialect. Converting claim urls: " + claimUris
                    .toString());
        }

        if (idPClaimMappings != null && idPClaimMappings.length > 0) {
            Map<String, String> localToIdPClaimMap;
            localToIdPClaimMap = FrameworkUtils.getClaimMappings(idPClaimMappings, true);
            Map<String, String> defaultValuesForClaims = loadDefaultValuesForClaims(idPClaimMappings);

            // Loop remote claims and map to local claims
            Map<String, String> convertedClaims = mapRemoteClaimsToLocalClaims(remoteClaims, localToIdPClaimMap,
                    defaultValuesForClaims);
            if (log.isDebugEnabled()) {
                StringBuilder claimUris = new StringBuilder();
                for (String key : convertedClaims.keySet()) {
                    claimUris.append(key).append(",");
                }
                log.debug("Converted federated user claims to local dialect. Converting claim urls: " + claimUris
                        .toString());
            }
            return convertedClaims;
        } else {
            // If idp claim mappings are not configured, return original claims.
            return remoteClaims;
        }

    }

    /**
     * To get the relevant Service Provider.
     *
     * @param requestMsgCtx Token Request Message Context.
     * @return Relevant Service Provider.
     * @throws IdentityApplicationManagementException Identity Application Management Exception.
     */
    private static ServiceProvider getServiceProvider(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityApplicationManagementException {

        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isBlank(spTenantDomain)) {
            spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService
                .getServiceProviderNameByClientId(requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
                        INBOUND_AUTH2_TYPE, spTenantDomain);
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }

    public static Map<String, String> convertClaimsToOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx,
                                                                 Map<String, String> userClaims) throws
            IdentityApplicationManagementException, IdentityException {

        Map<String, String> mappedAppClaims = new HashMap<>();

        if (log.isDebugEnabled()) {
            StringBuilder claimUris = new StringBuilder();
            for (String key : userClaims.keySet()) {
                claimUris.append(key).append(",");
            }
            log.debug("Converting user claims from local dialect to OIDC dialect for user: " + requestMsgCtx
                    .getAuthorizedUser() + ", client id:" + requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId()
                    + ", converting claim urls: " + claimUris.toString());
        }

        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isBlank(spTenantDomain)) {
            spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService
                .getServiceProviderNameByClientId(requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
                        INBOUND_AUTH2_TYPE, spTenantDomain);
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName,
                spTenantDomain);
        if (serviceProvider == null) {
            return mappedAppClaims;
        }
        ClaimMapping[] spClaimMappings = serviceProvider.getClaimConfig().getClaimMappings();
        if (spClaimMappings == null || !(spClaimMappings.length > 0)) {
            spClaimMappings = new ClaimMapping[0];
        }

        List<String> requestedLocalClaims = new ArrayList<>();
        for (ClaimMapping mapping : spClaimMappings) {
            if (mapping.isRequested()) {
                requestedLocalClaims.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Requested number of local claims: " + requestedLocalClaims.size());
        }

        Map<String, String> spToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(SP_DIALECT, null, spTenantDomain, false);

        for (Map.Entry<String, String> oidcToLocalClaimMapping : spToLocalClaimMappings.entrySet()) {
            String value = userClaims.get(oidcToLocalClaimMapping.getValue());
            if (value != null && requestedLocalClaims.contains(oidcToLocalClaimMapping.getValue())) {
                mappedAppClaims.put(oidcToLocalClaimMapping.getKey(), value);
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Mapped claim: key -  " + oidcToLocalClaimMapping.getKey() + " value -" + value);
                }
            }
        }

        if (log.isDebugEnabled()) {
            StringBuilder claimUris = new StringBuilder();
            for (String key : mappedAppClaims.keySet()) {
                claimUris.append(key).append(",");
            }
            log.debug("Converted user claims from local dialect to OIDC dialect for user: " + requestMsgCtx
                    .getAuthorizedUser() + ", client id:" + requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId()
                    + ", converted claim urls: " + claimUris.toString());
        }

        return mappedAppClaims;
    }

    /**
     * Handle claims from identity provider based on claim configurations.
     *
     * @param identityProvider Identity Provider
     * @param attributes       Relevant Claims coming from IDP
     * @param tenantDomain     Tenant Domain.
     * @param tokenReqMsgCtx   Token request message context.
     * @return mapped local claims.
     * @throws IdentityOAuth2Exception Identity Oauth2 Exception.
     */
    public static Map<String, String> handleClaimMapping(IdentityProvider identityProvider,
            Map<String, String> attributes, String tenantDomain, OAuthTokenReqMessageContext tokenReqMsgCtx)
            throws IdentityException, IdentityApplicationManagementException {

        boolean proxyUserAttributes = !OAuthServerConfiguration.getInstance()
                .isConvertOriginalClaimsFromAssertionsToOIDCDialect();

        if (proxyUserAttributes) {
            setHasNonOIDCClaimsProperty(tokenReqMsgCtx);
            return attributes;
        }

        ClaimMapping[] idPClaimMappings = identityProvider.getClaimConfig().getClaimMappings();
        Map<String, String> claimsAfterIdpMapping;
        Map<String, String> claimsAfterSPMapping = new HashMap<>();
        ServiceProvider serviceProvider = getServiceProvider(tokenReqMsgCtx);

        if (ArrayUtils.isNotEmpty(idPClaimMappings)) {
            if (log.isDebugEnabled()) {
                log.debug("Claim mappings exist for identity provider " + identityProvider.getIdentityProviderName());
            }
            claimsAfterIdpMapping = handleClaimsForIDP(attributes, tenantDomain, identityProvider, false,
                    idPClaimMappings);
            if (isUserClaimsInTokenLoggable()) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Claims of user : " + tokenReqMsgCtx.getAuthorizedUser() + " after IDP " + " claim mapping "
                                    + claimsAfterIdpMapping.toString());
                }
            }
            if (isSPRequestedClaimsExist(tokenReqMsgCtx)) {
                claimsAfterSPMapping = ClaimsUtil.convertClaimsToOIDCDialect(tokenReqMsgCtx, claimsAfterIdpMapping);
                claimsAfterSPMapping = handleUnMappedClaims(tokenReqMsgCtx, attributes, claimsAfterSPMapping,
                        idPClaimMappings);
            } else {
                if (isUserClaimsInTokenLoggable()) {
                    if (log.isDebugEnabled()) {
                        log.debug("IDP claims exists, SP claims does not exist, for the identity provider "
                                + identityProvider.getIdentityProviderName() + ", service provider " + serviceProvider
                                .getApplicationName() + ", hence cannot do claim mapping");
                    }
                }
            }
        } else {
            claimsAfterIdpMapping = attributes;

            if (isUserClaimsInTokenLoggable()) {
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims do not exist for, identity provider, " + identityProvider
                            .getIdentityProviderName() + ", hence directly copying custom claims, " +
                            claimsAfterIdpMapping.toString());
                }
            }
            if (isSPRequestedClaimsExist(tokenReqMsgCtx)) {
                claimsAfterSPMapping = ClaimsUtil.convertClaimsToOIDCDialect(tokenReqMsgCtx, claimsAfterIdpMapping);
                if (isUserClaimsInTokenLoggable()) {
                    if (log.isDebugEnabled()) {
                        log.debug("IDP claims do not exist but SP Claim mappings exists for, identity provider, "
                                + identityProvider.getIdentityProviderName() + ", and Service Provider, "
                                + serviceProvider.getApplicationName() + ", claims after SP mapping, "
                                + claimsAfterSPMapping.toString());
                    }
                }
                claimsAfterSPMapping = handleUnMappedClaims(tokenReqMsgCtx, attributes, claimsAfterSPMapping,
                        idPClaimMappings);
            } else {
                setHasNonOIDCClaimsProperty(tokenReqMsgCtx);
                claimsAfterSPMapping = attributes;
                if (isUserClaimsInTokenLoggable()) {
                    if (log.isDebugEnabled()) {
                        log.debug("IDP claims and SP Claim mappings do not exists for, identity provider, "
                                + identityProvider.getIdentityProviderName() + ", and Service Provider, "
                                + serviceProvider.getApplicationName() + ", hence claims are proxied, "
                                + claimsAfterSPMapping.toString());
                    }
                }
            }
        }
        return claimsAfterSPMapping;
    }

    /**
     * To check whether user claims in token is loggable.
     *
     * @return true if the user claims in token is loggable, otherwise false.
     */
    private static boolean isUserClaimsInTokenLoggable() {
        return IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS);
    }

    /**
     * To set HasNonOIDCClaims property to true.
     *
     * @param tokenReqMsgCtx Token request message context.
     */
    private static void setHasNonOIDCClaimsProperty(OAuthTokenReqMessageContext tokenReqMsgCtx) {
        tokenReqMsgCtx.addProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS, true);
    }

    /**
     * To check whether requested claims exist in the relevant Service Provider.
     *
     * @param tokenReqMsgCtx Token request message context.
     * @return true if requested claim mappings exist in SP side.
     * @throws IdentityApplicationManagementException Identity application management exception.
     */
    private static boolean isSPRequestedClaimsExist(OAuthTokenReqMessageContext tokenReqMsgCtx)
            throws IdentityApplicationManagementException {

        boolean isSPClaimMappingExist = false;
        ServiceProvider serviceProvider = getServiceProvider(tokenReqMsgCtx);
        ClaimConfig claimConfig = serviceProvider.getClaimConfig();
        ClaimMapping[] claimMappings = claimConfig.getClaimMappings();
        if (claimMappings != null) {
            for (ClaimMapping claimMapping : claimMappings) {
                if (claimMapping.isRequested()) {
                    isSPClaimMappingExist = true;
                    break;
                }
            }
        }
        if (isSPClaimMappingExist && log.isDebugEnabled()) {
            log.debug("Service provider " + serviceProvider.getApplicationName() + " has requested claim mappings");
        }
        return isSPClaimMappingExist;
    }

    /**
     * This method handles unmapped claims.
     *
     * @param tokenReqMsgCtx             Token request message context.
     * @param userAttributes             User Attributes.
     * @param claimsAfterIDPandSPMapping Claims after IDP and SP mapping.
     * @param idPClaimMappings           IDP Claim mappings.
     * @return the final mapping after handling unmapped claims.
     * @throws IdentityApplicationManagementException Identity Application Management Exception.
     */
    private static Map<String, String> handleUnMappedClaims(OAuthTokenReqMessageContext tokenReqMsgCtx, Map<String,
            String> userAttributes, Map<String, String> claimsAfterIDPandSPMapping, ClaimMapping[] idPClaimMappings)
            throws IdentityApplicationManagementException {

        boolean isAddUnmappedUserAttributes = OAuthServerConfiguration.getInstance().isAddUnmappedUserAttributes();
        if (isAddUnmappedUserAttributes) {
            claimsAfterIDPandSPMapping = addMissingClaims(tokenReqMsgCtx, userAttributes, claimsAfterIDPandSPMapping,
                    idPClaimMappings);
            setHasNonOIDCClaimsProperty(tokenReqMsgCtx);
            if (isUserClaimsInTokenLoggable()) {
                if (log.isDebugEnabled()) {
                    log.debug("AddUnMappedAttributes is set to true in identity level, hence OIDC claims "
                            + "after conversion, for the user : " + tokenReqMsgCtx.getAuthorizedUser() + ", "
                            + claimsAfterIDPandSPMapping.toString());
                }
            }
        } else {
            if (isUserClaimsInTokenLoggable()) {
                if (log.isDebugEnabled()) {
                    log.debug("AddUnMappedAttributes is set to false in identity level, hence OIDC claims "
                            + "after conversion, for the user : " + tokenReqMsgCtx.getAuthorizedUser() + ", "
                            + claimsAfterIDPandSPMapping.toString());
                }
            }
        }
        return claimsAfterIDPandSPMapping;
    }

    /**
     * To add the missing claims that are missed in IDP and SP mapping.
     *
     * @param tokenReqMsgCtx             Token request message context.
     * @param userAttributes                 Attributes received from IDP.
     * @param claimsAfterIDPandSPMapping Claims.
     * @param idPClaimMappings           IDP Claim mappings.
     * @return Final claim map with all the claims received from the IDP.
     * @throws IdentityApplicationManagementException Identity Application Management Exception.
     */
    private static Map<String, String> addMissingClaims(OAuthTokenReqMessageContext tokenReqMsgCtx,
            Map<String, String> userAttributes, Map<String, String> claimsAfterIDPandSPMapping,
            ClaimMapping[] idPClaimMappings) throws IdentityApplicationManagementException {

        boolean isUserClaimsLoggable = isUserClaimsInTokenLoggable();
        ServiceProvider serviceProvider = getServiceProvider(tokenReqMsgCtx);
        ClaimConfig serviceProviderClaimConfig = serviceProvider.getClaimConfig();
        AuthenticatedUser authenticatedUser = tokenReqMsgCtx.getAuthorizedUser();

        userAttributes.forEach((key, value) -> {
            boolean foundMatching = false;
            String localClaimUri = null;

            // If IDP Claim mapping is not empty.
            if (ArrayUtils.isNotEmpty(idPClaimMappings)) {
                // Go through the claim mappings to identify the missed attributes in IDP level claim mapping.
                for (ClaimMapping claimMapping : idPClaimMappings) {
                    if (claimMapping.getRemoteClaim().getClaimUri().equals(key)) {
                        localClaimUri = claimMapping.getLocalClaim().getClaimUri();
                        foundMatching = true;
                        break;
                    }
                }
                // If the relevant attribute is not mapped in IDP, add that.
                if (!foundMatching) {
                    if (isUserClaimsLoggable) {
                        if (log.isDebugEnabled()) {
                            log.debug("IDP Claim mapping does not exist for " + key + ", hence adding value " + value
                                    + " for the user : " + authenticatedUser);
                        }
                    }
                    claimsAfterIDPandSPMapping.put(key, value);
                } else {
                    // If the relevant attribute has mapping in IDP level, check for SP level mapping.
                    foundMatching = false;
                    ClaimMapping[] spClaimMapping = serviceProviderClaimConfig.getClaimMappings();
                    for (ClaimMapping claimMapping : spClaimMapping) {
                        if (claimMapping.getLocalClaim().getClaimUri().equals(localClaimUri) && claimMapping
                                .isRequested()) {
                            foundMatching = true;
                            break;
                        }
                    }
                    // If the relevant attribute has IDP level mapping but not SP level mapping, add it.
                    if (!foundMatching) {
                        if (isUserClaimsLoggable) {
                            if (log.isDebugEnabled()) {
                                log.debug("IDP Claim mapping exist, but SP Claim mapping does not exist for " + key
                                        + ", hence adding value " + value + " for the user : " + authenticatedUser);
                            }
                        }
                        claimsAfterIDPandSPMapping.put(key, value);
                    }
                }
            } else {
                // If the IDP level mapping is not there, all the claims coming from IDP are assumed to be local claim.
                ClaimMapping[] spClaimMapping = serviceProviderClaimConfig.getClaimMappings();
                for (ClaimMapping claimMapping : spClaimMapping) {
                    if (claimMapping.getLocalClaim().getClaimUri().equals(key) && claimMapping.isRequested()) {
                        foundMatching = true;
                        break;
                    }
                }
                // If the attribute does not have the specific mapping in SP level, add the mapping.
                if (!foundMatching) {
                    if (isUserClaimsLoggable) {
                        if (log.isDebugEnabled()) {
                            log.debug("SP Claim mapping does not exist for " + key + ", hence adding value " + value
                                    + " for the user : " + authenticatedUser);
                        }
                    }
                    claimsAfterIDPandSPMapping.put(key, value);
                }
            }
        });
        if (isUserClaimsLoggable) {
            if (log.isDebugEnabled()) {
                log.debug("Final set of claims for the user : " + authenticatedUser + ": " + claimsAfterIDPandSPMapping
                        .toString());
            }
        }
        return claimsAfterIDPandSPMapping;
    }

    /**
     * To check whether relevant identity provider is resident identity provider.
     *
     * @param identityProvider Specific Identity Provider
     * @return true if the specific identity provider resident identity provider, unless false.
     */
    public static boolean isResidentIdp(IdentityProvider identityProvider) {
        return IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME
                .equals(identityProvider.getIdentityProviderName());
    }

    public static Map<String, String> mapRemoteClaimsToLocalClaims(Map<String, String> remoteClaims,
                                                                   Map<String, String> localToIdPClaimMap,
                                                                   Map<String, String> defaultValuesForClaims) {

        Map<String, String> localUnfilteredClaims = new HashMap<>();
        for (Map.Entry<String, String> entry : localToIdPClaimMap.entrySet()) {
            String localClaimURI = entry.getKey();
            String claimValue = remoteClaims.get(localToIdPClaimMap.get(localClaimURI));
            if (StringUtils.isEmpty(claimValue)) {
                claimValue = defaultValuesForClaims.get(localClaimURI);
            }
            if (!StringUtils.isEmpty(claimValue)) {
                localUnfilteredClaims.put(localClaimURI, claimValue);
            }
        }

        return localUnfilteredClaims;
    }

    public static Map<String, String> loadDefaultValuesForClaims(ClaimMapping[] idPClaimMappings) {

        Map<String, String> defaultValuesForClaims = new HashMap<>();
        for (ClaimMapping claimMapping : idPClaimMappings) {
            String defaultValue = claimMapping.getDefaultValue();
            if (defaultValue != null && !defaultValue.isEmpty()) {
                defaultValuesForClaims.put(claimMapping.getLocalClaim().getClaimUri(), defaultValue);
            }
        }
        return defaultValuesForClaims;
    }

    public static Map<String, String> extractClaimsFromAssertion(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                                 OAuth2AccessTokenRespDTO responseDTO,
                                                                 Assertion assertion, String userAttributeSeparator) {

        Map<String, String> attributes = new HashMap<>();

        List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();
        if (CollectionUtils.isNotEmpty(attributeStatementList)) {
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    List<XMLObject> values = attribute.getAttributeValues();
                    String attributeValues = null;
                    if (values != null) {
                        for (int i = 0; i < values.size(); i++) {
                            Element value = attribute.getAttributeValues().get(i).getDOM();
                            String attributeValue = value.getTextContent();
                            if (log.isDebugEnabled()) {
                                log.debug("Attribute: " + attribute.getName() + ", Value: " + attributeValue);
                            }
                            if (StringUtils.isBlank(attributeValues)) {
                                attributeValues = attributeValue;
                            } else {
                                attributeValues += userAttributeSeparator + attributeValue;
                            }
                            attributes.put(attribute.getName(), attributeValues);
                        }
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No AttributeStatement found in the request for client with id: " + tokReqMsgCtx
                        .getOauth2AccessTokenReqDTO().getClientId());
            }
        }

        return attributes;

    }

    /**
     * This method handles the claim from an non- resident IDP.
     *
     * @param attributes        Relevant User Attributes.
     * @param tenantDomain      Tenant Domain.
     * @param identityProvider  Identity Provider.
     * @param localClaimDialect Local Claim Dialect.
     * @param idPClaimMappings  IDP Claim Mappings.
     * @return claims from IDP
     */
    public static  Map<String, String> handleClaimsForIDP(Map<String, String> attributes, String tenantDomain,
            IdentityProvider identityProvider, boolean localClaimDialect,
            ClaimMapping[] idPClaimMappings) {

        Map<String, String> localClaims;
        if (localClaimDialect) {
            localClaims = handleLocalClaims(attributes, identityProvider);
        } else {
            if (idPClaimMappings.length > 0) {
                localClaims = ClaimsUtil
                        .convertFederatedClaimsToLocalDialect(attributes, idPClaimMappings, tenantDomain);
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims dialect is not local. Converted claims for identity provider: "
                            + identityProvider.getIdentityProviderName());
                }
            } else {
                localClaims = handleLocalClaims(attributes, identityProvider);
            }
        }
        return localClaims;
    }

    /**
     * This method handles the claim from resident IDP
     *
     * @param attributes       Relevant User Attributes.
     * @param identityProvider Identity Provider
     * @return Claims from IDP
     */
    public static Map<String, String> handleClaimsForResidentIDP(Map<String, String> attributes, IdentityProvider
            identityProvider) {

        boolean localClaimDialect;
        Map<String, String> localClaims = new HashMap<>();
        localClaimDialect = identityProvider.getClaimConfig().isLocalClaimDialect();
        if (localClaimDialect) {
            localClaims = handleLocalClaims(attributes, identityProvider);
        } else {
            if (ClaimsUtil.isInLocalDialect(attributes)) {
                localClaims = attributes;
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims dialect is not local. But claims are in local dialect " +
                            "for identity provider: " + identityProvider.getIdentityProviderName() +
                            ". Using attributes in assertion as the IDP claims.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims dialect is not local. These claims are not handled for " +
                            "identity provider: " + identityProvider.getIdentityProviderName());
                }
            }

        }
        return localClaims;
    }

    /**
     * This method is responsible for adding user attributes to cache.
     * @param tokenRespDTO Token response.
     * @param msgCtx Request message context.
     * @param userAttributes Relevant user attributes.
     */
    public static void addUserAttributesToCache(OAuth2AccessTokenRespDTO tokenRespDTO,
            OAuthTokenReqMessageContext msgCtx, Map<ClaimMapping, String> userAttributes) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(
                tokenRespDTO.getAccessToken());
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);
        authorizationGrantCacheEntry.setSubjectClaim(msgCtx.getAuthorizedUser().getAuthenticatedSubjectIdentifier());

        Object hasNonOIDCClaimsProperty = msgCtx.getProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS);
        if (hasNonOIDCClaimsProperty != null) {
            authorizationGrantCacheEntry.setHasNonOIDCClaims((Boolean) hasNonOIDCClaimsProperty);
        } else {
            authorizationGrantCacheEntry.setHasNonOIDCClaims(false);
        }

        if (StringUtils.isNotBlank(tokenRespDTO.getTokenId())) {
            authorizationGrantCacheEntry.setTokenId(tokenRespDTO.getTokenId());
        }

        long validityPeriod = TimeUnit.MILLISECONDS.toNanos(tokenRespDTO.getExpiresInMillis());
        authorizationGrantCacheEntry.setValidityPeriod(validityPeriod);
        AuthorizationGrantCache.getInstance()
                .addToCacheByToken(authorizationGrantCacheKey, authorizationGrantCacheEntry);
    }

    /**
     * This method is responsible for checking whether particular claims from IDP are in local claim format.
     * @param attributes Relevant User attributes.
     * @param identityProvider Identity Provider.
     * @return relevant local claims.
     */
    private static Map<String, String> handleLocalClaims(Map<String, String> attributes, IdentityProvider
            identityProvider) {

        Map<String, String> localClaims = new HashMap<>();
        if (ClaimsUtil.isInLocalDialect(attributes)) {
            localClaims = attributes;
            if (log.isDebugEnabled()) {
                log.debug("Claims are in local dialect for identity provider: " + identityProvider
                        .getIdentityProviderName() + ". Using attributes in assertion as the IDP claims.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Claims are not in local dialect for identity provider: " + identityProvider
                        .getIdentityProviderName() + ". Not considering attributes in assertion.");
            }
        }
        return localClaims;
    }
}
