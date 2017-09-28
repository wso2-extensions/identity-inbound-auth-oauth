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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 *
 */
public class UserInfoJSONResponseBuilder implements UserInfoResponseBuilder {
    private static final Log log = LogFactory.getLog(UserInfoJSONResponseBuilder.class);
    private ArrayList<String> essentialClaims = new ArrayList<>();
    private static final String UPDATED_AT = "updated_at";
    private static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String ADDRESS = "address";
    private static final String ADDRESS_PREFIX = "address.";

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {
        Resource oidcScopesResource = null;
        String tenantDomain = null;
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            /*
                We can't get any information related to SP tenantDomain using the tokenResponse directly or indirectly.
                Therefore we make use of the thread local variable set at the UserInfo endpoint to get the tenantId
                of the service provider
             */
            int tenantId = OAuth2Util.getClientTenatId();
            tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            carbonContext.setTenantId(tenantId);
            carbonContext.setTenantDomain(tenantDomain);
            RegistryService registry = OAuth2ServiceComponentHolder.getRegistryService();
            oidcScopesResource = registry.getConfigSystemRegistry(tenantId).get(OAuthConstants.SCOPE_RESOURCE_PATH);
        } catch (RegistryException e) {
            log.error("Error while obtaining registry collection from :" + OAuthConstants.SCOPE_RESOURCE_PATH, e);
        } finally {
            // clear the thread local that contained the SP tenantId
            OAuth2Util.clearClientTenantId();
            PrivilegedCarbonContext.endTenantFlow();
        }

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);
        Map<String, Object> claims = null;
        Map<String, Object> returnClaims = new HashMap<>();
        Map<String, Object> claimsforAddressScope = new HashMap<>();
        String requestedScopeClaims = null;
        String addressValues = null;
        String[] arrRequestedScopeClaims = null;

        if (userAttributes == null || userAttributes.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Trying to retrieve from user store.");
            }
            claims = ClaimUtil.getClaimsFromUserStore(tokenResponse);
        } else {
            UserInfoClaimRetriever retriever = UserInfoEndpointConfig.getInstance().getUserInfoClaimRetriever();
            claims = retriever.getClaimsMap(userAttributes);
        }
        if(claims == null){
            claims = new HashMap<String,Object>();
        }
        if (claims.get(OAuth2Util.SUB) != null) {
            claims.put(OAuth2Util.SUB, returnSubjectClaim(claims.get(OAuth2Util.SUB).toString(), tenantDomain,
                    tokenResponse));
        }
        if (oidcScopesResource != null && oidcScopesResource.getProperties() != null) {
            addressValues = oidcScopesResource.getProperty(ADDRESS);
        }
        for (String requestedScope : tokenResponse.getScope()) {
            if (oidcScopesResource != null && oidcScopesResource.getProperties() != null) {
                Enumeration supporetdScopes = oidcScopesResource.getProperties().propertyNames();
                while (supporetdScopes.hasMoreElements()) {
                    String supportedScope = (String) supporetdScopes.nextElement();
                    if (supportedScope.equals(requestedScope)) {
                        requestedScopeClaims = oidcScopesResource.getProperty(requestedScope);
                        if (requestedScopeClaims.contains(",")) {
                            arrRequestedScopeClaims = requestedScopeClaims.split("\\s*,\\s*");
                        } else {
                            arrRequestedScopeClaims = new String[1];
                            arrRequestedScopeClaims[0] = requestedScopeClaims;
                        }
                        for (Map.Entry<String, Object> entry : claims.entrySet()) {
                            String requestedClaims = entry.getKey();
                            if (Arrays.asList(arrRequestedScopeClaims).contains(requestedClaims)) {
                                // Address claim is handled for both ways, where address claims are sent as "address."
                                // prefix or in address scope.
                                if (requestedClaims.contains(ADDRESS_PREFIX)) {
                                    claimsforAddressScope.put(entry.getKey().substring(ADDRESS_PREFIX.length()), claims.get(entry.getKey()));
                                } else if (addressValues != null && addressValues.contains(requestedClaims)) {
                                    claimsforAddressScope.put(entry.getKey(), claims.get(entry.getKey()));
                                } else {
                                    returnClaims.put(entry.getKey(), claims.get(entry.getKey()));
                                }
                            }
                        }

                    }
                }
            }
        }
        if (returnClaims.containsKey(UPDATED_AT) && returnClaims.get(UPDATED_AT) != null) {
            if (returnClaims.get(UPDATED_AT) instanceof String) {
                returnClaims.put(UPDATED_AT, Integer.parseInt((String) (returnClaims.get(UPDATED_AT))));
            }
        }
        if (returnClaims.containsKey(PHONE_NUMBER_VERIFIED) && returnClaims.get(PHONE_NUMBER_VERIFIED) != null) {
            if (returnClaims.get(PHONE_NUMBER_VERIFIED) instanceof String) {
                returnClaims.put(PHONE_NUMBER_VERIFIED, (Boolean.valueOf((String)
                        (returnClaims.get(PHONE_NUMBER_VERIFIED)))));
            }
        }
        if (returnClaims.containsKey(EMAIL_VERIFIED) && returnClaims.get(EMAIL_VERIFIED) != null) {
            if (returnClaims.get(EMAIL_VERIFIED) instanceof String) {
                returnClaims.put(EMAIL_VERIFIED, (Boolean.valueOf((String) (returnClaims.get(EMAIL_VERIFIED)))));
            }
        }
        if (claimsforAddressScope.size() > 0) {
            JSONObject jsonObject = new JSONObject();
            for (Map.Entry<String, Object> entry : claimsforAddressScope.entrySet()) {
                jsonObject.put(entry.getKey(), entry.getValue());
            }
            returnClaims.put(ADDRESS, jsonObject);
        }
        if (!returnClaims.containsKey("sub") || StringUtils.isBlank((String) claims.get("sub"))) {
            returnClaims.put("sub", tokenResponse.getAuthorizedUser());
        }
        if (essentialClaims != null) {
            for (String key : essentialClaims) {
                returnClaims.put(key, claims.get(key));
            }
        }
        return JSONUtils.buildJSON(returnClaims);
    }

    private Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse) {
        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(tokenResponse.getAuthorizationContextToken()
                .getTokenString());
        AuthorizationGrantCacheEntry cacheEntry = (AuthorizationGrantCacheEntry) AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry == null) {
            return new HashMap<ClaimMapping, String>();
        }

        if (StringUtils.isNotEmpty(cacheEntry.getEssentialClaims())) {
            essentialClaims = OAuth2Util.getEssentialClaims(cacheEntry.getEssentialClaims(),
                    OAuthConstants.OAuth20Params.USERINFO);
        } else {
            essentialClaims = new ArrayList<>();
        }
        return cacheEntry.getUserAttributes();
    }

    /**
     * Returns subject claim.
     *
     * @param sub subject
     * @param tenantDomain tenant domain
     * @param tokenResponse token response
     * @return
     * @throws UserInfoEndpointException
     */

    protected String returnSubjectClaim(String sub, String tenantDomain, OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        String clientId = null;

        try {
            clientId = OAuth2Util.getClientIdForAccessToken
                    (tokenResponse.getAuthorizationContextToken().getTokenString());
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error while obtaining the client ID :" + clientId, e);
        }
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();

        ServiceProvider serviceProvider;
        try {
            //getting service provider
            serviceProvider = applicationMgtService.getServiceProviderByClientId(
                    clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new UserInfoEndpointException("Error while obtaining the service provider.", e);
        }
        String userName = tokenResponse.getAuthorizedUser();
        String userStoreDomain = IdentityUtil.extractDomainFromName(userName);

        if (serviceProvider != null) {
            boolean isUseTenantDomainInLocalSubject = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                    .isUseTenantDomainInLocalSubjectIdentifier();
            boolean isUseUserStoreDomainInLocalSubject = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                    .isUseUserstoreDomainInLocalSubjectIdentifier();
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(sub);
            if (StringUtils.isNotEmpty(sub)) {
                // building subject in accordance with Local and Outbound Authentication Configuration preferences
                if (isUseTenantDomainInLocalSubject) {
                    sub = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);
                }
                if (isUseUserStoreDomainInLocalSubject) {
                    sub = UserCoreUtil.addDomainToName(sub, userStoreDomain);
                }
            }
        }
        return sub;
    }
}
