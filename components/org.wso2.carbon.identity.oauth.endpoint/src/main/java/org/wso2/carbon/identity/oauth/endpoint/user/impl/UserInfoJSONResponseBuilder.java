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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Enumeration;
import java.util.Arrays;
import java.util.Iterator;

/**
 *
 */
public class UserInfoJSONResponseBuilder implements UserInfoResponseBuilder {
    private static final Log log = LogFactory.getLog(UserInfoJSONResponseBuilder.class);
    private ArrayList<String> lstEssential = new ArrayList<>();
    private static final String UPDATED_AT = "updated_at";
    private static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String EMAIL_VERIFIED = "email_verified";
    Map<String, Object> claimsforAddressScope = new HashMap<>();

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {
        Resource resource = null;
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(tokenResponse.getAuthorizedUser());
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            carbonContext.setTenantId(tenantId);
            carbonContext.setTenantDomain(tenantDomain);
            RegistryService registry = OAuth2ServiceComponentHolder.getRegistryService();
            resource = registry.getConfigSystemRegistry(tenantId).get(OAuthConstants.SCOPE_RESOURCE_PATH);
        } catch (RegistryException e) {
            log.error("Error while obtaining registry collection from :" + OAuthConstants.SCOPE_RESOURCE_PATH, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);
        Map<String, Object> claims = null;
        Map<String, Object> returnClaims = new HashMap<>();
        String requestedScopeClaims = null;

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
        String[] arrRequestedScopeClaims = null;
        for (String requestedScope : tokenResponse.getScope()) {
            if (resource != null && resource.getProperties() != null) {
                Enumeration supporetdScopes = resource.getProperties().propertyNames();
                while (supporetdScopes.hasMoreElements()) {
                    String supportedScope = (String) supporetdScopes.nextElement();
                    if (supportedScope.equals(requestedScope)) {
                        requestedScopeClaims = resource.getProperty(requestedScope);
                        if (requestedScopeClaims.contains(",")) {
                            arrRequestedScopeClaims = requestedScopeClaims.split(",");
                        } else {
                            arrRequestedScopeClaims = new String[1];
                            arrRequestedScopeClaims[0] = requestedScopeClaims;
                        }
                        for (Map.Entry<String, Object> entry : claims.entrySet()) {
                            String requestedClaims = entry.getKey();
                            if (Arrays.asList(arrRequestedScopeClaims).contains(requestedClaims)) {
                                returnClaims.put(entry.getKey(), claims.get(entry.getKey()));
                                if (requestedScope.equals("address")) {
                                    claimsforAddressScope.put(entry.getKey(), entry.getKey());
                                }
                            }
                        }

                    }
                }
            }
        }
        if (!returnClaims.containsKey("sub") || StringUtils.isBlank((String) claims.get("sub"))) {
            returnClaims.put("sub", tokenResponse.getAuthorizedUser());
        }
        if (claimsforAddressScope != null) {
            for (Map.Entry<String, Object> entry : claimsforAddressScope.entrySet()) {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put(entry.getKey(), claims.get(entry.getKey()));
                returnClaims.put("address", jsonObject);
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
        if (lstEssential != null) {
            for (String key : lstEssential) {
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
            lstEssential = getEssentialClaims(cacheEntry.getEssentialClaims());
        }
        return cacheEntry.getUserAttributes();
    }

    private ArrayList<String> getEssentialClaims(String essentialClaims) {
        JSONObject jsonObjectClaims = new JSONObject(essentialClaims);
        String key;
        ArrayList essentailClaimslist = new ArrayList();
        if ((jsonObjectClaims != null) && jsonObjectClaims.toString().contains("userinfo")) {
            JSONObject newJSON = jsonObjectClaims.getJSONObject("userinfo");
            Iterator<?> keys = newJSON.keys();
            while (keys.hasNext()) {
                key = (String) keys.next();
                String value = null;
                if (newJSON != null) {
                    value = newJSON.get(key).toString();
                }
                JSONObject jsonObjectValues = new JSONObject(value);
                if (jsonObjectValues != null) {
                    Iterator<?> claimKeyValues = jsonObjectValues.keys();
                    while (claimKeyValues.hasNext()) {
                        String claimKeys = (String) claimKeyValues.next();
                        String claimValues = jsonObjectValues.get(claimKeys).toString();
                        if (claimValues.equals("true") && claimKeys.equals("essential")) {
                            essentailClaimslist.add(key);
                        }
                    }
                }
            }
        }
        return essentailClaimslist;
    }

}
