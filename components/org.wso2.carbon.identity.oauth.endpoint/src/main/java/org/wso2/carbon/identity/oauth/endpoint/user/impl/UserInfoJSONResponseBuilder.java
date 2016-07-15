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
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 *
 */
public class UserInfoJSONResponseBuilder implements UserInfoResponseBuilder {
    private static final Log log = LogFactory.getLog(UserInfoJSONResponseBuilder.class);
    Map<String, Object> claimsUserStore = null;
    JSONObject jsonObject = new JSONObject();

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);
        Map<String, Object> claims = null;

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
        Map<String, Object> supportedScopes = OAuthServerConfiguration.getInstance().getSupportedScopes();
        Iterator it = supportedScopes.entrySet().iterator();
        String subClaims = null;
        String mainClaims = null;
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry) it.next();
            if (pair.getKey().equals("openid")) {
                if (pair.getValue().toString().contains(":")) {
                    String[] arrAllClaims = pair.getValue().toString().split(":");
                    mainClaims = arrAllClaims[0];
                } else {
                    mainClaims = pair.getValue().toString();
                }
                String[] arrMainClaims = null;
                if (mainClaims.contains(",")) {
                    String[] arrTempMainClaims = mainClaims.split(",");
                    arrMainClaims = Arrays.copyOf(arrTempMainClaims, arrTempMainClaims.length);

                } else {
                    arrMainClaims = new String[1];
                    arrMainClaims[0] = mainClaims;
                }
                if (!Arrays.asList(arrMainClaims).contains("all")) {
                    claims = new HashMap<>();
                }
            }
        }
        if(!claims.containsKey("sub") || StringUtils.isBlank((String) claims.get("sub"))) {
            claims.put("sub", tokenResponse.getAuthorizedUser());
        }
        for (String scope : tokenResponse.getScope()) {
            if (claims.size() == 1 && claims.containsKey("sub")) {
                claimsUserStore = ClaimUtil.getClaimsFromUserStore(tokenResponse);
            }
            if (supportedScopes.containsKey(scope)) {
                String[] arrMainClaims = null;
                Iterator iterator = supportedScopes.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry keyValue = (Map.Entry) iterator.next();
                    if (keyValue.getKey().equals(scope)) {
                        if (keyValue.getValue().toString().contains(":")) {
                            String[] arrallClaims = keyValue.getValue().toString().split(":");
                            mainClaims = arrallClaims[0];
                            subClaims = arrallClaims[1];

                        } else {
                            mainClaims = keyValue.getValue().toString();
                            subClaims = null;
                        }
                        if (mainClaims.contains(",")) {
                            String[] arrMainClaimsTemp = mainClaims.split(",");
                            arrMainClaims = Arrays.copyOf(arrMainClaimsTemp, arrMainClaimsTemp.length);
                        } else {
                            arrMainClaims = new String[1];
                            arrMainClaims[0] = mainClaims;
                        }
                        String[] arrSubClaims = null;
                        if (subClaims != null) {
                            if (subClaims.contains(",")) {
                                String[] arrSubClaimsTemp = subClaims.split(",");
                                arrSubClaims = Arrays.copyOf(arrSubClaimsTemp, arrSubClaimsTemp.length);
                            } else {
                                arrSubClaims = new String[1];
                                arrSubClaims[0] = subClaims;
                            }
                        }

                        for (int i = 0; i < arrMainClaims.length; i++) {
                            if (arrSubClaims != null && arrSubClaims.length > 0) {

                                for (int j = 0; j < arrSubClaims.length; j++) {
                                    if (!claims.containsKey(arrSubClaims[j]) && claimsUserStore != null &&
                                            claimsUserStore.containsKey(arrSubClaims[j])) {
                                        jsonObject.put(arrSubClaims[j].trim(), claimsUserStore.get(arrSubClaims[j].trim()));
                                    } else {
                                        jsonObject.put(arrSubClaims[j].trim(), " ");
                                    }
                                }
                            }
                            if (supportedScopes.containsKey("openid") && supportedScopes.get("openid").toString().
                                    contains("all")) {
                                log.debug("The default behaviour is enabled");
                            } else if (!claims.containsKey(arrMainClaims[i])) {
                                if (claimsUserStore != null && claimsUserStore.containsKey(arrMainClaims[i])) {
                                    if (arrSubClaims != null && arrSubClaims.length > 0) {
                                        claims.put(arrMainClaims[i].trim(), jsonObject);
                                    } else {
                                        claims.put(arrMainClaims[i], claimsUserStore.get(arrMainClaims[i]));
                                    }
                                } else {
                                    if (arrSubClaims != null && arrSubClaims.length > 0) {
                                        claims.put(arrMainClaims[i].trim(), jsonObject);
                                    } else {
                                        if (arrMainClaims[i].trim().equals("birthdate")) {
                                            claims.put(arrMainClaims[i].trim(), "2014-10-10");
                                        } else {
                                            claims.put(arrMainClaims[i].trim(), " ");
                                        }
                                    }
                                }
                            }
                        }
                    }

                }
            }
        }
        return JSONUtils.buildJSON(claims);
    }

    private Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse) {
        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(tokenResponse.getAuthorizationContextToken()
                .getTokenString());
        AuthorizationGrantCacheEntry cacheEntry = (AuthorizationGrantCacheEntry) AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry == null) {
            return new HashMap<ClaimMapping, String>();
        }

        return cacheEntry.getUserAttributes();
    }

}
