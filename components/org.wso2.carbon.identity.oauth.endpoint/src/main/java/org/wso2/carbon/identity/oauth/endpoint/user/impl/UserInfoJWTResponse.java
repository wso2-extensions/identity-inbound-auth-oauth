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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

public class UserInfoJWTResponse implements UserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(UserInfoJWTResponse.class);
    private static final String INBOUND_AUTH2_TYPE = "oauth2";

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {
        ServiceProvider serviceProvider = null;
        AccessTokenDO accessTokenDO = null;
        Map<String, Object> claims = null;

        try {
            PrivilegedCarbonContext.startTenantFlow();
            /*
                We can't get any information related to SP tenantDomain using the tokenResponse directly or indirectly.
                Therefore we make use of the thread local variable set at the UserInfo endpoint to get the tenantId
                of the service provider
             */
            int tenantId = OAuth2Util.getClientTenatId();
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);

            ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder
                    .getApplicationMgtService();
            try {
                accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(tokenResponse.getAuthorizationContextToken().getTokenString());
                String spName = applicationMgtService.getServiceProviderNameByClientId(
                        OAuth2Util.getClientIdForAccessToken(tokenResponse.getAuthorizationContextToken().getTokenString()),
                        INBOUND_AUTH2_TYPE, tenantDomain);
                serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName, tenantDomain);
            } catch (IdentityApplicationManagementException e) {
                throw new UserInfoEndpointException("Error while getting service provider information.", e);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("Error while getting client id of the given access token.", e);
            }
        } finally {
            // clear the thread local that contained the SP tenantId
            OAuth2Util.clearClientTenantId();
            PrivilegedCarbonContext.endTenantFlow();
        }

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);

        if (userAttributes.isEmpty()) {
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
        if(!claims.containsKey("sub") || StringUtils.isBlank((String) claims.get("sub"))) {
            claims.put("sub", tokenResponse.getAuthorizedUser());
        }

        if (claims.get("sub") != null) {
            String subjectIdentifier = (String) claims.get("sub");
            // Append tenant domain and user store domain to the subject identifier if needed
            if (serviceProvider.getLocalAndOutBoundAuthenticationConfig().isUseTenantDomainInLocalSubjectIdentifier()) {
                subjectIdentifier = UserCoreUtil.addTenantDomainToEntry(subjectIdentifier, accessTokenDO.getAuthzUser().getTenantDomain());
            }
            if (serviceProvider.getLocalAndOutBoundAuthenticationConfig().isUseUserstoreDomainInLocalSubjectIdentifier()) {
                if (IdentityUtil.getPrimaryDomainName().equalsIgnoreCase(accessTokenDO.getAuthzUser().getUserStoreDomain())) {
                    subjectIdentifier = IdentityUtil.getPrimaryDomainName() + "/" + subjectIdentifier;
                } else {
                    subjectIdentifier = UserCoreUtil.addDomainToName(subjectIdentifier, accessTokenDO.getAuthzUser().getUserStoreDomain());
                }
            }
            claims.put("sub", subjectIdentifier);
        }

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setAllClaims(claims);
        return new PlainJWT(jwtClaimsSet).serialize();
    }

    private Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse) {

        Map<ClaimMapping,String> claims = new HashMap<ClaimMapping,String>();
        AuthorizationGrantCacheKey cacheKey =
                new AuthorizationGrantCacheKey(tokenResponse.getAuthorizationContextToken().getTokenString());
        AuthorizationGrantCacheEntry cacheEntry =
                (AuthorizationGrantCacheEntry) AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
        if (cacheEntry != null) {
            claims = cacheEntry.getUserAttributes();
        }
        return claims;
    }

}
