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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.HashMap;
import java.util.Map;

public class UserInfoJWTResponse implements UserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(UserInfoJWTResponse.class);
    private static final JWSAlgorithm DEFAULT_SIGNATURE_ALGO = new JWSAlgorithm(JWSAlgorithm.NONE.getName());

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        JWSAlgorithm signatureAlgorithm = DEFAULT_SIGNATURE_ALGO;

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);

        Map<String, Object> claims = null;
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

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setAllClaims(claims);

        String sigAlg = OAuthServerConfiguration.getInstance().getUserInfoJWTSignatureAlgorithm();
        if (StringUtils.isNotBlank(sigAlg)) {
            try {
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(sigAlg);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("Provided signature algorithm : " + sigAlg + " is not supported.",
                        e);
            }
        }

        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            if (log.isDebugEnabled()) {
                log.debug("User Info JWT Signature algorithm is not defined. Returning unsigned JWT.");
            }
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String signingTenantDomain;
        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(tokenResponse
                    .getAuthorizationContextToken().getTokenString());
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while signing JWT", e);
        }

        if (accessTokenDO == null) {
            // this means the token is not active so we can't proceed further
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN,
                    "Invalid Access Token.");
        }
        signingTenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();

        if (isJWTSignedWithSPKey || StringUtils.isBlank(signingTenantDomain)) {
            String clientId = null;
            try {
                clientId = accessTokenDO.getConsumerKey();
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
                signingTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
                throw new UserInfoEndpointException("Error occurred while retrieving SP with client ID: " + clientId, e);
            }
        }

        try {
            return OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while signing JWT", e);
        }
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
