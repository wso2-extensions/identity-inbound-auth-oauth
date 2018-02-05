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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.AbstractUserInfoResponseBuilder;

import java.util.Map;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Builds user info response as a JWT according to http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
 */
public class UserInfoJWTResponse extends AbstractUserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(UserInfoJWTResponse.class);
    private static final JWSAlgorithm DEFAULT_SIGNATURE_ALGORITHM = new JWSAlgorithm(JWSAlgorithm.NONE.getName());

    @Override
    protected Map<String, Object> retrieveUserClaims(OAuth2TokenValidationResponseDTO tokenValidationResponse)
            throws UserInfoEndpointException {
        return ClaimUtil.getUserClaimsUsingTokenResponse(tokenValidationResponse);
    }

    @Override
    protected String buildResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                   String spTenantDomain,
                                   Map<String, Object> filteredUserClaims) throws UserInfoEndpointException {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setAllClaims(filteredUserClaims);
        return buildJWTResponse(tokenResponse, spTenantDomain, jwtClaimsSet);
    }

    private String buildJWTResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                    String spTenantDomain,
                                    JWTClaimsSet jwtClaimsSet) throws UserInfoEndpointException {
        JWSAlgorithm signatureAlgorithm = getJWTSignatureAlgorithm();
        if (JWSAlgorithm.NONE.equals(signatureAlgorithm)) {
            if (log.isDebugEnabled()) {
                log.debug("User Info JWT Signature algorithm is not defined. Returning unsigned JWT.");
            }
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        // Tenant domain to which the signing key belongs to.
        String signingTenantDomain = getSigningTenantDomain(tokenResponse, spTenantDomain);
        try {
            return OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while signing JWT", e);
        }
    }

    private JWSAlgorithm getJWTSignatureAlgorithm() throws UserInfoEndpointException {
        JWSAlgorithm signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
        String sigAlg = OAuthServerConfiguration.getInstance().getUserInfoJWTSignatureAlgorithm();
        if (isNotBlank(sigAlg)) {
            try {
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(sigAlg);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("Provided signature algorithm : " + sigAlg + " is not supported.", e);
            }
        }
        return signatureAlgorithm;
    }

    private String getSigningTenantDomain(OAuth2TokenValidationResponseDTO tokenResponse,
                                          String spTenantDomain) throws UserInfoEndpointException {
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String signingTenantDomain;
        if (isJWTSignedWithSPKey) {
            signingTenantDomain = spTenantDomain;
        } else {
            AccessTokenDO accessTokenDO = getAccessTokenDO(tokenResponse.getAuthorizationContextToken().getTokenString());
            signingTenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();
        }
        return signingTenantDomain;
    }

    private AccessTokenDO getAccessTokenDO(String accessToken) throws UserInfoEndpointException {
        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessToken);
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while signing JWT", e);
        }

        if (accessTokenDO == null) {
            // this means the token is not active so we can't proceed further
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN, "Invalid Access Token.");
        }
        return accessTokenDO;
    }
}
