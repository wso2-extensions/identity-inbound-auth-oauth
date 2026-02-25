/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;

import java.text.ParseException;

/**
 * Util class for token management related activities.
 */
public class TokenMgtUtil {

    private static final Log LOG = LogFactory.getLog(TokenMgtUtil.class);

    /**
     * Parse JWT Token.
     *
     * @param accessToken Access Token
     * @return SignedJWT
     * @throws IdentityOAuth2Exception If an error occurs while parsing the JWT token
     */
    public static SignedJWT parseJWT(String accessToken) throws IdentityOAuth2Exception {

        try {
            return SignedJWT.parse(accessToken);
        } catch (ParseException e) {
            if (LOG.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    LOG.debug(String.format("Failed to parse the received token: %s", accessToken));
                } else {
                    LOG.debug("Failed to parse the received token.");
                }
            }
            throw new IdentityOAuth2Exception("Error while parsing token.", e);
        }
    }

    /**
     * Get JWT Claim sets for the given access token.
     *
     * @param signedJWT Signed JWT
     * @return JWT Claim sets
     * @throws IdentityOAuth2Exception If an error occurs while getting the JWT claim sets
     */
    public static JWTClaimsSet getTokenJWTClaims(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given token.");
            }
            return claimsSet;
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while retrieving claim set from token.", e);
        }
    }

    /**
     * Check if the given token is a non-persistence access token.
     *
     * @param token Access Token
     * @return True if the token is a non-persistence access token.
     */
    public static boolean isNonPersistenceAccessToken(String token) {

        if (JWTUtils.isJWT(token)) {
            try {
                SignedJWT signedJWT = parseJWT(token);
                JWTClaimsSet claimsSet = getTokenJWTClaims(signedJWT);
                return claimsSet.getClaim(OAuth2Constants.ENTITY_ID) != null;
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while parsing the JWT token.", e);
            }
        }
        return false;
    }

    /**
     * Get the token ID from a non-persistence access token.
     *
     * @param accessToken Non-persistence access token
     * @return Token ID or null if not found
     * @throws IdentityOAuth2Exception If an error occurs while parsing the JWT token
     */
    public static String getTokenIDFromNonPersistenceAccessToken(String accessToken) throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJWT = parseJWT(accessToken);
            JWTClaimsSet claimsSet = getTokenJWTClaims(signedJWT);
            return (String) claimsSet.getClaim(OAuth2Constants.TOKEN_ID);
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while parsing the JWT token.", e);
            return null;
        }
    }
}
