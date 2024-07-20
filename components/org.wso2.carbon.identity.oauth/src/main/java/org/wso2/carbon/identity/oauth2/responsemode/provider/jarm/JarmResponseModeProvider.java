/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.responsemode.provider.jarm;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AbstractResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Calendar;
import java.util.Date;

import javax.servlet.http.HttpServletResponse;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Abstract class for jarm response mode provider classes (jwt, query.jwt, fragment.jwt, form_post.jwt)
 */
public abstract class JarmResponseModeProvider extends AbstractResponseModeProvider {

    private static final String ISSUER = "iss";
    private static final String AUDIENCE = "aud";
    private static final String EXPIRATION_TIME = "exp";
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";
    private static final String ACCESS_CODE = "code";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String TOKEN_TYPE = "token_type";
    private static final String EXPIRES_IN = "expires_in";
    private static final String ID_TOKEN = "id_token";
    private static final String STATE = "state";
    private static final String SCOPE = "scope";
    private static final String SESSION_STATE = "session_state";
    private static final String AUTHENTICATED_IDPS = "AuthenticatedIdPs";
    private static final int TO_MILLISECONDS = 1000;

    protected JWTClaimsSet getJWTClaimsSet(AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException {

        String code = authorizationResponseDTO.getSuccessResponseDTO().getAuthorizationCode();
        String idToken = authorizationResponseDTO.getSuccessResponseDTO().getIdToken();
        String accessToken = authorizationResponseDTO.getSuccessResponseDTO().getAccessToken();
        String tokenType = authorizationResponseDTO.getSuccessResponseDTO().getTokenType();
        long validityPeriod = authorizationResponseDTO.getSuccessResponseDTO().getValidityPeriod();
        String authenticatedIdPs = authorizationResponseDTO.getAuthenticatedIDPs();
        String sessionState = authorizationResponseDTO.getSessionState();
        String state = authorizationResponseDTO.getState();
        String scope = authorizationResponseDTO.getSuccessResponseDTO().getScope();

        JWTClaimsSet.Builder jwtClaimsSet = new JWTClaimsSet.Builder();
        jwtClaimsSet.claim(ISSUER, getIssuer(authorizationResponseDTO));
        jwtClaimsSet.claim(AUDIENCE, authorizationResponseDTO.getClientId());

        long jwtValidityInMillis = OAuthServerConfiguration.getInstance().
                getJarmResponseJwtValidityPeriodInSeconds() * TO_MILLISECONDS;
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
        Date expirationTime = new Date(jwtValidityInMillis + currentTimeInMillis);

        jwtClaimsSet.claim(EXPIRATION_TIME, expirationTime);

        if (code != null) {
            jwtClaimsSet.claim(ACCESS_CODE, code);
        }

        if (accessToken != null) {
            jwtClaimsSet.claim(ACCESS_TOKEN, accessToken);
            jwtClaimsSet.claim(EXPIRES_IN, validityPeriod);
        }

        if (tokenType != null) {
            jwtClaimsSet.claim(TOKEN_TYPE, tokenType);
        }

        if (idToken != null) {
            jwtClaimsSet.claim(ID_TOKEN, idToken);
        }

        if (sessionState != null) {
            jwtClaimsSet.claim(SESSION_STATE, sessionState);
        }

        if (state != null) {
            jwtClaimsSet.claim(STATE, authorizationResponseDTO.getState());
        }

        if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
            jwtClaimsSet.claim(AUTHENTICATED_IDPS, authenticatedIdPs);
        }

        if (scope != null) {
            jwtClaimsSet.claim(SCOPE, scope);
        }

        return jwtClaimsSet.build();
    }

    protected JWTClaimsSet getErrorJWTClaimsSet(AuthorizationResponseDTO authorizationResponseDTO)
            throws OAuthSystemException {

        JWTClaimsSet.Builder jwtClaimsSet = new JWTClaimsSet.Builder();
        jwtClaimsSet.claim(ISSUER, getIssuer(authorizationResponseDTO));
        jwtClaimsSet.claim(AUDIENCE, authorizationResponseDTO.getClientId());
        jwtClaimsSet.claim(ERROR, authorizationResponseDTO.getErrorResponseDTO().getError());
        jwtClaimsSet.claim(ERROR_DESCRIPTION, authorizationResponseDTO.getErrorResponseDTO().getErrorDescription());

        long jwtValidityInMillis = OAuthServerConfiguration.getInstance().
                getJarmResponseJwtValidityPeriodInSeconds() * 1000;
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
        Date expirationTime = new Date(jwtValidityInMillis + currentTimeInMillis);

        jwtClaimsSet.claim(EXPIRATION_TIME, expirationTime);

        if (StringUtils.isNotBlank(authorizationResponseDTO.getState())) {
            jwtClaimsSet.claim(STATE, authorizationResponseDTO.getState());
        }
        if (StringUtils.isNotBlank(authorizationResponseDTO.getSessionState())) {
            jwtClaimsSet.claim(SESSION_STATE, authorizationResponseDTO.getSessionState());
        }

        return jwtClaimsSet.build();
    }

    protected String getJWTToken(AuthorizationResponseDTO authorizationResponseDTO, JWTClaimsSet jwtClaimsSet)
            throws OAuthSystemException {

        String jwtToken;
        try {
            String signingTenantDomain = authorizationResponseDTO.getSigningTenantDomain();
            JWSAlgorithm signatureAlgorithm = getJWTSignatureAlgorithm();
            if (JWSAlgorithm.NONE.equals(signatureAlgorithm)) {
                signatureAlgorithm = JWSAlgorithm.parse(new PlainJWT(jwtClaimsSet).serialize());
            }
            jwtToken = OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
        } catch (IdentityOAuth2Exception e) {
            authorizationResponseDTO.setError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Error in signing JWT.", OAuth2ErrorCodes.SERVER_ERROR);
            throw new OAuthSystemException("Error in signing JWT");
        }
        return jwtToken;
    }

    protected static JWSAlgorithm getJWTSignatureAlgorithm() throws OAuthSystemException {

        JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.NONE.getName());
        String sigAlg = OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm();
        if (isNotBlank(sigAlg)) {
            try {
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(sigAlg);
            } catch (IdentityOAuth2Exception e) {
                throw new OAuthSystemException("Configured signature algorithm : " + sigAlg + " is not supported.", e);
            }
        }
        return signatureAlgorithm;
    }

    protected static String getIssuer(AuthorizationResponseDTO authorizationResponseDTO) throws OAuthSystemException {

        try {
            return OAuth2Util.getIdTokenIssuer(authorizationResponseDTO.getSigningTenantDomain(),
                    authorizationResponseDTO.isMtlsRequest());
        } catch (IdentityOAuth2Exception e) {
            authorizationResponseDTO.setError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Error getting Id Token Issuer.", OAuth2ErrorCodes.SERVER_ERROR);
            throw new OAuthSystemException("Error getting Id Token Issuer.");
        }

    }
}
