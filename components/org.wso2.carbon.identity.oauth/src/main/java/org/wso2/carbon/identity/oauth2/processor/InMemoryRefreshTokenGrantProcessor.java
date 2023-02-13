/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.processor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

/**
 * TODO://add class level comment
 */
public class InMemoryRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log log = LogFactory.getLog(InMemoryRefreshTokenGrantProcessor.class);
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";

    /**
     * Validate refresh token in memory as a JWT and validate against the persisted refresh tokens in the database.
     *
     * @param tokenReqMessageContext Token Request Message Context
     * @return Valid RefreshTokenValidationDataDO
     * @throws IdentityOAuth2Exception if validation of refresh token fails due to any reason.
     */
    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) {
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
        //validate JWT token signature, expiry time, not before time
        try {
            SignedJWT signedJWT = OAuth2Util.getSignedJWT(tokenReq.getRefreshToken());
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
            }
            IdentityProvider identityProvider = OAuth2Util.getResidentIDPForIssuer(claimsSet.getIssuer());
            if (!OAuth2Util.validateSignature(signedJWT, identityProvider)) {
                throw new IdentityOAuth2Exception(("Invalid signature"));
            }
            if (!OAuth2Util.isActive(claimsSet.getExpirationTime())) {
                throw new IdentityOAuth2Exception("Invalid token. Expiry time exceeded");
                //TODO://handle error properly with invalid grant error
            }
            checkNotBeforeTime(claimsSet.getNotBeforeTime());
            Object consumerKey = claimsSet.getClaim("azp");
            if (!tokenReq.getClientId().equals(consumerKey)) {
                throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match");
            }
            //validate token against persisted invalid refresh tokens
            Object scopes = claimsSet.getClaim("scope");
            if (OAuthTokenPersistenceFactory.getInstance()
                    .getTokenManagementDAO().isInvalidRefreshToken(
                            OAuth2Util.getTokenIdentifier(tokenReq.getRefreshToken(),
                            tokenReq.getClientId()))) {
                //TODO://throw better error message and proper error handling to client
                throw new IdentityOAuth2Exception("Error while validating refresh token for invalid tokens");
            }
            //create new RefreshTokenValidationDO
            RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            validationDataDO.setGrantType("refresh_token");
            validationDataDO.setScope(OAuth2Util.getScopes(scopes));
            AuthenticatedUser user = OAuth2Util.getUserFromUserName(claimsSet.getSubject());
            user.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
            validationDataDO.setAuthorizedUser(user);
            validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            return validationDataDO;
        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) {
            //TODO:// If the token is opaque, delete the existing token from the DB. (migration)
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
        //If JWT make the old refresh token inactive and persist it
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
        AccessTokenDO oldAccessTokenBean = new AccessTokenDO();
        oldAccessTokenBean.setConsumerKey(tokenReq.getClientId());
        String tokenId = UUID.randomUUID().toString();
        oldAccessTokenBean.setTokenId(tokenId);
        oldAccessTokenBean.setGrantType(tokenReq.getGrantType());
        oldAccessTokenBean.setRefreshToken(OAuth2Util.getTokenIdentifier(tokenReq.getRefreshToken(),
                tokenReq.getClientId()));
        oldAccessTokenBean.setRefreshTokenIssuedTime(oldAccessToken.getIssuedTime());
        oldAccessTokenBean.setRefreshTokenValidityPeriodInMillis(oldAccessToken.getValidityPeriodInMillis());
        oldAccessTokenBean.setScope(oldAccessToken.getScope());
        oldAccessTokenBean.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE);
        oldAccessTokenBean.setAuthzUser(oldAccessToken.getAuthorizedUser());

        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .invalidateAndCreateNewAccessToken(null, oldAccessTokenBean.getTokenState(), tokenReq.getClientId(),
                        oldAccessTokenBean.getTokenId(), oldAccessTokenBean, null, oldAccessTokenBean.getGrantType());
    }

    @Override
    public void addUserAttributesToCache(AccessTokenDO accessTokenBean, OAuthTokenReqMessageContext msgCtx) {
        //do nothing
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean, String tokenType) {

        Timestamp timestamp = new Timestamp(new Date().getTime());
        String tokenId = UUID.randomUUID().toString();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(tokenType);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());
        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            //not possible to determine the previous access token, hence setting default value false.
            accessTokenDO.setIsConsentedToken(false);
            tokReqMsgCtx.setConsentedToken(false);
        }
        return accessTokenDO;
    }
    private boolean checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Token is used before Not_Before_Time." +
                            ", Not Before Time(ms) : " + notBeforeTimeMillis +
                            ", TimeStamp Skew : " + timeStampSkewMillis +
                            ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }
        return true;
    }
}
