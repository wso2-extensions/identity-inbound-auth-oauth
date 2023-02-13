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

package org.wso2.carbon.identity.oauth2;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.text.ParseException;
import java.util.UUID;

/**
 * Handles oauth2 token revocation when persistence layer exists.
 */
public class InMemoryOAuth2RevocationProcessor implements OAuth2RevocationProcessor {
    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception, UserIdNotFoundException {

        //TODO://token binding is not supported ATM.
        //TODO://not clearing or serving from oauth cache ATM
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        //TODO://should dao invalidation be synchronized for user and scope (user Id not available though ATM)
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .invalidateAndCreateNewAccessToken(null, accessTokenDO.getTokenState(),
                            accessTokenDO.getConsumerKey(),
                            accessTokenDO.getTokenId(), accessTokenDO, null, null);
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {
        //TODO://token binding is not supported ATM.
        //TODO://not clearing or serving from oauth cache ATM
        refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        AccessTokenDO accessTokenBean = new AccessTokenDO();
        accessTokenBean.setConsumerKey(revokeRequestDTO.getConsumerKey());
        String tokenId = UUID.randomUUID().toString();
        accessTokenBean.setTokenId(tokenId);
        accessTokenBean.setRefreshToken(OAuth2Util.getTokenIdentifier(revokeRequestDTO.getToken(),
                revokeRequestDTO.getConsumerKey()));
        accessTokenBean.setRefreshTokenIssuedTime(refreshTokenDO.getIssuedTime());
        accessTokenBean.setRefreshTokenValidityPeriodInMillis(refreshTokenDO.getValidityPeriodInMillis());
        accessTokenBean.setScope(refreshTokenDO.getScope());
        accessTokenBean.setTokenState(refreshTokenDO.getRefreshTokenState());
        accessTokenBean.setAuthzUser(refreshTokenDO.getAuthorizedUser());
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .invalidateAndCreateNewAccessToken(null, accessTokenBean.getTokenState(),
                        revokeRequestDTO.getConsumerKey(),
                        accessTokenBean.getTokenId(), accessTokenBean, null, null);
    }

    @Override
    public RefreshTokenValidationDataDO getRevocableRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

        isJWTToken(revokeRequestDTO);
        SignedJWT signedJWT = getSignedJWT(revokeRequestDTO);
        JWTClaimsSet claimsSet = getJWTClaimSet(signedJWT);
        validateJWT(signedJWT, claimsSet, revokeRequestDTO);
        //validate token against persisted invalid refresh tokens
        RefreshTokenValidationDataDO validationDataDO = OAuthTokenPersistenceFactory.getInstance()
                .getTokenManagementDAO().validateRefreshToken(revokeRequestDTO.getConsumerKey(),
                        OAuth2Util.getTokenIdentifier(revokeRequestDTO.getToken(),
                                revokeRequestDTO.getConsumerKey()));
        //TODO://check if refresh token in request is already persisted as an inactive or revoked access token in db
        //TODO://check in the rule engine if token is revoked indirectly
        //returns refresh token in every state
        if (StringUtils.isEmpty(validationDataDO.getRefreshTokenState())) {
            //set expiration state according to jwt claim in it
            if (OAuth2Util.isActive(claimsSet.getExpirationTime())) {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            //set other fields from jwt claims
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            validationDataDO.setScope(OAuth2Util.getScopes(claimsSet.getClaim("scope")));
            AuthenticatedUser user = OAuth2Util.getUserFromUserName(claimsSet.getSubject());
            user.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
            validationDataDO.setAuthorizedUser(user);
        }
        return validationDataDO;
    }

    @Override
    public AccessTokenDO getRevocableAccessToken(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = null;
        isJWTToken(revokeRequestDTO);
        SignedJWT signedJWT = getSignedJWT(revokeRequestDTO);
        JWTClaimsSet claimsSet = getJWTClaimSet(signedJWT);
        validateJWT(signedJWT, claimsSet, revokeRequestDTO);

        //check if token is already revoked and persisted in the database if so return nothing
        String accessTokenIdentifier = OAuth2Util.getTokenIdentifier(revokeRequestDTO.getToken(),
                revokeRequestDTO.getConsumerKey());
        //TODO:// check the cache if caching enabled?
        if (!OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().isInvalidToken(accessTokenIdentifier)) {
            //TODO://check in the rule engine if token is revoked indirectly
            //TODO://check if acccess token in request is already persisted as an inactive/revoked token in db
            accessTokenDO = new AccessTokenDO();
            String tokenId = UUID.randomUUID().toString();
            accessTokenDO.setTokenId(tokenId);
            accessTokenDO.setAccessToken(OAuth2Util.getTokenIdentifier(revokeRequestDTO.getToken(),
                    revokeRequestDTO.getConsumerKey()));
            //consumer key from the azp claim in access token JWT
            accessTokenDO.setConsumerKey((String) claimsSet.getClaim("azp"));
            //check if token is expired and set tokenState EXPIRED
            if (OAuth2Util.isActive(claimsSet.getExpirationTime())) {
                accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            accessTokenDO.setIsConsentedToken(false); //TODO:// is consent field is not supported ATM
            //set other fields from jwt claims
            accessTokenDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            accessTokenDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            //TODO://we do not know the grant type ATM
            accessTokenDO.setScope(OAuth2Util.getScopes(claimsSet.getClaim("scope")));
            AuthenticatedUser user = OAuth2Util.getUserFromUserName(claimsSet.getSubject());
            user.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
            accessTokenDO.setAuthzUser(user);
        }
        return accessTokenDO;
        //TODO:// add to cache if caching enabled?
    }

    @Override
    public boolean validateTokenBinding(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO) {

        //TODO:// decide if token binding should be supported with non persistence scenario
        return false;
    }


    private void isJWTToken(OAuthRevocationRequestDTO revokeRequestDTO) throws IdentityOAuth2Exception {
        if (!OAuth2Util.isJWT(revokeRequestDTO.getToken())) {
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
    }

    private SignedJWT getSignedJWT(OAuthRevocationRequestDTO revokeRequestDTO) throws IdentityOAuth2Exception {
        try {
            return OAuth2Util.getSignedJWT(revokeRequestDTO.getToken());
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
    }

    private JWTClaimsSet getJWTClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {
        JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
            }
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
        return claimsSet;
    }

    private void validateJWT(SignedJWT signedJWT, JWTClaimsSet claimsSet, OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

        IdentityProvider identityProvider;
        try {
            identityProvider = OAuth2Util.getResidentIDPForIssuer(claimsSet.getIssuer());
            if (!OAuth2Util.validateSignature(signedJWT, identityProvider)) {
                throw new IdentityOAuth2Exception(("Invalid signature"));
            }
            Object consumerKey = claimsSet.getClaim("azp");
            if (!revokeRequestDTO.getConsumerKey().equals(consumerKey)) {
                throw new IdentityOAuth2Exception("Invalid client. Consumer key does not match in the token.");
            }
        }  catch (ParseException | JOSEException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
    }
}
