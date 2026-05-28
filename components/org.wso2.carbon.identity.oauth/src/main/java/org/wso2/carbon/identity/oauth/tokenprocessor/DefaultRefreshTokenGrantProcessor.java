/*
 * Copyright (c) 2023-2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.cache.RefreshTokenCache;
import org.wso2.carbon.identity.oauth.cache.RefreshTokenCacheEntry;
import org.wso2.carbon.identity.oauth.cache.RefreshTokenCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.GracefulRefreshTokenRotation;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of @RefreshTokenProcessor responsible for handling refresh token persistence logic.
 */
public class DefaultRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log log = LogFactory.getLog(DefaultRefreshTokenGrantProcessor.class);
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";
    public static final int LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT = 10;

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(tokenReq.getClientId(), tokenReq.getRefreshToken());
        validatePersistedAccessToken(validationBean, tokenReq.getClientId());
        validateReuseRefreshToken(validationBean, tokenReq.getClientId(), tokenReq.getTenantDomain());
        return validationBean;
    }

    /**
     * When graceful refresh token rotation is enabled for the application:
     * Flips the in-memory token state from {@code GRACEFULLY_ROTATED} back to {@code ACTIVE} so that
     * downstream validation (validateRefreshTokenStatus, setRefreshTokenData, etc.) sees {@code ACTIVE}.
     * The DB value stays {@code GRACEFULLY_ROTATED}.
     * Rejects the request if the reuse count has already reached the app-configured limit.
     * Missing or unparseable reuse-count attributes are treated as zero (covers first-time issuance,
     * legacy rows, and custom persistence implementations)
     * No-op when graceful rotation is disabled or the application cannot be resolved.
     */
    private void validateReuseRefreshToken(RefreshTokenValidationDataDO validationBean, String clientId,
                                             String tenantDomain) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = StringUtils.isNotBlank(tenantDomain)
                    ? OAuth2Util.getAppInformationByClientId(clientId, tenantDomain)
                    : OAuth2Util.getAppInformationByClientIdOnly(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " + clientId, e);
        }
        if (oAuthAppDO == null || !oAuthAppDO.isGracefulRefreshTokenRotationEnabled()) {
            return;
        }
        //Store the token status in memory in a consistent format so it can be validated easily later
        if (OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED.equals(
                validationBean.getRefreshTokenState())) {
            validationBean.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        }
        //Reject the request if the grace window has already closed.
        AccessTokenExtendedAttributes extendedTokenAttributes = validationBean.getAccessTokenExtendedAttributes();
        if (extendedTokenAttributes != null && extendedTokenAttributes.getParameters() != null) {
            String allowedGracePeriod = extendedTokenAttributes.getParameters()
                    .get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS);
            if (StringUtils.isNotBlank(allowedGracePeriod)) {
                long allowedGracePeriodInLong;
                try {
                    allowedGracePeriodInLong = Long.parseLong(allowedGracePeriod);
                } catch (NumberFormatException e) {
                    log.warn("Unparseable graceful refresh token grace validity '" + allowedGracePeriod
                            + "' for client: " + clientId + ". Rejecting refresh request as grace-expired.");
                    throw new IdentityOAuth2Exception("Refresh token grace period has expired.");
                }
                long issuedTime = validationBean.getIssuedTime().getTime();
                if (OAuth2Util.getTimeToExpire(issuedTime, allowedGracePeriodInLong, true) < 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("Refresh token grace window has closed for client: " + clientId
                                + ". Grace validity (ms): " + allowedGracePeriodInLong + ". Rejecting request.");
                    }
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                                OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                OAuthConstants.LogConstants.ActionIDs.VALIDATE_REFRESH_TOKEN)
                                .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                                .inputParam(LogConstants.InputKeys.TENANT_DOMAIN, tenantDomain)
                                .inputParam("graceful grace validity (ms)", allowedGracePeriodInLong)
                                .resultMessage("Refresh token grace period has expired.")
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                    }
                    throw new IdentityOAuth2Exception("Refresh token grace period has expired.");
                }
            }
        }
        //Enforce reuse limit.
        AccessTokenExtendedAttributes extendedAttributes = validationBean.getAccessTokenExtendedAttributes();
        if (extendedAttributes == null || extendedAttributes.getParameters() == null) {
            return;
        }
        String allowedReuseCount = extendedAttributes.getParameters()
                .get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
        if (StringUtils.isBlank(allowedReuseCount)) {
            return;
        }
        int reuseCount;
        try {
            reuseCount = Integer.parseInt(allowedReuseCount);
        } catch (NumberFormatException e) {
            log.warn("Unparseable graceful refresh token reuse count '" + allowedReuseCount
                    + "' for client: " + clientId + ". Rejecting refresh request.");
            throw new IdentityOAuth2Exception("Refresh token grace period has expired.");
        }
        int allowedReUseLimit = oAuthAppDO.getGracefulRefreshTokenReuseLimit();
        if (reuseCount >= allowedReUseLimit) {
            if (log.isDebugEnabled()) {
                log.debug("Refresh token reuse limit (" + allowedReUseLimit + ") reached for client: " + clientId
                        + ". Current reuse count: " + reuseCount + ". Rejecting refresh request.");
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_REFRESH_TOKEN)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .inputParam(LogConstants.InputKeys.TENANT_DOMAIN, tenantDomain)
                        .inputParam("graceful reuse count", reuseCount)
                        .configParam("allowed graceful reuse limit", allowedReUseLimit)
                        .resultMessage("Refresh token has reached the configured graceful reuse limit.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            throw new IdentityOAuth2Exception("Refresh token has reached the configured graceful reuse limit.");
        }
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                                String userStoreDomain, String clientId) throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("Previous access token (hashed): %s", DigestUtils.sha256Hex(
                        oldAccessToken.getAccessToken())));
            }
        }

        OAuthAppDO oAuthAppDO = (OAuthAppDO) tokenReqMessageContext.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
        if (oAuthAppDO != null && isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled())
                && oAuthAppDO.isGracefulRefreshTokenRotationEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Graceful refresh token rotation is enabled for client: " + clientId
                        + ". Processing token with graceful rotation.");
            }
            int tenantId = IdentityTenantUtil.getTenantId(
                    tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());
            RefreshTokenCacheKey reuseCountCacheKey =
                    new RefreshTokenCacheKey(oldAccessToken.getTokenId());
            int reuseCount = getReuseCount(oldAccessToken.getTokenId(), clientId, reuseCountCacheKey, tenantId,
                    userStoreDomain);
            if (reuseCount >= oAuthAppDO.getGracefulRefreshTokenReuseLimit()) {
                if (log.isDebugEnabled()) {
                    log.debug("Fresh reuse count (" + reuseCount + ") has reached the configured limit ("
                            + oAuthAppDO.getGracefulRefreshTokenReuseLimit() + ") for client: " + clientId
                            + ". Rejecting refresh request.");
                }
                throw new IdentityOAuth2Exception(
                        "Refresh token has reached the configured graceful reuse limit.");
            }
            // Write-through: stamp the reuse count on the old token's extended attributes before the DB write, so that
            // any concurrent reuse attempts will see the updated count and get rejected when the limit is reached.
            updateRefreshGraceReuseLimit(oldAccessToken, reuseCount);

            // Revoke whichever token in the old↔successor pair is now stale: on reuse the successor
            // is revoked; on the first rotation a predecessor (if any) is revoked via JOIN lookup.
            // Returns true when a successor was found (= reuse), false for a fresh first-rotation.
            String tenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
            boolean isRefreshTokenReuse = revokeOverlappingTokens(oldAccessToken, userStoreDomain, clientId,
                    tenantDomain);
            // Derive the reuse count to stamp on the new token row: existing count + 1 on reuse,
            // or the existing count unchanged for a fresh first rotation.
            int updatedReuseCount = computeReuseCount(oldAccessToken, isRefreshTokenReuse);
            if (log.isDebugEnabled()) {
                log.debug((isRefreshTokenReuse
                        ? "Refresh token reuse detected for client: " + clientId
                        : "First graceful rotation for client: " + clientId)
                        + ". New reuse count: " + updatedReuseCount + ".");
            }
            // Mirror the new reuse count onto the in-memory old-token object so that the value
            // is available when the DAO assembles the extended-attributes JSON for the old row.
            updateReuseCountOnOldAccessToken(oldAccessToken, updatedReuseCount);
            Map<String, String> toeknAttributeRowUpdates = new HashMap<>();
            if (updatedReuseCount > 0) {
                toeknAttributeRowUpdates.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                        Integer.toString(updatedReuseCount));
                toeknAttributeRowUpdates.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID,
                        accessTokenBean.getTokenId());
            }

            // On the first rotation, stamp the grace deadline (elapsed + grace period) as an extended attribute
            // so that downstream expiry checks can detect when the grace window has closed.
            // On subsequent reuses the deadline is already anchored; we skip updating the old row's state.
            String oldTokenStateId = null;
            String oldTokenNewState = null;
            if (updatedReuseCount == 0) {
                long elapsedSinceRefreshIssuedMillis =
                        System.currentTimeMillis() - oldAccessToken.getIssuedTime().getTime();
                long graceMillis =
                        TimeUnit.SECONDS.toMillis(oAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod());
                long graceValidityMillis = elapsedSinceRefreshIssuedMillis + graceMillis;
                oldTokenStateId = UUID.randomUUID().toString();
                oldTokenNewState = OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED;
                toeknAttributeRowUpdates.put(
                        GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS,
                        Long.toString(graceValidityMillis));
                toeknAttributeRowUpdates.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID,
                        accessTokenBean.getTokenId());
                if (log.isDebugEnabled()) {
                    log.debug("Stamping grace deadline of " + graceValidityMillis + " ms on old token for client: "
                            + clientId + ". Token id: " + oldAccessToken.getTokenId()
                            + ". State will be set to GRACEFULLY_ROTATED.");
                }
            }

            // Atomically mark the old token as GRACEFULLY_ROTATED (first rotation) or update its
            // extended attributes (reuse), and insert the new access token — all in one DB transaction
            // so a crash between the two writes cannot leave the token table in an inconsistent state.
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                    .gracefullyRotateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                            oldAccessToken.getIssuedTime(),
                            oldTokenStateId, oldTokenNewState, clientId, accessTokenBean, userStoreDomain,
                            oldAccessToken.getGrantType(), toeknAttributeRowUpdates);
            // Write-through: update cache with the new reuse count after the DB write succeeds.
            RefreshTokenCache.getInstance().addToCache(reuseCountCacheKey,
                    new RefreshTokenCacheEntry(updatedReuseCount), tenantId);
            if (log.isDebugEnabled()) {
                log.debug("Updated graceful reuse count cache to " + updatedReuseCount + " for token id: "
                        + oldAccessToken.getTokenId() + " after DB write for client: " + clientId + ".");
            }
            return;
        }

        // set the previous access token state to "INACTIVE" and store new access token in single db connection
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .invalidateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, clientId, UUID.randomUUID().toString(),
                        accessTokenBean, userStoreDomain, oldAccessToken.getGrantType());
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean, String tokenType)
            throws IdentityOAuth2Exception {

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
        int appTenantId = IdentityTenantUtil.getTenantId(tokenReq.getTenantDomain());
        accessTokenDO.setAppResidentTenantId(appTenantId);
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());

        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            String previousGrantType = validationBean.getGrantType();
            // Check if the previous grant type is consent refresh token type or not.
            if (!OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(previousGrantType)) {
                // If the previous grant type is not a refresh token, then check if it's a consent token or not.
                if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(previousGrantType)) {
                    accessTokenDO.setIsConsentedToken(true);
                }
            } else {
                /* When previousGrantType == refresh_token, we need to check whether the original grant type
                 is consented or not. */
                accessTokenDO.setIsConsentedToken(validationBean.isConsented());
            }

            if (accessTokenDO.isConsentedToken()) {
                tokReqMsgCtx.setConsentedToken(true);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Setting access token extended attributes for token request in refresh token flow for client: "
                    + tokenReq.getClientId() + " with token id: " + tokenId);
        }
        if (tokenReq.getAccessTokenExtendedAttributes() != null &&
                tokenReq.getAccessTokenExtendedAttributes().getParameters() != null) {
            HashMap<String, String> parameters =
                    new HashMap<>(tokenReq.getAccessTokenExtendedAttributes().getParameters());
            parameters.remove(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
            parameters.remove(
                    GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_GRACE_VALIDITY_IN_MILLIS);
            parameters.remove(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID);
            if (!parameters.isEmpty()) {
                accessTokenDO.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(parameters));
            }
        }
        return accessTokenDO;
    }

    private boolean validatePersistedAccessToken(RefreshTokenValidationDataDO validationBean, String clientId)
            throws IdentityOAuth2Exception {

        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid Refresh Token provided for Client with Client Id : %s", clientId));
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
        }
        return true;
    }

    @Override
    public boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
                                        String userStoreDomain) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug(String.format("Evaluating refresh token. Token value(hashed): %s, Token state: %s",
                        DigestUtils.sha256Hex(tokenReq.getRefreshToken()), validationBean.getRefreshTokenState()));
            } else {
                log.debug(String.format("Evaluating refresh token. Token state: %s",
                        validationBean.getRefreshTokenState()));
            }
        }
        if (!OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(validationBean.getRefreshTokenState())) {
            /* if refresh token is not in active state, check whether there is an access token issued with the same
             * refresh token.
             */
            List<AccessTokenDO> accessTokenBeans = getAccessTokenBeans(tokenReq, validationBean, userStoreDomain);
            for (AccessTokenDO token : accessTokenBeans) {
                if (tokenReq.getRefreshToken() != null && tokenReq.getRefreshToken().equals(token.getRefreshToken())
                        && (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(token.getTokenState())
                        || OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(token.getTokenState()))) {
                    return true;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug(String.format("Refresh token: %s is not the latest", tokenReq.getRefreshToken()));
            }
            return false;
        }
        return true;
    }

    /**
     * Revoke the stale partner of {@code oldAccessToken} using the {@code successorTokenId} linkage.
     * If {@code oldAccessToken} carries a {@code successorTokenId} extended attribute,
     * the token it points to is stale and is revoked. Returns {@code true} to signal reuse so the
     * caller increments the reuse counter.
     * If no such attribute is present, a JOIN-based DAO query looks for any token
     * whose own {@code successorTokenId} attribute equals {@code oldAccessToken.tokenId} (i.e., a
     * predecessor that still has an active row). If found it is revoked. Returns {@code false}.
     */
    private boolean revokeOverlappingTokens(RefreshTokenValidationDataDO oldAccessToken, String userStoreDomain,
                                            String clientId, String tenantDomain) throws IdentityOAuth2Exception {

        // Case A: old token already has a successor → this is a reuse.
        String successorTokenId = readSuccessorTokenId(oldAccessToken);
        if (StringUtils.isNotBlank(successorTokenId)) {
            String successorAccessToken = OAuthTokenPersistenceFactory.getInstance()
                    .getAccessTokenDAOImpl(clientId)
                    .getAccessTokenByTokenId(successorTokenId);
            if (StringUtils.isNotBlank(successorAccessToken)) {
                revokeAndClearCache(successorAccessToken, successorTokenId, clientId, tenantDomain);
            } else if (log.isDebugEnabled()) {
                log.debug("Successor token id " + successorTokenId
                        + " has no active access token row for client: " + clientId
                        + ". Treating as reuse anyway.");
            }
            return true;
        }

        // Case B: look for a predecessor whose successorTokenId points at the current old token.
        AccessTokenDO predecessor = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAOImpl(clientId)
                .getActiveTokenByExtendedAttribute(
                        GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID,
                        oldAccessToken.getTokenId(), userStoreDomain);
        if (predecessor != null) {
            revokeAndClearCache(predecessor.getAccessToken(), predecessor.getTokenId(), clientId, tenantDomain);
        } else if (log.isDebugEnabled()) {
            log.debug("No predecessor token referencing old token id "
                    + oldAccessToken.getTokenId() + " for client: " + clientId
                    + " during graceful rotation.");
        }
        return false;
    }

    private String readSuccessorTokenId(RefreshTokenValidationDataDO oldAccessToken) {

        AccessTokenExtendedAttributes attrs = oldAccessToken.getAccessTokenExtendedAttributes();
        if (attrs == null || attrs.getParameters() == null) {
            return null;
        }
        return attrs.getParameters()
                .get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_SUCCESSOR_TOKEN_ID);
    }

    private void revokeAndClearCache(String plainAccessToken, String tokenId, String clientId, String tenantDomain)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking stale token (hashed): " + DigestUtils.sha256Hex(plainAccessToken)
                    + " tokenId: " + tokenId + " for client: " + clientId
                    + " during graceful refresh token rotation.");
        }
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .revokeAccessTokens(new String[]{plainAccessToken});
        AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(
                new AuthorizationGrantCacheKey(plainAccessToken), tokenId);
        OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(plainAccessToken), tenantDomain);
    }

    /**
     * Compute the reuse count to persist on the new token row. Reads the existing count from
     * {@code oldAccessToken}'s extended attributes (defaulting to 0 when absent or unparseable)
     * and increments by one only when this rotation is a reuse of an already-rotated row.
     */
    private int computeReuseCount(RefreshTokenValidationDataDO oldAccessToken, boolean isRefreshTokenReuse) {

        int oldCount = readPersistedReuseCount(oldAccessToken);
        return isRefreshTokenReuse ? oldCount + 1 : oldCount;
    }

    /**
     * Read the graceful reuse count stored in {@code tokenData}'s extended attributes.
     * Returns 0 when absent, blank, or unparseable.
     */
    private int readPersistedReuseCount(RefreshTokenValidationDataDO tokenData) {

        AccessTokenExtendedAttributes attributes = tokenData.getAccessTokenExtendedAttributes();
        if (attributes == null || attributes.getParameters() == null) {
            return 0;
        }
        String rawCount = attributes.getParameters()
                .get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
        return parseReuseCount(rawCount);
    }

    /**
     * Returns the current graceful reuse count for the given token, checking the cache first and falling
     * back to a DB read on a cache miss. Populates the cache from the DB value on miss.
     */
    private int getReuseCount(String tokenId, String clientId,
                              RefreshTokenCacheKey cacheKey,
                              int tenantId, String userStoreDomain) throws IdentityOAuth2Exception {

        RefreshTokenCacheEntry cacheEntry =
                RefreshTokenCache.getInstance().getValueFromCache(cacheKey, tenantId);
        if (cacheEntry != null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache hit for graceful reuse count of token id: " + tokenId
                        + ". Cached count: " + cacheEntry.getGracefulReuseCount() + ".");
            }
            return cacheEntry.getGracefulReuseCount();
        }
        if (log.isDebugEnabled()) {
            log.debug("Cache miss for graceful reuse count of token id: " + tokenId
                    + ". Falling back to DB read for client: " + clientId + ".");
        }
        String initialRawCount = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAOImpl(clientId)
                .getAccessTokenExtendedAttributeValue(
                        tokenId, GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                        userStoreDomain);
        int initialCount = parseReuseCount(initialRawCount);
        if (log.isDebugEnabled()) {
            log.debug("Loaded graceful reuse count " + initialCount + " from DB for token id: " + tokenId
                    + ". Populating cache.");
        }
        RefreshTokenCache.getInstance().addToCacheOnRead(cacheKey,
                new RefreshTokenCacheEntry(initialCount), tenantId);
        return initialCount;
    }

    private int parseReuseCount(String raw) {

        if (StringUtils.isBlank(raw)) {
            return 0;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Update the in-memory extended attributes of the old token row with the new reuse count. When
     * {@code updatedReuseCount} is zero and no attributes exist yet, this is a no-op (avoids creating
     * empty attribute containers for the first-rotation case).
     */
    private void updateReuseCountOnOldAccessToken(RefreshTokenValidationDataDO oldAccessToken,
                                                  int updatedReuseCount) {

        if (updatedReuseCount == 0 && oldAccessToken.getAccessTokenExtendedAttributes() == null) {
            return;
        }
        AccessTokenExtendedAttributes attributes = oldAccessToken.getAccessTokenExtendedAttributes();
        if (attributes == null) {
            attributes = new AccessTokenExtendedAttributes(new HashMap<>());
            oldAccessToken.setAccessTokenExtendedAttributes(attributes);
        } else if (attributes.getParameters() == null) {
            attributes.setParameters(new HashMap<>());
        }
        attributes.getParameters().put(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                Integer.toString(updatedReuseCount));
    }

    private void updateRefreshGraceReuseLimit(RefreshTokenValidationDataDO oldAccessToken, int reuseCount) {

        AccessTokenExtendedAttributes attributes = oldAccessToken.getAccessTokenExtendedAttributes();
        if (attributes == null) {
            attributes = new AccessTokenExtendedAttributes(new HashMap<>());
            oldAccessToken.setAccessTokenExtendedAttributes(attributes);
        } else if (attributes.getParameters() == null) {
            attributes.setParameters(new HashMap<>());
        }
        attributes.getParameters().put(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                Integer.toString(reuseCount));
    }

    private boolean isRenewRefreshToken(String renewRefreshToken) {

        if (StringUtils.isNotBlank(renewRefreshToken)) {
            if (log.isDebugEnabled()) {
                log.debug("Reading the Oauth application specific renew " +
                        "refresh token value as " + renewRefreshToken + " from the IDN_OIDC_PROPERTY table");
            }
            return Boolean.parseBoolean(renewRefreshToken);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Reading the global renew refresh token value from the identity.xml");
            }
            return OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();
        }
    }

    private List<AccessTokenDO> getAccessTokenBeans(OAuth2AccessTokenReqDTO tokenReq,
                                                    RefreshTokenValidationDataDO validationBean, String userStoreDomain)
            throws IdentityOAuth2Exception {

        List<AccessTokenDO> accessTokenBeans = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAOImpl(tokenReq.getClientId())
                .getLatestAccessTokens(tokenReq.getClientId(), validationBean.getAuthorizedUser(), userStoreDomain,
                        OAuth2Util.buildScopeString(validationBean.getScope()),
                        validationBean.getTokenBindingReference(), true, LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT);
        if (accessTokenBeans == null || accessTokenBeans.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No previous access tokens found. User: %s, client: %s, scope: %s",
                        validationBean.getAuthorizedUser(), tokenReq.getClientId(),
                        OAuth2Util.buildScopeString(validationBean.getScope())));
            }
            throw new IdentityOAuth2Exception("No previous access tokens found");
        }
        return accessTokenBeans;
    }

    /**
     * Add user attributes to cache against the new access token.
     * @param accessTokenBean Access token data object.
     * @param msgCtx Token request message context.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void addUserAttributesToCache(AccessTokenDO accessTokenBean, OAuthTokenReqMessageContext msgCtx)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) msgCtx.getProperty(PREV_ACCESS_TOKEN);
        if (oldAccessToken == null || StringUtils.isBlank(oldAccessToken.getAccessToken())) {
            return;
        }
        AuthorizationGrantCacheKey oldAuthorizationGrantCacheKey = new AuthorizationGrantCacheKey(oldAccessToken
                .getAccessToken());
        if (log.isDebugEnabled()) {
            log.debug("Getting AuthorizationGrantCacheEntry using access token id: " + accessTokenBean.getTokenId());
        }
        AuthorizationGrantCacheEntry grantCacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey,
                        oldAccessToken.getTokenId());

        /*
         * When multiple concurrent refresh token requests occur using the same refresh token,
         * other nodes in the cluster may revoke the cache entries associated with the previous token.
         * However, since the current node is unaware of these deletions, it may fail to retrieve the
         * cache entry for the token. This block ensures that the cache is fetched using the given token ID,
         * even if the cache entry related to the token is marked as deleted.
         * This is done for JWT tokens and federated users only.
         */
        if (grantCacheEntry == null) {
            if (msgCtx.getAuthorizedUser() != null && msgCtx.getAuthorizedUser().isFederatedUser()) {
                OAuthAppDO oAuthAppDO = (OAuthAppDO) msgCtx.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
                if (oAuthAppDO != null && OAuth2Util.JWT.equals(oAuthAppDO.getTokenType())) {
                    grantCacheEntry = AuthorizationGrantCache.getInstance()
                            .getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey, oldAccessToken.getTokenId(),
                                    OAuth2Constants.STORE_OPERATION);
                }
            }
        }

        if (grantCacheEntry != null) {
            if (log.isDebugEnabled()) {
                log.debug("Getting user attributes cached against the previous access token with access token id: " +
                        oldAccessToken.getTokenId());
            }
            AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessTokenBean
                    .getAccessToken());

            // Pre-compute graceful rotation validity before mutating the entry.
            OAuthAppDO oAuthAppDO = (OAuthAppDO) msgCtx.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
            // Only restore the old cache entry with a grace TTL on the first rotation. On reuses the entry
            // already carries the original deadline; recomputing elapsed would push it forward.
            boolean isGracefulRotation = oAuthAppDO != null
                    && isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled())
                    && oAuthAppDO.isGracefulRefreshTokenRotationEnabled()
                    && readPersistedReuseCount(oldAccessToken) == 0;
            long gracefulValidityNanos = 0;
            if (isGracefulRotation) {
                long elapsedSinceRefreshIssuedMillis =
                        System.currentTimeMillis() - oldAccessToken.getIssuedTime().getTime();
                long graceMillis =
                        TimeUnit.SECONDS.toMillis(oAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod());
                gracefulValidityNanos = TimeUnit.MILLISECONDS.toNanos(elapsedSinceRefreshIssuedMillis + graceMillis);
            }

            if (StringUtils.isNotBlank(accessTokenBean.getTokenId())) {
                grantCacheEntry.setTokenId(accessTokenBean.getTokenId());
            } else {
                grantCacheEntry.setTokenId(null);
            }

            // Setting the validity period of the cache entry to be same as the validity period of the refresh token.
            grantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(accessTokenBean.getRefreshTokenValidityPeriodInMillis()));

            // This new method has introduced in order to resolve a regression occurred : wso2/product-is#4366.
            AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(oldAuthorizationGrantCacheKey,
                    oldAccessToken.getTokenId());
            // If refresh token persistence is disabled and the user is not federated, do not store user attributes.
            // When a user's profile is updated after the token is issued, the cache cannot be cleared because
            // the Identity Server will not persist either the refresh token or the access token. As a result,
            // outdated user attribute data would be returned on the next refresh grant.
            // To mitigate this, user attributes are set to null.
            if (!OAuth2Util.isRefreshTokenPersistenceEnabled() && !accessTokenBean.getAuthzUser().isFederatedUser()) {
                grantCacheEntry.setUserAttributes(null);
            }
            AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey, grantCacheEntry);

            // When graceful refresh token rotation is enabled, re-add the old cache entry under the old access
            // token key with the graceful validity period so that the old refresh token remains usable within
            // the grace window.
            if (isGracefulRotation) {
                if (log.isDebugEnabled()) {
                    log.debug("Re-adding authorization grant cache entry for old access token id: "
                            + oldAccessToken.getTokenId() + " with grace validity: " + gracefulValidityNanos
                            + " ns so the old refresh token remains usable within the grace window.");
                }
                grantCacheEntry.setTokenId(oldAccessToken.getTokenId());
                grantCacheEntry.setValidityPeriod(gracefulValidityNanos);
                AuthorizationGrantCache.getInstance().addToCacheByToken(oldAuthorizationGrantCacheKey,
                        grantCacheEntry);
            }
        }
    }
}
