/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_CODE;

/**
 * A class that provides OIDC claims for JWT access tokens.
 */
public class JWTAccessTokenOIDCClaimsHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(JWTAccessTokenOIDCClaimsHandler.class);

    private static final String OAUTH2 = "oauth2";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        Map<String, Object> claims = getUserClaimsInOIDCDialect(request);
        return setClaimsToJwtClaimSet(builder, claims);
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        /*
          Handling the user attributes for the access token. There is no requirement of the consent
          to manage user attributes for the access token.
         */
        Map<String, Object> claims = getUserClaimsInOIDCDialect(request);
        return setClaimsToJwtClaimSet(builder, claims);
    }

    /**
     * Get user claims in OIDC dialect.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext
     * @return User claims in OIDC dialect
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        Map<String, Object> userClaimsInOIDCDialect;

        Map<ClaimMapping, String> userAttributes = getCachedUserAttributes(requestMsgCtx, false);
        if ((userAttributes.isEmpty() || isOrganizationSwitchGrantType(requestMsgCtx))
                && (isLocalUser(requestMsgCtx.getAuthorizedUser())
                || isOrganizationSsoUserSwitchingOrganization(requestMsgCtx.getAuthorizedUser()))) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache against the access token or authorization code. " +
                        "Retrieving claims for local user: " + requestMsgCtx.getAuthorizedUser() + " from userstore.");
            }
            if (!StringUtils.equals(requestMsgCtx.getAuthorizedUser().getUserResidentOrganization(),
                    requestMsgCtx.getAuthorizedUser().getAccessingOrganization()) &&
                    !CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME &&
                    StringUtils.isNotEmpty(AuthzUtil.getUserIdOfAssociatedUser(requestMsgCtx.getAuthorizedUser()))) {
                requestMsgCtx.getAuthorizedUser().setSharedUserId(AuthzUtil.getUserIdOfAssociatedUser(requestMsgCtx
                        .getAuthorizedUser()));
                requestMsgCtx.getAuthorizedUser().setUserSharedOrganizationId(requestMsgCtx.getAuthorizedUser()
                        .getAccessingOrganization());
            }
            // Get claim in oidc dialect from user store.
            userClaimsInOIDCDialect = retrieveClaimsForLocalUser(requestMsgCtx);
        } else {
            // Get claim map from the cached attributes
            userClaimsInOIDCDialect = getOIDCClaimsFromUserAttributes(userAttributes, requestMsgCtx);
            // Since this is a federated flow, we need to get the federated user attributes as well.
            Map<ClaimMapping, String> federatedUserAttributes = getCachedUserAttributes(requestMsgCtx, true);
            Map<String, Object>  federatedUserClaimsInOIDCDialect =
                    getOIDCClaimsFromFederatedUserAttributes(federatedUserAttributes, requestMsgCtx);
            userClaimsInOIDCDialect.putAll(federatedUserClaimsInOIDCDialect);
        }

        Object hasNonOIDCClaimsProperty = requestMsgCtx.getProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS);
        if (isPreserverClaimUrisInAssertion(requestMsgCtx) || (hasNonOIDCClaimsProperty != null
                && (Boolean) hasNonOIDCClaimsProperty)) {
            return userClaimsInOIDCDialect;
        } else {
            return filterClaims(userClaimsInOIDCDialect, requestMsgCtx);
        }
    }

    /**
     * Filter claims with allowed access token claims
     *
     * @param userClaimsInOIDCDialect User claims in OIDC dialect
     * @param requestMsgCtx           OAuthTokenReqMessageContext
     * @return Filtered claims
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private Map<String, Object> filterClaims(Map<String, Object> userClaimsInOIDCDialect,
                                             OAuthTokenReqMessageContext requestMsgCtx) throws IdentityOAuth2Exception {

        String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        // Get allowed access token claims.
        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, Object> claims = allowedClaims.stream()
                .filter(userClaimsInOIDCDialect::containsKey)
                .collect(Collectors.toMap(claim -> claim, userClaimsInOIDCDialect::get));
        return handleClaimsFormat(claims, clientId, spTenantDomain);
    }

    /**
     * Filter claims with allowed access token claims
     *
     * @param userClaimsInOIDCDialect User claims in OIDC dialect
     * @param authzReqMessageContext           OAuthAuthzReqMessageContext
     * @return Filtered claims
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private Map<String, Object> filterClaims(Map<String, Object> userClaimsInOIDCDialect,
                                             OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        String spTenantDomain = getServiceProviderTenantDomain(authzReqMessageContext);
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        // Get allowed access token claims.
        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, Object> claims = allowedClaims.stream().filter(userClaimsInOIDCDialect::containsKey)
                .collect(Collectors.toMap(claim -> claim, userClaimsInOIDCDialect::get));
        return handleClaimsFormat(claims, clientId, spTenantDomain);
    }

    /**
     * Get claims for local user form userstore.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext
     * @return Local user claims
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private Map<String, Object> retrieveClaimsForLocalUser(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
            String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
            AuthenticatedUser authenticatedUser = requestMsgCtx.getAuthorizedUser();

            return getLocalUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException |
                 OrganizationManagementException e) {
            if (FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()) {
                log.error("Error occurred while getting claims for user: " + requestMsgCtx.getAuthorizedUser() +
                        " from userstore.", e);
            } else {
                throw new IdentityOAuth2Exception("Error occurred while getting claims for user: " +
                        requestMsgCtx.getAuthorizedUser() + " from userstore.", e);
            }
        }
        return new HashMap<>();
    }

    /**
     * Get oidc claims mapping.
     *
     * @param userAttributes    User attributes.
     * @param requestMsgCtx     Request Context.
     * @return User attributes Map.
     */
    private Map<String, Object> getOIDCClaimsFromUserAttributes(Map<ClaimMapping, String> userAttributes,
                                                                OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
        Map<String, String> claims = new HashMap<>();
        if (isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue().toString());
            }
        }
        return OIDCClaimUtil.getMergedUserClaimsInOIDCDialect(spTenantDomain, claims);
    }

    /**
     * Get oidc claims mapping.
     *
     * @param federatedUserAttributes User attributes.
     * @param requestMsgCtx           Request Context.
     * @return User attributes Map.
     */
    private Map<String, Object> getOIDCClaimsFromFederatedUserAttributes(Map<ClaimMapping,
            String> federatedUserAttributes, OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = null;
        try {
            oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        } catch (ClaimMetadataException e) {
            throw new IdentityOAuth2Exception("Error while retrieving OIDC to Local claim mappings.", e);
        }
        // Get user claims in OIDC dialect.
        Map<String, String> userClaimsInOidcDialect = new HashMap<>();
        if (MapUtils.isNotEmpty(federatedUserAttributes)) {
            for (Map.Entry<ClaimMapping, String> userAttribute : federatedUserAttributes.entrySet()) {
                ClaimMapping claimMapping = userAttribute.getKey();
                String claimValue = userAttribute.getValue().toString();
                String localClaimURI = claimMapping.getLocalClaim().getClaimUri();
                if (oidcToLocalClaimMappings.containsKey(localClaimURI) && StringUtils.isNotBlank(claimValue)) {
                    userClaimsInOidcDialect.put(localClaimURI, claimValue);
                    if (log.isDebugEnabled() &&
                            IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                        log.debug("Mapped claim: key - " + localClaimURI + " value - " + claimValue);
                    }
                }
            }
        }
        return OIDCClaimUtil.getMergedUserClaimsInOIDCDialect(spTenantDomain, userClaimsInOidcDialect);
    }

    /**
     * Get user claims in OIDC dialect.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @return User claims in OIDC dialect
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        Map<String, Object> userClaimsInOIDCDialect;
        Map<ClaimMapping, String> userAttributes =
                getUserAttributesCachedAgainstToken(getAccessToken(authzReqMessageContext), false);

        if (isEmpty(userAttributes)) {
            if (isLocalUser(authzReqMessageContext)) {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute from auth " +
                            "context for local user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                userAttributes = authzReqMessageContext.getAuthorizationReqDTO().getUser()
                        .getUserAttributes();

                if (isEmpty(userAttributes)) {
                    if (log.isDebugEnabled()) {
                        log.debug("User attributes not found in cache. Trying to retrieve attribute for " +
                                "local user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                    }
                    userClaimsInOIDCDialect = retrieveClaimsForLocalUser(authzReqMessageContext);
                } else {
                    userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute for federated " +
                            "user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                userClaimsInOIDCDialect = retrieveClaimsForFederatedUser(authzReqMessageContext);
            }
        } else {
            userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
            // Since this is a federated flow we are retrieving the federated user attributes as well.
            Map<ClaimMapping, String> federatedUserAttributes =
                    getUserAttributesCachedAgainstToken(getAccessToken(authzReqMessageContext), true);
            Map<String, Object> federatedUserClaimsInOIDCDialect =
                    getUserClaimsInOIDCDialectFromFederatedUserAttributes(authzReqMessageContext
                            .getAuthorizationReqDTO().getTenantDomain(), federatedUserAttributes);
            userClaimsInOIDCDialect.putAll(federatedUserClaimsInOIDCDialect);
        }
        return filterClaims(userClaimsInOIDCDialect, authzReqMessageContext);
    }

    /**
     * This method retrieves the user attributes cached against the access token or the authorization code.
     * Currently, this is supported for the code grant and the refresh grant.
     *
     * @param requestMsgCtx The context of the OAuth token request containing necessary properties.
     * @param fetchFederatedUserAttributes Flag to indicate whether to fetch federated user attributes.
     * @return A map of cached user attributes against the code or the access token.
     * @throws IdentityOAuth2Exception If an error occurs while selecting the OAuth2 token issuer.
     */
    private Map<ClaimMapping, String> getCachedUserAttributes(OAuthTokenReqMessageContext requestMsgCtx,
                                                              boolean fetchFederatedUserAttributes)
            throws IdentityOAuth2Exception {

        Map<ClaimMapping, String> userAttributes = getUserAttributesCachedAgainstAuthorizationCode(
                getAuthorizationCode(requestMsgCtx), fetchFederatedUserAttributes);
        if (log.isDebugEnabled()) {
            log.debug("Retrieving claims cached against authorization_code for user: " +
                    requestMsgCtx.getAuthorizedUser());
        }
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the authorization_code for user: " + requestMsgCtx.
                        getAuthorizedUser() + ". Retrieving claims cached against the access_token.");
            }
            userAttributes = getUserAttributesCachedAgainstToken(getAccessToken(requestMsgCtx),
                    fetchFederatedUserAttributes);
            if (log.isDebugEnabled()) {
                log.debug("Retrieving claims cached against access_token for user: " +
                        requestMsgCtx.getAuthorizedUser());
            }
        }
        // Check for claims cached against the device code.
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the access_token for user: " +
                        requestMsgCtx.getAuthorizedUser() + ". Retrieving claims cached against the device code.");
            }
            userAttributes = getUserAttributesCachedAgainstDeviceCode(getDeviceCode(requestMsgCtx),
                    fetchFederatedUserAttributes);
        }
        /* When building the jwt token, we cannot add it to authorization cache, as we save entries against, access
         token. Hence if it is added against authenticated user object.*/
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims found in authorization cache. Retrieving claims from attributes of user : " +
                        requestMsgCtx.getAuthorizedUser());
            }
            AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
            userAttributes = user != null ? user.getUserAttributes() : null;
        }
        // In the refresh flow, we need to follow the same way to get the claims.
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims found in user in user attributes for user : " + requestMsgCtx.getAuthorizedUser());
            }

            /*
            The purpose of this segment is retrieving the user attributes at the refresh grant while the caches
            are disabled. The code/token acts as the key in cache layer while access token hash acts as the key for
            entries in the persistence layer(SessionStore).
            At this point, the token indicated by RefreshGrantHandler.PREV_ACCESS_TOKEN is no longer
            present in the caches or the persistence layer because a new access token has already been generated
            and added to the cache with new token references. However, RefreshGrantHandler.PREV_ACCESS_TOKEN cannot
            yet be replaced with the new access token since the refresh token has not been generated, and
            the new token is not yet considered "previous" by definition.
             */
            String latestAccessTokenHash = getLatestAccessTokenHash(requestMsgCtx);
            if (StringUtils.isNotBlank(latestAccessTokenHash)) {
                userAttributes = getUserAttributesCachedAgainstToken(latestAccessTokenHash,
                        fetchFederatedUserAttributes);
            }

            Object previousAccessTokenObject = requestMsgCtx.getProperty(RefreshGrantHandler.PREV_ACCESS_TOKEN);

            if (previousAccessTokenObject != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieving claims from previous access token of user : " + requestMsgCtx
                            .getAuthorizedUser());
                }
                RefreshTokenValidationDataDO refreshTokenValidationDataDO =
                        (RefreshTokenValidationDataDO) previousAccessTokenObject;

                // This segment is retrieving the user attributes at the refresh grant while the caches are enabled.
                if (isEmpty(userAttributes)) {
                    userAttributes = getUserAttributesCachedAgainstToken(refreshTokenValidationDataDO.getAccessToken(),
                            fetchFederatedUserAttributes);
                }
                requestMsgCtx.addProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS,
                        isTokenHasCustomUserClaims(refreshTokenValidationDataDO));
            }
        }
        return userAttributes;
    }

    /**
     * Get user attributes cached against the authorization code.
     *
     * @param authorizationCode      Authorization Code
     * @param fetchFederatedUserAttr Flag to indicate whether to fetch federated user attributes.
     * @return User attributes cached against the authorization code
     */
    private Map<ClaimMapping, String> getUserAttributesCachedAgainstAuthorizationCode(String authorizationCode,
                                                                                      boolean fetchFederatedUserAttr) {

        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (authorizationCode != null) {
            // Get the cached user claims against the authorization code if any.
            userAttributes = getUserAttributesFromCacheUsingCode(authorizationCode, fetchFederatedUserAttr);
        }
        return userAttributes;
    }

    /**
     * GEt user attributes cached against the device code.
     *
     * @param deviceCode                   Device Code
     * @param fetchFederatedUserAttributes Flag to indicate whether to fetch federated user attributes.
     * @return User attributes cached against the device code
     */
    private Map<ClaimMapping, String> getUserAttributesCachedAgainstDeviceCode(String deviceCode,
                                                                               boolean fetchFederatedUserAttributes) {

        if (StringUtils.isEmpty(deviceCode)) {
            return Collections.emptyMap();
        }
        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                DeviceAuthorizationGrantCache.getInstance().getValueFromCache(cacheKey);
        if (fetchFederatedUserAttributes) {
            return cacheEntry == null ? Collections.emptyMap() : cacheEntry.getMappedRemoteClaims();
        }
        return cacheEntry == null ? Collections.emptyMap() : cacheEntry.getUserAttributes();
    }

    /**
     * Get user attributes cached against the authorization code.
     *
     * @param authorizationCode            Authorization Code
     * @param fetchFederatedUserAttributes Flag to indicate whether to fetch federated user attributes.
     * @return User attributes cached against the authorization code
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingCode(String authorizationCode,
                                                                          boolean fetchFederatedUserAttributes) {
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Retrieving user attributes cached against authorization code: " + authorizationCode);
            } else {
                log.debug("Retrieving user attributes cached against authorization code.");
            }
        }

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
        if (fetchFederatedUserAttributes) {
            return cacheEntry == null ? new HashMap<>() : cacheEntry.getMappedRemoteClaims();
        }
        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Get user attributes cached against the access token.
     *
     * @param accessToken                  Access Token
     * @param fetchFederatedUserAttributes Flag to indicate whether to fetch federated user attributes.
     * @return User attributes cached against the access token
     */
    private Map<ClaimMapping, String> getUserAttributesCachedAgainstToken(String accessToken,
                                                                          boolean fetchFederatedUserAttributes) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (accessToken != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(accessToken, fetchFederatedUserAttributes);
        }
        return userAttributes;
    }

    /**
     * Get claims for local user form userstore.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext
     * @return Local user claims
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private Map<String, Object> retrieveClaimsForLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(authzReqMessageContext);
            String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
            AuthenticatedUser authenticatedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();

            return getLocalUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException |
                 OrganizationManagementException e) {
            if (FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()) {
                log.error("Error occurred while getting claims for user " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser(), e);
            } else {
                throw new IdentityOAuth2Exception("Error occurred while getting claims for user " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser(), e);
            }
        }
        return new HashMap<>();
    }

    /**
     * Retrieve the claim set of the AuthenticatedUser from the OAuthAuthzReqMessageContext.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return Map of user attributes.
     */
    private Map<String, Object> retrieveClaimsForFederatedUser(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = authzReqMessageContext.getAuthorizationReqDTO();
        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();

        if (oAuth2AuthorizeReqDTO == null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth2AuthorizeReqDTO is NULL for federated user: " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser());
            }
            return userClaimsMappedToOIDCDialect;
        }
        AuthenticatedUser authenticatedUser = oAuth2AuthorizeReqDTO.getUser();
        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Authenticated User is not available in the request");
            }
            return userClaimsMappedToOIDCDialect;
        }
        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
        // Since this is a federated flow we are retrieving the federated user attributes as well.
        Map<ClaimMapping, String> federatedUserAttributes =
                oAuth2AuthorizeReqDTO.getMappedRemoteClaims();
        userClaimsMappedToOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
        Map<String, Object> federatedUserClaimsMappedToOIDCDialect =
                getUserClaimsInOIDCDialectFromFederatedUserAttributes(authzReqMessageContext.getAuthorizationReqDTO()
                .getTenantDomain(), federatedUserAttributes);
        userClaimsMappedToOIDCDialect.putAll(federatedUserClaimsMappedToOIDCDialect);
        return userClaimsMappedToOIDCDialect;
    }

    /**
     * Get claims map.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private Map<String, Object> getOIDCClaimMapFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<>();
        if (isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    /**
     * Get user claims in OIDC claim dialect from federated user attributes.
     *
     * @param spTenantDomain    Service Provider Tenant Domain
     * @param federatedUserAttr Federated User Attributes
     * @return User claims in OIDC dialect
     * @throws IdentityOAuth2Exception Identity OAuth2 Exception
     */
    private static Map<String, Object> getUserClaimsInOIDCDialectFromFederatedUserAttributes(String spTenantDomain,
                                                                                             Map<ClaimMapping, String>
                                                                                                     federatedUserAttr)
            throws IdentityOAuth2Exception {

        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = null;
        try {
            oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        } catch (ClaimMetadataException e) {
            throw new IdentityOAuth2Exception("Error while retrieving OIDC to Local claim mappings.", e);
        }
        // Get user claims in OIDC dialect.
        Map<String, Object> userClaimsInOidcDialect = new HashMap<>();
        if (MapUtils.isNotEmpty(federatedUserAttr)) {
            for (Map.Entry<ClaimMapping, String> userAttribute : federatedUserAttr.entrySet()) {
                ClaimMapping claimMapping = userAttribute.getKey();
                String claimValue = userAttribute.getValue();
                String localClaimURI = claimMapping.getLocalClaim().getClaimUri();
                if (oidcToLocalClaimMappings.containsKey(localClaimURI) && StringUtils.isNotBlank(claimValue)) {
                    userClaimsInOidcDialect.put(localClaimURI, claimValue);
                    if (log.isDebugEnabled() &&
                            IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                        log.debug("Mapped claim: key - " + localClaimURI + " value - " + claimValue);
                    }
                }
            }
        }
        return userClaimsInOidcDialect;
    }

    /**
     * Get user claims in OIDC claim dialect from userstore.
     *
     * @param spTenantDomain    Service Provider Tenant Domain
     * @param clientId          Client Id
     * @param authenticatedUser Authenticated User
     * @return User claims in OIDC dialect
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     * @throws IdentityException                      Identity Exception
     * @throws UserStoreException                     User Store Exception
     * @throws OrganizationManagementException        Organization Management Exception
     */
    private Map<String, Object> getLocalUserClaimsInOIDCDialect(String spTenantDomain, String clientId,
                                                                AuthenticatedUser authenticatedUser)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException,
            OrganizationManagementException {

        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();
        ServiceProvider serviceProvider = getServiceProvider(spTenantDomain, clientId);
        if (serviceProvider == null) {
            log.warn("Unable to find a service provider associated with client_id: " + clientId + " in tenantDomain: " +
                    spTenantDomain + ". Returning empty claim map for user.");
            return userClaimsMappedToOIDCDialect;
        }

        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, String> oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(spTenantDomain);
        if (oidcToLocalClaimMappings.isEmpty()) {
            return new HashMap<>();
        }
        List<String> localClaimURIs = allowedClaims.stream().map(oidcToLocalClaimMappings::get).filter(Objects::nonNull)
                .collect(Collectors.toList());
        return OIDCClaimUtil.getUserClaimsInOIDCDialect(serviceProvider, authenticatedUser, localClaimURIs);
    }

    /**
     * Get user attribute cached against the access token.
     *
     * @param accessToken Access token
     * @return User attributes cached against the access token
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingToken(String accessToken,
                                                                           boolean fetchFederatedUserAttributes) {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieving user attributes cached against access token: " + accessToken);
            } else {
                log.debug("Retrieving user attributes cached against access token.");
            }
        }

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);
        if (fetchFederatedUserAttributes) {
            return cacheEntry == null ? new HashMap<>() : cacheEntry.getMappedRemoteClaims();
        }
        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    private String getAuthorizationCode(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(AUTHZ_CODE);
    }

    private String getAccessToken(OAuthAuthzReqMessageContext authzReqMessageContext) {

        return (String) authzReqMessageContext.getProperty(ACCESS_TOKEN);
    }

    private String getAccessToken(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(ACCESS_TOKEN);
    }

    private String getDeviceCode(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(DEVICE_CODE);
    }

    private boolean isLocalUser(AuthenticatedUser authenticatedUser) {

        return !authenticatedUser.isFederatedUser();
    }

    private boolean isLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext) {

        return !authzReqMessageContext.getAuthorizationReqDTO().getUser().isFederatedUser();
    }

    /**
     * The access token hash acts as the key for entries in the SessionStore.
     * This method retrieves the access token hash for OAuthConstants.ACCESS_TOKEN from the properties
     * of OAuthTokenReqMessageContext treating it as the latest access token. It determines the type
     * of access token (opaque or JWT) via the OAuth token issuer and obtains the access token hash accordingly.
     * This method is useful for retrieving access tokens when the cache is disabled and
     * SessionStore persistence is employed.
     *
     * @param oAuthTokenReqMessageContext The context of the OAuth token request containing necessary properties.
     * @return The hash of the latest access token if available and valid, otherwise null.
     * @throws IdentityOAuth2Exception If an error occurs while selecting the OAuth2 token issuer.
     */
    private String getLatestAccessTokenHash(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        // The OAuthConstants.ACCESS_TOKEN is considered as the latest access token.
        Object latestAccessTokenObj = getAccessToken(oAuthTokenReqMessageContext);
        if (latestAccessTokenObj != null && StringUtils.isNotBlank(latestAccessTokenObj.toString())) {

            Object oAuthAppDOObj = oAuthTokenReqMessageContext.getProperty(AccessTokenIssuer.OAUTH_APP_DO);

            if (oAuthAppDOObj != null) {
                try {
                    OAuthAppDO oAuthAppDO = (OAuthAppDO) oAuthAppDOObj;
                    OauthTokenIssuer tokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(oAuthAppDO);
                    if (tokenIssuer != null) {
                        String latestAccessToken = latestAccessTokenObj.toString();
                        try {
                            return tokenIssuer.getAccessTokenHash(latestAccessToken);
                        } catch (OAuthSystemException e) {
                            throw new IdentityOAuth2Exception("Error occurred while generating the access token hash " +
                                    "at user attribute retrieval", e);
                        }
                    }
                } catch (ClassCastException e) {
                    log.error("Error occurred while generating the access token hash at user attribute " +
                            "retrieval", e);

                }
            }
        }
        return null;
    }

    /**
     * To check whether a token has custom user claims.
     *
     * @param refreshTokenValidationDataDO RefreshTokenValidationDataDO.
     * @return true if the token user attributes has non OIDC claims.
     */
    private boolean isTokenHasCustomUserClaims(RefreshTokenValidationDataDO refreshTokenValidationDataDO) {

        if (refreshTokenValidationDataDO.getAccessToken() == null) {
            return false;
        }
        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(
                refreshTokenValidationDataDO.getAccessToken());
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);
        boolean hasNonOIDCClaims = cacheEntry != null && cacheEntry.isHasNonOIDCClaims();

        if (log.isDebugEnabled()) {
            log.debug("hasNonOIDCClaims is set to " + hasNonOIDCClaims + " for the access token of the user : "
                    + refreshTokenValidationDataDO.getAuthorizedUser());
        }
        return cacheEntry != null && cacheEntry.isHasNonOIDCClaims();
    }

    /**
     * This method retrieves OIDC to Local claim mappings.
     *
     * @param tenantDomain Tenant Domain.
     * @return Map of OIDC to Local claim mappings.
     */
    private Map<String, String> getOIDCToLocalClaimMappings(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OAuthConstants.OIDC_DIALECT, null,
                            tenantDomain, false);
        } catch (ClaimMetadataException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OIDC to Local claim mappings.", e);
        }
    }

    /**
     * This method sets claims to JWTClaimSet.
     *
     * @param jwtClaimsSetBuilder JWTClaimSet builder.
     * @param userClaimsInOIDCDialect User claims in OIDC dialect.
     * @return JWTClaimSet with claims.
     */
    private JWTClaimsSet setClaimsToJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder, Map<String, Object>
            userClaimsInOIDCDialect) {

        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();
        for (Map.Entry<String, Object> claimEntry : userClaimsInOIDCDialect.entrySet()) {
            String claimValue = claimEntry.getValue().toString();
            String claimKey = claimEntry.getKey();
            if (isMultiValuedAttribute(claimKey, claimValue, multiAttributeSeparator)) {
                JSONArray claimValues = new JSONArray();
                String[] attributeValues = claimValue.split(Pattern.quote(multiAttributeSeparator));
                for (String attributeValue : attributeValues) {
                    if (StringUtils.isNotBlank(attributeValue)) {
                        claimValues.add(attributeValue);
                    }
                }
                if (jwtClaimsSet.getClaim(claimKey) == null) {
                    jwtClaimsSetBuilder.claim(claimEntry.getKey(), claimValues);
                }
            } else {
                if (jwtClaimsSet.getClaim(claimKey) == null) {
                    jwtClaimsSetBuilder.claim(claimEntry.getKey(), claimEntry.getValue());
                }
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    /**
     * Check weather claim value if multi valued or not.
     *
     * @param claimKey Claim key.
     * @param claimValue Claim value.
     * @param multiAttributeSeparator Multi attribute separator.
     * @return True if claim value is multi valued, false otherwise.
     */
    private boolean isMultiValuedAttribute(String claimKey, String claimValue, String multiAttributeSeparator) {

        // Address claim contains multi attribute separator but its not a multi valued attribute.
        if (claimKey.equals(ADDRESS)) {
            return false;
        }
        // To format the groups claim to always return as an array, we should consider single group as
        // multi value attribute.
        if (claimKey.equals(GROUPS)) {
            return true;
        }
        return StringUtils.contains(claimValue, multiAttributeSeparator);
    }

    /**
     * Get access token claims.
     *
     * @param clientId Client Id.
     * @param tenantDomain Tenant Domain.
     * @return List of JWT access token claims.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    private List<String> getAccessTokenClaims(String clientId, String tenantDomain) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppDO;

        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
            String[] claimsArray = oAuthAppDO.getAccessTokenClaims();
            if (claimsArray == null) {
                return new ArrayList<>();
            }
            return new ArrayList<>(Arrays.asList(claimsArray));
        } catch (InvalidOAuthClientException e) {
            String error = "Error occurred while getting app information for client_id: " + clientId;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    /**
     * Handle claims format.
     *
     * @param userClaims   User claims.
     * @param tenantDomain Tenant Domain.
     */
    private Map<String, Object> handleClaimsFormat(Map<String, Object> userClaims, String clientId,
                                                   String tenantDomain) throws IdentityOAuth2Exception {

        List<String> registeredScopes = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO()
                .getScopeNames(IdentityTenantUtil.getTenantId(tenantDomain));
        return OpenIDConnectServiceComponentHolder.getInstance().getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, registeredScopes.toArray(new String[0]),
                        clientId, tenantDomain);
    }

    /**
     * Get service provider.
     *
     * @param spTenantDomain Tenant Domain.
     * @param clientId       Client Id.
     * @return ServiceProvider.
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     */
    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityApplicationManagementException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, OAUTH2, spTenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving service provider for clientId: " + clientId + " in tenantDomain: " + spTenantDomain);
        }
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }


    /**
     * Get the tenant domain of the service provider.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return Tenant domain of the service provider.
     */
    private String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {

        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    /**
     * Retrieves the service provider tenant domain from the OAuthAuthzReqMessageContext.
     *
     * @param requestMsgCtx OAuthAuthzReqMessageContext containing the tenant domain.
     * @return The tenant domain.
     */
    private String getServiceProviderTenantDomain(OAuthAuthzReqMessageContext requestMsgCtx) {

        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    /**
     * Check whether an organization SSO user is trying to switch the organization.
     *
     * @param authorizedUser authorized user from the token request.
     * @return true if an organization SSO user is trying to switch the organization.
     */
    private boolean isOrganizationSsoUserSwitchingOrganization(AuthenticatedUser authorizedUser) {

        String accessingOrganization = authorizedUser.getAccessingOrganization();
        String userResidentOrganization = authorizedUser.getUserResidentOrganization();
        /* A federated user with resident organization is considered as an organization SSO user. When the accessing
           organization is different to the resident organization, it means the user is trying to switch the
           organization. */
        return authorizedUser.isFederatedUser() && userResidentOrganization != null && !userResidentOrganization.equals
                (accessingOrganization);
    }

    /**
     * Check whether grant type is organization switch grant.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext
     * @return true if grant type is organization switch grant.
     */
    private boolean isOrganizationSwitchGrantType(OAuthTokenReqMessageContext requestMsgCtx) {

        return StringUtils.equals(requestMsgCtx.getOauth2AccessTokenReqDTO().getGrantType(),
                OAuthConstants.GrantTypes.ORGANIZATION_SWITCH);
    }

    private boolean isPreserverClaimUrisInAssertion(OAuthTokenReqMessageContext requestMsgCtx) {

        return !OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect() &&
                requestMsgCtx.getAuthorizedUser().isFederatedUser();
    }
}
