/*
 * Copyright (c) 2017-2023, WSO2 LLC. (http://www.wso2.com).
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
import org.apache.commons.lang.ArrayUtils;
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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
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
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_CODE;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.ID_TOKEN_USER_CLAIMS_PROP_KEY;

/**
 * Default implementation of {@link CustomClaimsCallbackHandler}. This callback handler populates available user
 * claims after filtering them through requested scopes using {@link OpenIDConnectClaimFilter}.
 */
public class DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandler.class);
    private static final String OAUTH2 = "oauth2";

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthTokenReqMessageContext
            tokenReqMessageContext) throws IdentityOAuth2Exception {
        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(tokenReqMessageContext);
            tokenReqMessageContext.addProperty(ID_TOKEN_USER_CLAIMS_PROP_KEY, userClaimsInOIDCDialect.keySet());
            return setClaimsToJwtClaimSet(jwtClaimsSetBuilder, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while adding claims of user: " + tokenReqMessageContext.getAuthorizedUser() +
                        " to the JWTClaimSet used to build the id_token.", e);
            }
        }
        return null;
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSet,
                                           OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(authzReqMessageContext);
            return setClaimsToJwtClaimSet(jwtClaimsSet, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " +
                    authzReqMessageContext.getAuthorizationReqDTO().getUser() + " to the JWTClaimSet used to " +
                    "build the id_token.", e);
        }
        return null;
    }

    /**
     * Filter user claims based on the OIDC Scopes defined at server level.
     *
     * @param requestedScopes             Requested Scopes in the OIDC Request
     * @param serviceProviderTenantDomain Tenant domain of the service provider
     * @param userClaims                  Map of user claims
     * @return
     */
    protected Map<String, Object> filterClaimsByScope(Map<String, Object> userClaims,
                                                      String[] requestedScopes,
                                                      String clientId,
                                                      String serviceProviderTenantDomain) {
        return OpenIDConnectServiceComponentHolder.getInstance()
                .getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, serviceProviderTenantDomain);
    }

    /**
     * Get response map.
     *
     * @param requestMsgCtx Token request message context
     * @return Mapped claimed
     * @throws OAuthSystemException
     */
    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx)
            throws OAuthSystemException, IdentityOAuth2Exception {
        // Map<"email", "peter@example.com">
        Map<String, Object> userClaimsInOIDCDialect;
        // Get any user attributes that were cached against the access token
        // Map<(http://wso2.org/claims/email, email), "peter@example.com">
        Map<ClaimMapping, String> userAttributes = getCachedUserAttributes(requestMsgCtx);
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
            userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
        }

        Object hasNonOIDCClaimsProperty = requestMsgCtx.getProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS);
        if (isPreserverClaimUrisInAssertion(requestMsgCtx) || (hasNonOIDCClaimsProperty != null
                && (Boolean) hasNonOIDCClaimsProperty)) {
            return userClaimsInOIDCDialect;
        } else {
            return filterOIDCClaims(requestMsgCtx, userClaimsInOIDCDialect);
        }
    }

    private Map<String, Object> filterOIDCClaims(OAuthTokenReqMessageContext requestMsgCtx,
                                                 Map<String, Object> userClaimsInOIDCDialect)
            throws OAuthSystemException {

        AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        String[] approvedScopes = requestMsgCtx.getScope();
        String token = getAccessToken(requestMsgCtx);
        String authorizationCode = getAuthorizationCode(requestMsgCtx);
        String grantType = requestMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();
        // Get the flag which has the record whether the token is a consented one or not.
        boolean isConsentedToken = false;
        if (requestMsgCtx.isConsentedToken()) {
            isConsentedToken = requestMsgCtx.isConsentedToken();
        }

        return filterOIDCClaims(token, authorizationCode, grantType, userClaimsInOIDCDialect, user,
                approvedScopes, clientId, spTenantDomain, isConsentedToken);
    }


    private Map<String, Object> filterOIDCClaims(String accessToken,
                                                 String authorizationCode,
                                                 String grantType,
                                                 Map<String, Object> userClaimsInOIDCDialect,
                                                 AuthenticatedUser authenticatedUser,
                                                 String[] approvedScopes,
                                                 String clientId,
                                                 String spTenantDomain,
                                                 boolean isConsentedToken) throws OAuthSystemException {
        Map<String, Object> filteredUserClaimsByOIDCScopes =
                filterClaimsByScope(userClaimsInOIDCDialect, approvedScopes, clientId, spTenantDomain);

        // TODO: Get claims filtered by essential claims and add to returning claims
        // https://github.com/wso2/product-is/issues/2680

        if (accessToken != null) {
            if (StringUtils.isNotBlank(authorizationCode)) {
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
                AuthorizationGrantCacheEntry cacheEntry =
                        AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
                if (cacheEntry != null && cacheEntry.isRequestObjectFlow()) {
                    // Handle essential claims of the request object
                    Map<String, Object> claimsFromRequestObject =
                            filterClaimsFromRequestObject(userClaimsInOIDCDialect, accessToken);
                    filteredUserClaimsByOIDCScopes.putAll(claimsFromRequestObject);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("The request does not contains request object. So skipping " +
                                "filterClaimsFromRequestObject");
                    }
                }
            }
        }

        // User consent checking is skipped for API based authentication flow.
        if (isApiBasedAuthFlow(accessToken, authorizationCode)) {
            if (log.isDebugEnabled()) {
                String msg = "Filtering user claims based on user consent skipped due api based auth flow. Returning " +
                        "original user claims for user:%s, for clientId:%s of tenantDomain:%s";
                log.debug(String.format(msg, authenticatedUser.toFullQualifiedUsername(),
                        clientId, spTenantDomain));
            }
            return filteredUserClaimsByOIDCScopes;
        }

        // Restrict the claims based on user consent given
        return getUserConsentedClaims(filteredUserClaimsByOIDCScopes, authenticatedUser, grantType, clientId,
                spTenantDomain, isConsentedToken);
    }

    private boolean isPreserverClaimUrisInAssertion(OAuthTokenReqMessageContext requestMsgCtx) {

        return !OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect() &&
                requestMsgCtx.getAuthorizedUser().isFederatedUser();
    }

    private Map<String, Object> filterClaimsFromRequestObject(Map<String, Object> userAttributes,
                                                              String token) throws OAuthSystemException {

        try {
            List<RequestedClaim> requestedClaims = OpenIDConnectServiceComponentHolder.getRequestObjectService().
                    getRequestedClaimsForIDToken(token);
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByEssentialClaims(userAttributes, requestedClaims);
        } catch (RequestObjectException e) {
            throw new OAuthSystemException("Unable to retrieve requested claims from Request Object." + e);
        }
    }

    private Map<String, Object> getUserConsentedClaims(Map<String, Object> userClaims,
                                                       AuthenticatedUser authenticatedUser,
                                                       String grantType,
                                                       String clientId,
                                                       String spTenantDomain,
                                                       boolean isConsentedToken) throws OAuthSystemException {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = getServiceProvider(spTenantDomain, clientId);
        } catch (IdentityApplicationManagementException e) {
            throw new OAuthSystemException(
                    "Error while obtaining service provider for tenant domain: " + spTenantDomain + " client id: "
                            + clientId, e);
        }

        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, authenticatedUser, clientId,
                spTenantDomain, grantType, serviceProvider, isConsentedToken);
    }

    /**
     * This method retrieves the user attributes cached against the access token or the authorization code.
     * Currently, this is supported for the code grant and the refresh grant.
     *
     * @param requestMsgCtx The context of the OAuth token request containing necessary properties.
     * @return A map of cached user attributes against the code or the access token.
     * @throws OAuthSystemException    If there is an error while generating the access token hash.
     * @throws IdentityOAuth2Exception If an error occurs while selecting the OAuth2 token issuer.
     */
    private Map<ClaimMapping, String> getCachedUserAttributes(OAuthTokenReqMessageContext requestMsgCtx)
            throws OAuthSystemException, IdentityOAuth2Exception {

        Map<ClaimMapping, String> userAttributes = getUserAttributesCachedAgainstAuthorizationCode(
                getAuthorizationCode(requestMsgCtx));
        if (log.isDebugEnabled()) {
            log.debug("Retrieving claims cached against authorization_code for user: " +
                    requestMsgCtx.getAuthorizedUser());
        }
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the authorization_code for user: " + requestMsgCtx.
                        getAuthorizedUser() + ". Retrieving claims cached against the access_token.");
            }
            userAttributes = getUserAttributesCachedAgainstToken(getAccessToken(requestMsgCtx));
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
            userAttributes = getUserAttributesCachedAgainstDeviceCode(getDeviceCode(requestMsgCtx));
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
                userAttributes = getUserAttributesCachedAgainstToken(latestAccessTokenHash);
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
                    userAttributes = getUserAttributesCachedAgainstToken(refreshTokenValidationDataDO.getAccessToken());
                }
                requestMsgCtx.addProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS,
                        isTokenHasCustomUserClaims(refreshTokenValidationDataDO));
            }
        }
        return userAttributes;
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
     * @throws OAuthSystemException    If there is an error while generating the access token hash.
     */
    private String getLatestAccessTokenHash(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception, OAuthSystemException {

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
                        return tokenIssuer.getAccessTokenHash(latestAccessToken);
                    }
                } catch (ClassCastException e) {
                    log.error("Error occurred while generating the access token hash at user attribute " +
                            "retrieval", e);

                }
            }
        }
        return null;
    }
    private Map<String, Object> retrieveClaimsForLocalUser(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
            String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
            AuthenticatedUser authenticatedUser = requestMsgCtx.getAuthorizedUser();

            return getUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
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

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstAuthorizationCode(String authorizationCode) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (authorizationCode != null) {
            // Get the cached user claims against the authorization code if any.
            userAttributes = getUserAttributesFromCacheUsingCode(authorizationCode);
        }
        return userAttributes;
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstToken(String accessToken) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (accessToken != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(accessToken);
        }
        return userAttributes;
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstDeviceCode(String deviceCode) {

        if (StringUtils.isEmpty(deviceCode)) {
            return Collections.emptyMap();
        }
        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                DeviceAuthorizationGrantCache.getInstance().getValueFromCache(cacheKey);
        return cacheEntry == null ? Collections.emptyMap() : cacheEntry.getUserAttributes();
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws OAuthSystemException, IdentityOAuth2Exception {

        Map<String, Object> userClaimsInOIDCDialect;
        Map<ClaimMapping, String> userAttributes =
                getUserAttributesCachedAgainstToken(getAccessToken(authzReqMessageContext));

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
                        log.debug("User attributes not found in auth context. Trying to retrieve attribute for " +
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
        }

        return filterOIDCClaims(authzReqMessageContext, userClaimsInOIDCDialect);
    }

    /**
     * Retrieve the claim set of the AuthenticatedUser from the OAuthAuthzReqMessageContext.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return Map of user attributes.
     */
    private Map<String, Object> retrieveClaimsForFederatedUser(OAuthAuthzReqMessageContext authzReqMessageContext) {

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
        userClaimsMappedToOIDCDialect = getOIDCClaimMapFromUserAttributes(authenticatedUser.getUserAttributes());
        return userClaimsMappedToOIDCDialect;
    }

    private Map<String, Object> filterOIDCClaims(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                 Map<String, Object> userClaimsInOIDCDialect)
            throws OAuthSystemException {

        AuthenticatedUser user = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String[] approvedScopes = authzReqMessageContext.getApprovedScope();
        String accessToken = getAccessToken(authzReqMessageContext);
        String grantType = OAuthConstants.GrantTypes.IMPLICIT;
        boolean isConsentedGrant = OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(grantType);
        return filterOIDCClaims(accessToken, StringUtils.EMPTY, grantType, userClaimsInOIDCDialect, user,
                approvedScopes, clientId, spTenantDomain, isConsentedGrant);
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(authzReqMessageContext);
            String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
            AuthenticatedUser authenticatedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();

            return getUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
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

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain, String clientId,
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

        ClaimMapping[] requestClaimMappings = getRequestedClaimMappings(serviceProvider);
        if (ArrayUtils.isEmpty(requestClaimMappings)) {
            if (log.isDebugEnabled()) {
                String spName = serviceProvider.getApplicationName();
                log.debug("No requested claims configured for service provider: " + spName + " of tenantDomain: "
                        + spTenantDomain + ". No claims returned for user: " + authenticatedUser);
            }
            return userClaimsMappedToOIDCDialect;
        }
        List<String> requestedClaimUris = getRequestedClaimUris(requestClaimMappings);
        // Improve runtime claim value storage in cache through https://github.com/wso2/product-is/issues/15056
        requestedClaimUris.removeIf(claim -> claim.startsWith("http://wso2.org/claims/runtime/"));
        return OIDCClaimUtil.getUserClaimsInOIDCDialect(serviceProvider, authenticatedUser, requestedClaimUris);
    }

    private ClaimMapping[] getRequestedClaimMappings(ServiceProvider serviceProvider) {
        if (serviceProvider.getClaimConfig() == null) {
            return new ClaimMapping[0];
        }
        return serviceProvider.getClaimConfig().getClaimMappings();
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

    private boolean isOrganizationSwitchGrantType(OAuthTokenReqMessageContext requestMsgCtx) {

        return StringUtils.equals(requestMsgCtx.getOauth2AccessTokenReqDTO().getGrantType(),
                OAuthConstants.GrantTypes.ORGANIZATION_SWITCH);
    }

    private String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    private String getServiceProviderTenantDomain(OAuthAuthzReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    private List<String> getRequestedClaimUris(ClaimMapping[] requestedLocalClaimMap) {
        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        return claimURIList;
    }

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
     * Get user attribute cached against the access token.
     *
     * @param accessToken Access token
     * @return User attributes cached against the access token
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingToken(String accessToken) {
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

        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Get user attributes cached against the authorization code.
     *
     * @param authorizationCode Authorization Code
     * @return User attributes cached against the authorization code
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingCode(String authorizationCode) {
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
        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Set user claims in OIDC dialect to the JWTClaimSet. Additionally we process multi values attributes here.
     *
     * @param jwtClaimsSetBuilder
     * @param userClaimsInOIDCDialect
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

    private String getAuthorizationCode(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(AUTHZ_CODE);
    }

    private String getAccessToken(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(ACCESS_TOKEN);
    }

    private String getAccessToken(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return (String) authzReqMessageContext.getProperty(ACCESS_TOKEN);
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

    private boolean isApiBasedAuthFlow(String accessToken, String authorizationCode) {

        if (StringUtils.isNotEmpty(authorizationCode)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
            if (cacheEntry != null) {
                return cacheEntry.isApiBasedAuthRequest();
            }
        } else if (StringUtils.isNotEmpty(accessToken)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
            if (cacheEntry != null) {
                return cacheEntry.isApiBasedAuthRequest();
            }
        }
        return false;
    }
}
