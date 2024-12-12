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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.ID_TOKEN_USER_CLAIMS_PROP_KEY;

/**
 * Default implementation of {@link CustomClaimsCallbackHandler}. This callback handler populates available user
 * claims after filtering them through requested scopes using {@link OpenIDConnectClaimFilter}.
 */
public class DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandler.class);

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthTokenReqMessageContext
            tokenReqMessageContext) throws IdentityOAuth2Exception {
        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(tokenReqMessageContext);
            tokenReqMessageContext.addProperty(ID_TOKEN_USER_CLAIMS_PROP_KEY, userClaimsInOIDCDialect.keySet());
            return OIDCClaimUtil.setClaimsToJwtClaimSet(jwtClaimsSetBuilder, userClaimsInOIDCDialect);
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
            return OIDCClaimUtil.setClaimsToJwtClaimSet(jwtClaimsSet, userClaimsInOIDCDialect);
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
        Map<ClaimMapping, String> userAttributes = OIDCClaimUtil.getCachedUserAttributes(requestMsgCtx);
        if ((userAttributes.isEmpty() || OIDCClaimUtil.isOrganizationSwitchGrantType(requestMsgCtx))
                && (OIDCClaimUtil.isLocalUser(requestMsgCtx.getAuthorizedUser())
                || OIDCClaimUtil.isOrganizationSsoUserSwitchingOrganization(requestMsgCtx.getAuthorizedUser()))) {
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
            userClaimsInOIDCDialect = OIDCClaimUtil.getOIDCClaimsFromUserAttributes(userAttributes, requestMsgCtx);
        }

        Object hasNonOIDCClaimsProperty = requestMsgCtx.getProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS);
        if (OIDCClaimUtil.isPreserverClaimUrisInAssertion(requestMsgCtx) || (hasNonOIDCClaimsProperty != null
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
            serviceProvider = OIDCClaimUtil.getServiceProvider(spTenantDomain, clientId);
        } catch (IdentityApplicationManagementException e) {
            throw new OAuthSystemException(
                    "Error while obtaining service provider for tenant domain: " + spTenantDomain + " client id: "
                            + clientId, e);
        }

        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, authenticatedUser, clientId,
                spTenantDomain, grantType, serviceProvider, isConsentedToken);
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = OIDCClaimUtil.getServiceProviderTenantDomain(requestMsgCtx);
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

    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws OAuthSystemException, IdentityOAuth2Exception {

        Map<String, Object> userClaimsInOIDCDialect;
        Map<ClaimMapping, String> userAttributes =
                OIDCClaimUtil.getUserAttributesCachedAgainstToken(OIDCClaimUtil.getAccessToken(authzReqMessageContext));

        if (isEmpty(userAttributes)) {
            if (OIDCClaimUtil.isLocalUser(authzReqMessageContext)) {
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
                    userClaimsInOIDCDialect = OIDCClaimUtil.getOIDCClaimMapFromUserAttributes(userAttributes);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute for federated " +
                            "user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                userClaimsInOIDCDialect = OIDCClaimUtil.retrieveClaimsForFederatedUser(authzReqMessageContext);
            }
        } else {
            userClaimsInOIDCDialect = OIDCClaimUtil.getOIDCClaimMapFromUserAttributes(userAttributes);
        }

        return filterOIDCClaims(authzReqMessageContext, userClaimsInOIDCDialect);
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
            String spTenantDomain = OIDCClaimUtil.getServiceProviderTenantDomain(authzReqMessageContext);
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

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain, String clientId,
                                                           AuthenticatedUser authenticatedUser)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException,
            OrganizationManagementException {

        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();
        ServiceProvider serviceProvider = OIDCClaimUtil.getServiceProvider(spTenantDomain, clientId);
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

    private List<String> getRequestedClaimUris(ClaimMapping[] requestedLocalClaimMap) {
        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        return claimURIList;
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
