/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.LOCAL_ROLE_CLAIM_URI;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;

/**
 * Default implementation of {@link CustomClaimsCallbackHandler}. This callback handler populates available user
 * claims after filtering them through requested scopes.
 */
public class DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private final static Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandler.class);
    private final static String OAUTH2 = "oauth2";
    private final static String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private final static String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext requestMsgCtx) {
        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(requestMsgCtx);
            setClaimsToJwtClaimSet(jwtClaimsSet, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " + requestMsgCtx.getAuthorizedUser() +
                    " to the JWTClaimSet used to build the id_token.", e);
        }
    }

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthAuthzReqMessageContext authzReqMessageContext) {
        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(authzReqMessageContext);
            setClaimsToJwtClaimSet(jwtClaimsSet, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " +
                    authzReqMessageContext.getAuthorizationReqDTO().getUser() + " to the JWTClaimSet used to " +
                    "build the id_token.", e);
        }
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
                .getOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, serviceProviderTenantDomain);
    }

    /**
     * Get response map
     *
     * @param requestMsgCtx Token request message context
     * @return Mapped claimed
     * @throws OAuthSystemException
     */
    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx)
            throws OAuthSystemException {
        // Get any user attributes that were cached against the access token
        // Map<(http://wso2.org/claims/email, email), "peter@example.com">
        Map<ClaimMapping, String> userAttributes = getUserAttributesCachedAgainstToken(getAccessToken(requestMsgCtx));
        if (log.isDebugEnabled()) {
            log.debug("Retrieving claims cached against access_token for user: " + requestMsgCtx.getAuthorizedUser());
        }
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the access_token for user: " + requestMsgCtx.getAuthorizedUser() +
                        ". Retrieving claims cached against the authorization code.");
            }
            userAttributes = getUserAttributesCachedAgainstAuthorizationCode(getAuthorizationCode(requestMsgCtx));
        }
        // Map<"email", "peter@example.com">
        Map<String, Object> userClaimsInOIDCDialect = getClaimMapForUserInOIDCDialect(requestMsgCtx, userAttributes);
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        // Restrict Claims going into the token based on the scope
        return filterClaimsByScope(userClaimsInOIDCDialect, requestMsgCtx.getScope(), clientId, spTenantDomain);
    }

    private String getAuthorizationCode(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(AUTHZ_CODE);
    }

    private String getAccessToken(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(ACCESS_TOKEN);
    }

    private Map<String, Object> getClaimMapForUserInOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx,
                                                                Map<ClaimMapping, String> userAttributes) {
        if (isEmpty(userAttributes) && isLocalUser(requestMsgCtx)) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Retrieving claims for local user: " +
                        requestMsgCtx.getAuthorizedUser() + " from userstore.");
            }
            return retrieveClaimsForLocalUser(requestMsgCtx);
        }
        return getUserClaimsMapInOIDCDialect(userAttributes);
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthTokenReqMessageContext requestMsgCtx) {
        try {
            return getClaimsForLocalUserInOIDCDialect(requestMsgCtx);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException e) {
            log.error("Error occurred while getting claims for user: " + requestMsgCtx.getAuthorizedUser() +
                    " from userstore.", e);
        }
        return new HashMap<>();
    }

    private boolean isLocalUser(OAuthTokenReqMessageContext requestMsgCtx) {
        return !requestMsgCtx.getAuthorizedUser().isFederatedUser();
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

    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws OAuthSystemException {

        Map<String, Object> userClaimsInOIDCDialect;
        Map<ClaimMapping, String> userAttributes =
                getUserAttributesCachedAgainstToken(getAccessToken(authzReqMessageContext));

        if (isEmpty(userAttributes) && isLocalUser(authzReqMessageContext)) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Trying to retrieve attribute for local user: " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser());
            }
            userClaimsInOIDCDialect = getClaimsForLocalUserInOIDCDialect(authzReqMessageContext);
        } else {
            userClaimsInOIDCDialect = getUserClaimsMapInOIDCDialect(userAttributes);
        }

        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String[] approvedScopes = authzReqMessageContext.getApprovedScope();
        return filterClaimsByScope(userClaimsInOIDCDialect, approvedScopes, clientId, spTenantDomain);
    }

    private Map<String, Object> getClaimsForLocalUserInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext) {
        try {
            String spTenantDomain = getServiceProviderTenantDomain(authzReqMessageContext);
            String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
            AuthenticatedUser authenticatedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();

            return getUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException e) {
            log.error("Error occurred while getting claims for user " +
                    authzReqMessageContext.getAuthorizationReqDTO().getUser(), e);
        }
        return new HashMap<>();
    }

    private boolean isLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return !authzReqMessageContext.getAuthorizationReqDTO().getUser().isFederatedUser();
    }

    private String getAccessToken(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return (String) authzReqMessageContext.getProperty(ACCESS_TOKEN);
    }

    /**
     * Get claims map
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private Map<String, Object> getUserClaimsMapInOIDCDialect(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<>();
        if (isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    /**
     * Get claims from user store
     *
     * @param tokenReqMessageContext Token request message context
     * @return Users claim map
     * @throws UserStoreException
     * @throws IdentityApplicationManagementException
     * @throws IdentityException
     */
    private Map<String, Object> getClaimsForLocalUserInOIDCDialect(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws UserStoreException, IdentityApplicationManagementException, IdentityException {

        String spTenantDomain = getServiceProviderTenantDomain(tokenReqMessageContext);
        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        AuthenticatedUser authenticatedUser = tokenReqMessageContext.getAuthorizedUser();

        return getUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain,
                                                           String clientId,
                                                           AuthenticatedUser authenticatedUser)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException {

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

        String userTenantDomain = authenticatedUser.getTenantDomain();
        String fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, fullQualifiedUsername);
        if (realm == null) {
            log.warn("Invalid tenant domain: " + userTenantDomain + " provided. Cannot get claims for user: "
                    + fullQualifiedUsername);
            return userClaimsMappedToOIDCDialect;
        }

        List<String> requestedClaimUris = getRequestedClaimUris(requestClaimMappings);
        Map<String, String> userClaims = getUserClaimsInLocalDialect(fullQualifiedUsername, realm, requestedClaimUris);

        if (isEmpty(userClaims)) {
            // User claims can be empty if user does not exist in user stores. Probably a federated user.
            if (log.isDebugEnabled()) {
                log.debug("No claims found for " + fullQualifiedUsername + " from user store.");
            }
            return userClaimsMappedToOIDCDialect;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Number of user claims retrieved for " + fullQualifiedUsername + " from user store: " + userClaims.size());
            }
            // Map the local roles to SP defined roles.
            handleServiceProviderRoleMappings(serviceProvider, ATTRIBUTE_SEPARATOR, userClaims);

            // Get the user claims in oidc dialect to be returned in the id_token.
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(spTenantDomain, userClaims);
            userClaimsMappedToOIDCDialect.putAll(userClaimsInOIDCDialect);
        }

        return userClaimsMappedToOIDCDialect;
    }

    private ClaimMapping[] getRequestedClaimMappings(ServiceProvider serviceProvider) {
        if (serviceProvider.getClaimConfig() == null) {
            return new ClaimMapping[0];
        }
        return serviceProvider.getClaimConfig().getClaimMappings();
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain,
                                                           Map<String, String> userClaims) throws ClaimMetadataException {
        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        // Get user claims in OIDC dialect.
        return getUserClaimsInOidcDialect(oidcToLocalClaimMappings, userClaims);
    }

    private Map<String, String> getUserClaimsInLocalDialect(String username,
                                                            UserRealm realm,
                                                            List<String> claimURIList)
            throws FrameworkException, UserStoreException {
        Map<String, String> userClaims = new HashMap<>();
        try {
            userClaims = realm.getUserStoreManager().getUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(username),
                    claimURIList.toArray(new String[claimURIList.size()]), null);
        } catch (UserStoreException e) {
            if (e.getMessage().contains(IdentityCoreConstants.USER_NOT_FOUND)) {
                if (log.isDebugEnabled()) {
                    log.debug("User: " + username + " not found in user store.");
                }
            } else {
                throw e;
            }
        }
        return userClaims;
    }

    private void handleServiceProviderRoleMappings(ServiceProvider serviceProvider,
                                                   String claimSeparator,
                                                   Map<String, String> userClaims) throws FrameworkException {
        if (isNotEmpty(userClaims) && userClaims.containsKey(LOCAL_ROLE_CLAIM_URI)) {
            String roleClaim = userClaims.get(LOCAL_ROLE_CLAIM_URI);
            // Arrays.asList() returns a structurally immutable list (ie. we can't add or remove but can update) so we
            // create a new LinkedList.
            List<String> rolesList = new LinkedList<>(Arrays.asList(roleClaim.split(getRegexLiteral(claimSeparator))));

            String spMappedRoleClaim = getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
            userClaims.put(LOCAL_ROLE_CLAIM_URI, spMappedRoleClaim);
        }
    }

    private String getRegexLiteral(String claimSeparator) {
        return Pattern.quote(claimSeparator);
    }

    private String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    /**
     * @param serviceProvider
     * @param locallyMappedUserRoles
     * @return
     */
    private String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                     List<String> locallyMappedUserRoles,
                                                     String claimSeparator) throws FrameworkException {

        if (CollectionUtils.isNotEmpty(locallyMappedUserRoles)) {
            // Get Local Role to Service Provider Role mappings.
            RoleMapping[] localToSpRoleMapping = serviceProvider.getPermissionAndRoleConfig().getRoleMappings();

            if (ArrayUtils.isNotEmpty(localToSpRoleMapping)) {
                for (RoleMapping roleMapping : localToSpRoleMapping) {
                    // Check whether a local role is mapped to service provider role.
                    if (locallyMappedUserRoles.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        // Remove the local role from the list of user roles.
                        locallyMappedUserRoles.remove(roleMapping.getLocalRole().getLocalRoleName());
                        // Add the service provider mapped role.
                        locallyMappedUserRoles.add(roleMapping.getRemoteRole());
                    }
                }
            }
        }

        return StringUtils.join(locallyMappedUserRoles, claimSeparator);
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
     * Get user claims in OIDC claim dialect
     *
     * @param oidcToLocalClaimMappings OIDC dialect to Local dialect claim mappings
     * @param userClaims               User claims in local dialect
     * @return Map of user claim values in OIDC dialect.
     */
    private Map<String, Object> getUserClaimsInOidcDialect(Map<String, String> oidcToLocalClaimMappings,
                                                           Map<String, String> userClaims) {

        Map<String, Object> userClaimsInOidcDialect = new HashMap<>();
        if (isNotEmpty(userClaims)) {
            // Map<"email", "http://wso2.org/claims/emailaddress">
            for (Map.Entry<String, String> claimMapping : oidcToLocalClaimMappings.entrySet()) {
                String claimValue = userClaims.get(claimMapping.getValue());
                if (claimValue != null) {
                    String oidcClaimUri = claimMapping.getKey();
                    userClaimsInOidcDialect.put(oidcClaimUri, claimValue);
                    if (log.isDebugEnabled() &&
                            IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                        log.debug("Mapped claim: key - " + oidcClaimUri + " value - " + claimValue);
                    }
                }
            }
        }

        return userClaimsInOidcDialect;
    }

    /**
     * Get user attribute cached against the access token
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
     * Get user attributes cached against the authorization code
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
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByCode(cacheKey);

        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Set user claims in OIDC dialect to the JWTClaimSet. Additionally we process multi values attributes here.
     *
     * @param jwtClaimsSet
     * @param userClaimsInOIDCDialect
     */
    private void setClaimsToJwtClaimSet(JWTClaimsSet jwtClaimsSet, Map<String, Object> userClaimsInOIDCDialect) {
        for (Map.Entry<String, Object> claimEntry : userClaimsInOIDCDialect.entrySet()) {
            String claimValue = claimEntry.getValue().toString();
            if (isMultiValuedAttribute(claimValue)) {
                JSONArray claimValues = new JSONArray();
                String[] attributeValues = claimValue.split(getRegexLiteral(ATTRIBUTE_SEPARATOR));
                for (String attributeValue : attributeValues) {
                    if (StringUtils.isNotBlank(attributeValue)) {
                        claimValues.add(attributeValue);
                    }
                }
                jwtClaimsSet.setClaim(claimEntry.getKey(), claimValues);
            } else {
                jwtClaimsSet.setClaim(claimEntry.getKey(), claimEntry.getValue());
            }
        }
    }

    private boolean isMultiValuedAttribute(String claimValue) {
        return StringUtils.contains(claimValue, ATTRIBUTE_SEPARATOR);
    }
}
