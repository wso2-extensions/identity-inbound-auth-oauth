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

package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.exception.ApplicationRolesException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoEndpointConfig;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.core.util.IdentityUtil.isTokenLoggable;

/**
 * Util class which contains claim related data.
 */
public class ClaimUtil {

    private static final String SP_DIALECT = "http://wso2.org/oidc/claim";
    private static final String GROUPS = "groups";
    private static final Log log = LogFactory.getLog(ClaimUtil.class);

    private ClaimUtil() {

    }

    public static Map<String, Object> getUserClaimsUsingTokenResponse(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);
        Map<String, Object> userClaimsInOIDCDialect;
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache against the token. Retrieved claims from user store.");
            }
            userClaimsInOIDCDialect = getClaimsFromUserStore(tokenResponse);
        } else {
            UserInfoClaimRetriever retriever = UserInfoEndpointConfig.getInstance().getUserInfoClaimRetriever();
            userClaimsInOIDCDialect = retriever.getClaimsMap(userAttributes);
        }

        if (isEmpty(userClaimsInOIDCDialect)) {
            userClaimsInOIDCDialect = new HashMap<>();
        }

        return userClaimsInOIDCDialect;
    }

    /**
     * Get claims from user store for the user represented by the token response.
     *
     * @param tokenResponse OAuth2TokenValidationResponseDTO containing the token information.
     * @return Map of claims retrieved from the user store.
     * @throws UserInfoEndpointException If an error occurs while retrieving claims.
     */
    public static Map<String, Object> getClaimsFromUserStore(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        String authorizedUserName = StringUtils.EMPTY;
        try {
            AccessTokenDO accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(tokenResponse.getAuthorizationContextToken().getTokenString(),
                            false);
            authorizedUserName = tokenResponse.getAuthorizedUser();
            String userId = accessTokenDO.getAuthzUser().getUserId();
            String userTenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();
            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            String clientId = getClientID(accessTokenDO);

            return getClaimsFromUserStore(authorizedUserName, userId, userTenantDomain,
                    authenticatedUser, clientId, false);
        } catch (IdentityOAuth2Exception | UserIdNotFoundException e) {
            throw new UserInfoEndpointException("Error while retrieving claims for user: " +
                    tokenResponse.getAuthorizedUser(), e);
        } catch (Exception e) {
            String errMsg = StringUtils.isNotEmpty(authorizedUserName) ? "Error while retrieving the claims " +
                    "from user store for the username: " + authorizedUserName : "Error while retrieving the " +
                    "claims from user store";
            log.error(errMsg, e);
            throw new UserInfoEndpointException(errMsg);
        }
    }

    /**
     * Retrieves claims from the user store for the given user.
     *
     * @param authorizedUserName   Authorized username.
     * @param userId               User ID.
     * @param userTenantDomain     User tenant domain.
     * @param authenticatedUser    Authenticated user object.
     * @param clientId             Client ID of the application.
     * @param isImpersonatedUser   Flag indicating if the user is impersonated.
     * @return Map of claims retrieved from the user store.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving claims.
     */
    public static Map<String, Object> getClaimsFromUserStore(String authorizedUserName, String userId,
                                                             String userTenantDomain,
                                                             AuthenticatedUser authenticatedUser,
                                                             String clientId, boolean isImpersonatedUser)
            throws IdentityOAuth2Exception {

        UserRealm realm;
        List<String> claimURIList = new ArrayList<>();
        Map<String, Object> mappedAppClaims = new HashMap<>();
        String subjectClaimValue = null;
        try {
            // If the authenticated user is a federated user and had not mapped to local users, no requirement to
            // retrieve claims from local user store.

            if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && !isImpersonatedUser) {
                if (isNotEmpty(authenticatedUser.getUserStoreDomain())) {
                    String userStoreDomain = authenticatedUser.getUserStoreDomain();
                    if (OAuth2Util.isFederatedUser(authenticatedUser)) {
                        return handleClaimsForFederatedUser(authorizedUserName, mappedAppClaims, userStoreDomain);
                    }
                }
            }

            Map<String, String> spToLocalClaimMappings;
            String spTenantDomain;
            String appResidentTenantDomain = OAuth2Util.getAppResidentTenantDomain();
            if (StringUtils.isNotEmpty(appResidentTenantDomain)) {
                spTenantDomain = appResidentTenantDomain;
            } else {
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
                spTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            }

            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId, spTenantDomain);
            ClaimMapping[] requestedLocalClaimMappings = serviceProvider.getClaimConfig().getClaimMappings();
            String subjectClaimURI = getSubjectClaimUri(serviceProvider, requestedLocalClaimMappings);

            if (StringUtils.isNotBlank(subjectClaimURI)) {
                claimURIList.add(subjectClaimURI);
            }

            boolean isSubjectClaimInRequested = false;
            if (StringUtils.isNotBlank(subjectClaimURI) || ArrayUtils.isNotEmpty(requestedLocalClaimMappings)) {
                if (requestedLocalClaimMappings != null) {
                    for (ClaimMapping claimMapping : requestedLocalClaimMappings) {
                        if (claimMapping.isRequested()) {
                            claimURIList.add(claimMapping.getLocalClaim().getClaimUri());
                            if (claimMapping.getLocalClaim().getClaimUri().equals(subjectClaimURI)) {
                                isSubjectClaimInRequested = true;
                            }
                        }
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("Requested number of local claims: " + claimURIList.size());
                }

                spToLocalClaimMappings = ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon
                        (SP_DIALECT, null, userTenantDomain, true);

                Map<String, String> userClaims;
                if (!StringUtils.equals(authenticatedUser.getUserResidentOrganization(),
                        authenticatedUser.getAccessingOrganization()) &&
                        StringUtils.isNotEmpty(AuthzUtil.getUserIdOfAssociatedUser(authenticatedUser))) {
                    authenticatedUser.setSharedUserId(AuthzUtil.getUserIdOfAssociatedUser(authenticatedUser));
                    authenticatedUser.setUserSharedOrganizationId(authenticatedUser
                            .getAccessingOrganization());
                }
                if (OIDCClaimUtil.isSharedUserProfileResolverEnabled() &&
                        OIDCClaimUtil.isSharedUserAccessingSharedOrg(authenticatedUser) &&
                        StringUtils.isNotEmpty(authenticatedUser.getSharedUserId())) {
                    String userAccessingTenantDomain =
                            OIDCClaimUtil.resolveTenantDomain(authenticatedUser.getAccessingOrganization());
                    String sharedUserId = authenticatedUser.getSharedUserId();
                    realm = getUserRealm(null, userAccessingTenantDomain);
                    try {
                        FrameworkUtils.startTenantFlow(userAccessingTenantDomain);
                        userClaims = getUserClaimsFromUserStoreWithResolvedRoles(authenticatedUser, serviceProvider,
                                sharedUserId, realm, claimURIList);
                    } finally {
                        FrameworkUtils.endTenantFlow();
                    }
                } else {
                    realm = getUserRealm(null, userTenantDomain);
                    userClaims = getUserClaimsFromUserStoreWithResolvedRoles(authenticatedUser, serviceProvider,
                            userId, realm, claimURIList);
                }

                if (isNotEmpty(userClaims)) {
                    for (Map.Entry<String, String> entry : userClaims.entrySet()) {
                        //set local2sp role mappings
                        if (IdentityUtil.getRoleGroupClaims().stream().anyMatch(roleGroupClaimURI ->
                                roleGroupClaimURI.equals(entry.getKey()))) {
                            String claimSeparator = getMultiAttributeSeparator(userId, realm);
                            entry.setValue(getSpMappedRoleClaim(serviceProvider, entry, claimSeparator));
                        }

                        String oidcClaimUri = spToLocalClaimMappings.get(entry.getKey());
                        String claimValue = entry.getValue();
                        if (oidcClaimUri != null) {
                            if (entry.getKey().equals(subjectClaimURI)) {
                                subjectClaimValue = claimValue;
                                if (!isSubjectClaimInRequested) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Subject claim: " + entry.getKey() + " is not a requested " +
                                                "claim. Not adding to claim map.");
                                    }
                                    continue;
                                }
                            }
                            boolean isMultiValueSupportEnabledForUserinfoResponse = OAuthServerConfiguration
                                    .getInstance().getUserInfoMultiValueSupportEnabled();
                            if (isMultiValueSupportEnabledForUserinfoResponse &&
                                    isMultiValuedAttribute(oidcClaimUri, claimValue)) {
                                String[] attributeValues = processMultiValuedAttribute(claimValue);
                                mappedAppClaims.put(oidcClaimUri, attributeValues);
                            } else {
                                mappedAppClaims.put(oidcClaimUri, claimValue);
                            }

                            if (log.isDebugEnabled() &&
                                    isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                                log.debug("Mapped claim: key -  " + oidcClaimUri + " value -" + claimValue);
                            }
                        }
                    }
                }
            }

            if (StringUtils.isBlank(subjectClaimValue)) {
                if (log.isDebugEnabled()) {
                    log.debug("No subject claim found. Defaulting to username as the sub claim.");
                }
                subjectClaimValue = getUsernameFromTokenResponse(authorizedUserName);
            }

            if (log.isDebugEnabled() && isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                log.debug("Subject claim(sub) value: " + subjectClaimValue + " set in returned claims.");
            }
            mappedAppClaims.put(OAuth2Util.SUB, subjectClaimValue);
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug(" Error while retrieving App information with provided client id.", e);
            }
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (Exception e) {
            if (e instanceof UserStoreException) {
                if (e.getMessage().contains("UserNotFound")) {
                    if (log.isDebugEnabled()) {
                        log.debug(StringUtils.isNotEmpty(authorizedUserName) ? "User with username: "
                                + authorizedUserName + ", cannot be found in user store" : "User cannot " +
                                "found in user store");
                    }
                }
            } else {
                String errMsg = StringUtils.isNotEmpty(authorizedUserName) ? "Error while retrieving the claims " +
                        "from user store for the username: " + authorizedUserName : "Error while retrieving the " +
                        "claims from user store";
                log.error(errMsg, e);
                throw new IdentityOAuth2Exception(errMsg);
            }
        }
        return mappedAppClaims;
    }

    /**
     * Map the local roles of a user to service provider mapped role values.
     *
     * @param serviceProvider
     * @param locallyMappedUserRoles
     * @deprecated use {@link OIDCClaimUtil#getServiceProviderMappedUserRoles(ServiceProvider, List, String)} instead.
     */
    @Deprecated
    public static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                           List<String> locallyMappedUserRoles,
                                                           String claimSeparator) throws FrameworkException {

        return OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, locallyMappedUserRoles, claimSeparator);
    }

    private static String getSpMappedRoleClaim(ServiceProvider serviceProvider,
                                               Map.Entry<String, String> entry,
                                               String claimSeparator) throws FrameworkException {

        String roleClaim = entry.getValue();
        List<String> rolesList = Arrays.asList(roleClaim.split(claimSeparator));
        return OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
    }

    private static String getMultiAttributeSeparator(String username,
                                                     UserRealm realm) throws UserStoreException {

        String domain = IdentityUtil.extractDomainFromName(username);
        RealmConfiguration realmConfiguration =
                realm.getUserStoreManager().getSecondaryUserStoreManager(domain).getRealmConfiguration();
        String claimSeparator =
                realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isBlank(claimSeparator)) {
            claimSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        return claimSeparator;
    }

    private static Map<String, String> getUserClaimsFromUserStore(String userId,
                                                                  UserRealm realm,
                                                                  List<String> claimURIList) throws UserStoreException {

        AbstractUserStoreManager userstore = (AbstractUserStoreManager) realm.getUserStoreManager();
        if (userstore == null) {
            throw new UserStoreException("Unable to retrieve UserStoreManager");
        }
        Map<String, String> userClaims =
                userstore.getUserClaimValuesWithID(userId, claimURIList.toArray(new String[0]), null);
        if (log.isDebugEnabled()) {
            log.debug("User claims retrieved from user store: " + userClaims.size());
        }
        return userClaims;
    }

    private static Map<String, String> getUserClaimsFromUserStoreWithResolvedRoles(AuthenticatedUser authenticatedUser,
                                                                                   ServiceProvider serviceProvider,
                                                                                   String resolvedUserId,
                                                                                   UserRealm realm,
                                                                                   List<String> claimURIList)
            throws UserStoreException {

        Map<String, String> userClaims = getUserClaimsFromUserStore(resolvedUserId, realm, claimURIList);
        try {
            // Check whether the roles claim is requested.
            boolean isRoleClaimRequested = CollectionUtils.isNotEmpty(claimURIList) &&
                    claimURIList.contains(FrameworkConstants.ROLES_CLAIM);
            String appTenantDomain = serviceProvider.getTenantDomain();
            // Check whether the application is a shared app or an application created in sub org.
            boolean isSubOrgApp = OrganizationManagementUtil.isOrganization(appTenantDomain);
            // Resolving roles claim for sub org apps and shared apps since backward compatibility is not needed.
            if (isRoleClaimRequested && isSubOrgApp) {
                String[] appAssociatedRoles = OIDCClaimUtil.getAppAssociatedRolesOfUser(authenticatedUser,
                        serviceProvider.getApplicationResourceId());
                if (appAssociatedRoles != null && appAssociatedRoles.length > 0) {
                    // If application associated roles are returned, set the roles claim using resolved roles.
                    userClaims.put(FrameworkConstants.ROLES_CLAIM,
                            String.join(FrameworkUtils.getMultiAttributeSeparator(), appAssociatedRoles));
                } else {
                    // If no roles are returned, remove the roles claim from user claims.
                    userClaims.remove(FrameworkConstants.ROLES_CLAIM);
                }
            }
        } catch (ApplicationRolesException e) {
            throw new UserStoreException("Error while retrieving application associated roles for user.", e);
        } catch (OrganizationManagementException e) {
            throw new UserStoreException("Error while checking whether application tenant domain is an organization.");
        }
        return userClaims;
    }

    private static UserRealm getUserRealm(String username,
                                          String userTenantDomain) throws IdentityException, UserInfoEndpointException {

        UserRealm realm;
        realm = IdentityTenantUtil.getRealm(userTenantDomain, username);
        if (realm == null) {
            throw new UserInfoEndpointException("Invalid User Domain provided: " + userTenantDomain +
                    "Cannot retrieve user claims for user: " + username);
        }
        return realm;
    }

    private static String getSubjectClaimUri(ServiceProvider serviceProvider, ClaimMapping[] requestedLocalClaimMap) {

        String subjectClaimURI = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
        if (requestedLocalClaimMap != null) {
            for (ClaimMapping claimMapping : requestedLocalClaimMap) {
                if (claimMapping.getRemoteClaim().getClaimUri().equals(subjectClaimURI)) {
                    subjectClaimURI = claimMapping.getLocalClaim().getClaimUri();
                    break;
                }
            }
        }
        return subjectClaimURI;
    }

    private static String getClientID(AccessTokenDO accessTokenDO) throws UserInfoEndpointException {

        if (accessTokenDO != null) {
            return accessTokenDO.getConsumerKey();
        } else {
            // this means the token is not active so we can't proceed further
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN,
                    "Invalid Access Token. Access token is not ACTIVE.");
        }
    }

    private static Map<String, Object> handleClaimsForFederatedUser(String subjectClaimValue,
                                                                    Map<String, Object> mappedAppClaims,
                                                                    String userStoreDomain) {

        if (log.isDebugEnabled()) {
            log.debug("Federated user store prefix available in domain " + userStoreDomain + ". User is federated so " +
                    "not retrieving claims from user store.");
        }
        // Add the sub claim.
        mappedAppClaims.put(OAuth2Util.SUB, subjectClaimValue);
        if (log.isDebugEnabled() && isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            log.debug("Subject claim(sub) value: " + subjectClaimValue + " set in returned claims.");
        }
        return mappedAppClaims;
    }

    private static String getUsernameFromTokenResponse(String authorizedUserName) {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(authorizedUserName);
        return UserCoreUtil.removeDomainFromName(tenantAwareUsername);
    }

    private static Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        AuthorizationGrantCacheKey cacheKey =
                new AuthorizationGrantCacheKey(OAuth2Util.getAccessTokenIdentifier(tokenResponse));
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
        if (cacheEntry == null) {
            return new HashMap<>();
        }
        return cacheEntry.getUserAttributes();
    }

    /**
     * Check whether claim value is multivalued attribute or not by using attribute separator.
     *
     * @param claimValue String value contains claims.
     * @return Whether it is multivalued attribute or not.
     */
    public static boolean isMultiValuedAttribute(String claimValue) {

        return StringUtils.contains(claimValue, FrameworkUtils.getMultiAttributeSeparator());
    }

    /**
     * Checks whether a user value is multivalued or not.
     *
     * @param claimUri String value contains claim uri.
     * @param claimValue String value contains claims.
     * @return Whether it is multivalued attribute or not.
     */
    public static boolean isMultiValuedAttribute(String claimUri, String claimValue) {

        /* To format the groups claim to always return as an array, we should consider single
        group as multi value attribute. */
        if (GROUPS.equals(claimUri)) {
            return true;
        }
        return StringUtils.contains(claimValue, FrameworkUtils.getMultiAttributeSeparator());
    }

    /**
     * Split multivalued attribute string value by attribute separator.
     *
     * @param claimValue String value contains claims.
     * @return String array of multivalued claim values.
     */
    public static String[] processMultiValuedAttribute(String claimValue) {

        return claimValue.split(Pattern.quote(FrameworkUtils.getMultiAttributeSeparator()));
    }
}
