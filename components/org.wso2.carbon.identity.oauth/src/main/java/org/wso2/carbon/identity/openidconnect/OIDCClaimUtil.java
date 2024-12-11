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
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.ApplicationRolesResolver;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.exception.ApplicationRolesException;
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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.SubjectType;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
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
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.lang.ArrayUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.APP_ROLES_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.GROUPS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.InternalRoleDomains.
        APPLICATION_DOMAIN;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.InternalRoleDomains.
        WORKFLOW_DOMAIN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_CODE;

/**
 * Utility to handle OIDC Claim related functionality.
 */
public class OIDCClaimUtil {

    private static final Log log = LogFactory.getLog(OIDCClaimUtil.class);
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String SEND_ONLY_SP_MAPPED_ROLES = "SPRoleManagement.ReturnOnlyMappedLocalRoles";
    public static final String DEFAULT_SUBJECT_TYPE = "OAuth.OpenIDConnect.DefaultSubjectType";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String OAUTH2 = "oauth2";

    private OIDCClaimUtil() {
    }

    /**
     * Map the local roles of a user to service provider mapped role values.
     *
     * @param serviceProvider
     * @param locallyMappedUserRoles List of local roles
     * @param claimSeparator         Separator used to combine individual roles in the returned string.
     * @return Service Provider mapped roles combined with claimSeparator
     */
    public static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                           List<String> locallyMappedUserRoles,
                                                           String claimSeparator) throws FrameworkException {
        if (isNotEmpty(locallyMappedUserRoles)) {
            locallyMappedUserRoles = new ArrayList<>(locallyMappedUserRoles);
            // Get Local Role to Service Provider Role mappings.
            RoleMapping[] localToSpRoleMapping = serviceProvider.getPermissionAndRoleConfig().getRoleMappings();

            // List which will hold list of local roles that user store domain name to be removed.
            List<String> listOfRolesToRemoveDomainName = new ArrayList<>();
            // List which will hold list of service provider roles which are mapped to local roles internally
            List<String> spMappedRoles = new ArrayList<>();
            // Configuration in identity.xml which forces to return only sp mapped roles.
            boolean returnOnlyMappedLocalRoles = Boolean
                    .parseBoolean(IdentityUtil.getProperty(SEND_ONLY_SP_MAPPED_ROLES));
            // Boolean value defining whether user store domain name in the role name should be removed or not.
            boolean isRemoveUserDomainInRole = isRemoveUserDomainInRole(serviceProvider);

            if (isNotEmpty(localToSpRoleMapping)) {
                for (RoleMapping roleMapping : localToSpRoleMapping) {
                    // Check whether a local role is mapped to service provider role.
                    if (locallyMappedUserRoles.contains(getLocalRoleName(roleMapping))) {
                        // Remove the local roles from the list of user roles.
                        locallyMappedUserRoles.removeAll(Collections.singletonList(getLocalRoleName(roleMapping)));
                        // Add the service provider mapped role.
                        spMappedRoles.add(roleMapping.getRemoteRole());
                    }
                }
                if (!returnOnlyMappedLocalRoles) {
                    if (isRemoveUserDomainInRole) {
                        listOfRolesToRemoveDomainName = locallyMappedUserRoles;
                    } else {
                        spMappedRoles.addAll(locallyMappedUserRoles);
                    }
                }
            } else {
                if (isRemoveUserDomainInRole) {
                    listOfRolesToRemoveDomainName = locallyMappedUserRoles;
                } else {
                    spMappedRoles = locallyMappedUserRoles;
                }
            }
            if (isRemoveUserDomainInRole) {
                List<String> domainRemovedRoles = removeDomainFromNamesExcludeHybrid(listOfRolesToRemoveDomainName);
                if (!domainRemovedRoles.isEmpty()) {
                    spMappedRoles.addAll(domainRemovedRoles);
                }
            }
            return StringUtils.join(spMappedRoles, claimSeparator);
        }
        return null;
    }

    private static boolean isRemoveUserDomainInRole(ServiceProvider serviceProvider) {

        if (serviceProvider.getLocalAndOutBoundAuthenticationConfig() != null) {
            return !serviceProvider.getLocalAndOutBoundAuthenticationConfig().isUseUserstoreDomainInRoles();
        }
        return false;
    }

    /**
     * Remove domain name from roles except the hybrid roles (Internal,Application & Workflow)
     *
     * @param names list of roles assigned to a user
     * @return list of roles assigned to a user with domain name removed from roles
     */
    private static List<String> removeDomainFromNamesExcludeHybrid(List<String> names) {
        List<String> nameList = new ArrayList<String>();
        for (String name : names) {
            String userStoreDomain = IdentityUtil.extractDomainFromName(name);
            if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStoreDomain) || APPLICATION_DOMAIN
                    .equalsIgnoreCase(userStoreDomain) || WORKFLOW_DOMAIN.equalsIgnoreCase(userStoreDomain)) {
                nameList.add(name);
            } else {
                nameList.add(UserCoreUtil.removeDomainFromName(name));
            }
        }
        return nameList;
    }


    public static String getSubjectClaimCachedAgainstAccessToken(String accessToken) {
        if (isNotBlank(accessToken)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
            if (cacheEntry != null) {
                return cacheEntry.getSubjectClaim();
            }
        }
        return null;
    }

    private static String getLocalRoleName(RoleMapping roleMapping) {
        return roleMapping.getLocalRole().getLocalRoleName();
    }

    /**
     * Filter user claims based on consent with the highest priority {@link OpenIDConnectClaimFilter}. Consent based
     * user claims filtering can be configured at the global level.
     *
     * @deprecated This method only supports global level consent based user claims filtering configurations. Please
     * use {@link #filterUserClaimsBasedOnConsent(Map, AuthenticatedUser, String, String, String, ServiceProvider)}
     * which supports SP level configurations as well.
     */
    @Deprecated
    public static Map<String, Object> filterUserClaimsBasedOnConsent(Map<String, Object> userClaims,
                                                                     AuthenticatedUser authenticatedUser,
                                                                     String clientId,
                                                                     String spTenantDomain,
                                                                     String grantType) {

        if (isConsentBasedClaimFilteringApplicable(grantType)) {
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByUserConsent(userClaims, authenticatedUser, clientId, spTenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                String msg = "Filtering user claims based on consent skipped for grant type:%s. Returning original " +
                        "user claims for user: %s, for clientId: %s of tenantDomain: %s";
                log.debug(String.format(msg, grantType, authenticatedUser.toFullQualifiedUsername(),
                        clientId, spTenantDomain));
            }
            return userClaims;
        }
    }

    /**
     * Filter user claims based on consent with the highest priority {@link OpenIDConnectClaimFilter}. Consent based
     * user claims filtering can be configured at the global level, as well as the service provider level.
     */
    public static Map<String, Object> filterUserClaimsBasedOnConsent(Map<String, Object> userClaims,
                                                                     AuthenticatedUser authenticatedUser,
                                                                     String clientId,
                                                                     String spTenantDomain,
                                                                     String grantType,
                                                                     ServiceProvider serviceProvider) {

        if (isConsentBasedClaimFilteringApplicable(grantType) &&
                !FrameworkUtils.isConsentPageSkippedForSP(serviceProvider)) {
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByUserConsent(userClaims, authenticatedUser, clientId, spTenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                String msg = "Filtering user claims based on consent skipped for grant type:%s. Returning original " +
                        "user claims for user:%s, for clientId:%s of tenantDomain:%s";
                log.debug(String.format(msg, grantType, authenticatedUser.toFullQualifiedUsername(),
                        clientId, spTenantDomain));
            }
            return userClaims;
        }
    }

    /**
     * Get oidc claims mapping.
     *
     * @param spTenantDomain    Tenant domain.
     * @param claims            User claims
     * @return user attributes.
     * @throws IdentityOAuth2Exception If an exception occurred while getting user claims.
     */
    public static Map<String, Object> getMergedUserClaimsInOIDCDialect(String spTenantDomain,
                                                                       Map<String, String> claims)
            throws IdentityOAuth2Exception {

        Map<String, Object> oidcClaims = new HashMap<>();
        try {
            oidcClaims = OIDCClaimUtil.getUserClaimsInOIDCDialect(spTenantDomain, claims);
            // Merge the initial claims into oidcClaims, while prioritizing the initial claims map.
            oidcClaims.putAll(claims);
            return oidcClaims;
        } catch (ClaimMetadataException e) {
            throw new IdentityOAuth2Exception("Error occurred while mapping claims for user: " +
                    " from userstore.", e);
        }
    }

    public static Map<String, Object> filterUserClaimsBasedOnConsent(Map<String, Object> userClaims,
                                                                     AuthenticatedUser authenticatedUser,
                                                                     String clientId,
                                                                     String spTenantDomain,
                                                                     String grantType,
                                                                     ServiceProvider serviceProvider,
                                                                     boolean isConsentedToken) {

        if (!OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            return filterUserClaimsBasedOnConsent(userClaims, authenticatedUser, clientId, spTenantDomain, grantType,
                    serviceProvider);
        } else {
            if (isConsentedToken && !FrameworkUtils.isConsentPageSkippedForSP(serviceProvider)) {
                return OpenIDConnectServiceComponentHolder.getInstance()
                        .getHighestPriorityOpenIDConnectClaimFilter()
                        .getClaimsFilteredByUserConsent(userClaims, authenticatedUser, clientId, spTenantDomain);
            } else {
                if (log.isDebugEnabled()) {
                    String msg = "Filtering user claims based on consent skipped for grant type. Returning " +
                            "original user claims for user:%s, for clientId:%s of tenantDomain:%s";
                    log.debug(String.format(msg, authenticatedUser.toFullQualifiedUsername(),
                            clientId, spTenantDomain));
                }
                return userClaims;
            }
        }
    }

    public static boolean isConsentBasedClaimFilteringApplicable(String grantType) {

        return isOIDCConsentPageNotSkipped() && isUserConsentRequiredForClaims(grantType);
    }

    private static boolean isOIDCConsentPageNotSkipped() {

        return !OAuthServerConfiguration.getInstance().getOpenIDConnectSkipeUserConsentConfig();
    }

    /**
     * Check whether user consent based claim filtering is applicable for the grant type.
     *
     * @param grantType
     * @return
     */
    private static boolean isUserConsentRequiredForClaims(String grantType) {

        return OAuthServerConfiguration.getInstance().isUserConsentRequiredForClaims(grantType);
    }

    /**
     * Get the application's preferred subject type.
     *
     * @param authAppDO oauth app
     * @return subject type
     */

    public static SubjectType getSubjectType(OAuthAppDO authAppDO) {

        if (StringUtils.isNotEmpty(authAppDO.getSubjectType())) {
            return SubjectType.fromValue(authAppDO.getSubjectType());
        }
        // return default subject type if the property is not configured.
        log.debug("Subject type is not configured for the service provider: " + authAppDO.getOauthConsumerKey() +
                ". Returning default subject type: " + getDefaultSubjectType());
        return getDefaultSubjectType();
    }

    public static SubjectType getDefaultSubjectType() {

        return StringUtils.isNotBlank(IdentityUtil.getProperty(DEFAULT_SUBJECT_TYPE)) ?
                SubjectType.fromValue(IdentityUtil.getProperty(DEFAULT_SUBJECT_TYPE)) : SubjectType.PUBLIC;
    }

    /**
     * Get the subject claim for the given user. If pairwise subject type is opted, then a PPID will be returned,
     * otherwise, the authenticated user's username will be returned.
     *
     * @param authenticatedSubjectIdentifier authenticated subject identifier
     * @param application                    oauth app
     * @return sub claim
     * @throws IdentityOAuth2Exception when an error occurred while getting the service provider properties or user id
     */
    public static String getSubjectClaim(String authenticatedSubjectIdentifier, OAuthAppDO application)
            throws IdentityOAuth2Exception {

        if (SubjectType.PAIRWISE.equals(getSubjectType(application))) {
            String sectorIdentifierUri = application.getSectorIdentifierURI();
            return getPairwiseSubjectIdentifier(sectorIdentifierUri, authenticatedSubjectIdentifier,
                    application.getCallbackUrl());
        }
        return authenticatedSubjectIdentifier;
    }

    /**
     * Calculate pairwise subject identifier.
     * <a href="https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg">...</a>
     *
     * @param sectorIdentifierUri sector identifier URI
     * @param userId              user id
     * @param callBackURI         callback URI
     * @return pairwise subject identifier
     * @throws IdentityOAuth2Exception if required values are not present
     */
    private static String getPairwiseSubjectIdentifier(String sectorIdentifierUri, String userId, String callBackURI)
            throws IdentityOAuth2Exception {

        URI uri = null;
        if (StringUtils.isNotBlank(sectorIdentifierUri)) {
            uri = URI.create(sectorIdentifierUri);
        } else if (StringUtils.isNotBlank(callBackURI) && isValidCallBackURI(callBackURI)) {
            uri = URI.create(callBackURI);
        }
        String hostname;
        if (uri != null) {
            hostname = uri.getHost();
        } else {
            throw new IdentityOAuth2Exception("Invalid sector identifier URI or callback URI.");
        }

        if (StringUtils.isBlank(userId)) {
            throw new IdentityOAuth2Exception("Invalid user id.");
        }

        String seed = hostname.concat(userId);
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }

    /**
     * Check whether the callback URI is not a regex. If multiple callbacks are configured, then that callback URI
     * cannot be used in pairwise subject identifier calculation.
     *
     * @param callBackURI callback URI
     * @return true if the callback URI is not a regex
     */
    private static boolean isValidCallBackURI(String callBackURI) {

        return !callBackURI.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX);
    }

    public static String getCallbackUrl(String clientId, String tenantDomain) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
        return oAuthAppDO != null ? oAuthAppDO.getCallbackUrl() : null;
    }

    /**
     * Get user claims in OIDC dialect.
     *
     * @param serviceProvider Service Provider
     * @param authenticatedUser Authenticated User
     * @param claimURIList List of claim URIs
     * @return User claims in OIDC dialect
     * @throws IdentityException
     * @throws UserStoreException
     * @throws OrganizationManagementException
     */
    public static Map<String, Object> getUserClaimsInOIDCDialect(ServiceProvider serviceProvider,
                                                          AuthenticatedUser authenticatedUser,
                                                          List<String> claimURIList) throws IdentityException,
            UserStoreException, OrganizationManagementException {

        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();

        String fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
        String userTenantDomain = authenticatedUser.getTenantDomain();
        String userResidentTenantDomain = userTenantDomain;
        if (StringUtils.isNotEmpty(authenticatedUser.getUserResidentOrganization())) {
            userResidentTenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(authenticatedUser.getUserResidentOrganization());
        }
        /* For B2B users, the resident organization is available to find the tenant where the user's identity is
        managed. Hence, the correct tenant domain should be used to fetch user claims. */
        if (!StringUtils.equals(userTenantDomain, userResidentTenantDomain)) {
            String userId = authenticatedUser.getUserId();
            if (authenticatedUser.isFederatedUser()) {
                userId = resolveUserIdForOrganizationSsoUser(authenticatedUser);
            }
            AbstractUserStoreManager userStoreManager =
                    (AbstractUserStoreManager) OAuthComponentServiceHolder.getInstance().getRealmService()
                            .getTenantUserRealm(IdentityTenantUtil.getTenantId(userResidentTenantDomain))
                            .getUserStoreManager();
            userTenantDomain = userResidentTenantDomain;
            fullQualifiedUsername = userStoreManager.getUser(userId, null)
                    .getFullQualifiedUsername();
        }

        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, fullQualifiedUsername);
        if (realm == null) {
            log.warn("Invalid tenant domain: " + userTenantDomain + " provided. Cannot get claims for user: "
                    + fullQualifiedUsername);
            return userClaimsMappedToOIDCDialect;
        }

        boolean roleClaimRequested = false;
        String rolesClaimURI = IdentityUtil.getLocalGroupsClaimURI();
        if (claimURIList.contains(rolesClaimURI) && !CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
            claimURIList.remove(rolesClaimURI);
            roleClaimRequested = true;
        }
        boolean appRoleClaimRequested = false;
        if (claimURIList.contains(APP_ROLES_CLAIM)) {
            claimURIList.remove(APP_ROLES_CLAIM);
            appRoleClaimRequested = true;
        }
        Map<String, String> userClaims = getUserClaimsInLocalDialect(fullQualifiedUsername, realm, claimURIList);

        if (roleClaimRequested || appRoleClaimRequested) {
            String[] appAssocatedRolesOfUser = getAppAssociatedRolesOfUser(authenticatedUser,
                    serviceProvider.getApplicationResourceId());
            if (roleClaimRequested) {
                setRoleClaimInLocalDialect(userClaims, appAssocatedRolesOfUser);
            }
            if (appRoleClaimRequested) {
                setAppRoleClaimInLocalDialect(userClaims, appAssocatedRolesOfUser);
            }
        }

        /*
        If the application requested for groups and a shared user is accessing a shared org of that user,
        get the groups of the shared user from the shared organization.
        */
        if (claimURIList.contains(GROUPS_CLAIM) && isSharedUserAccessingSharedOrg(authenticatedUser) &&
                StringUtils.isNotEmpty(authenticatedUser.getSharedUserId())) {
            addSharedUserGroupsFromSharedOrganization(authenticatedUser, userClaims);
        }

        if (isEmpty(userClaims)) {
            // User claims can be empty if user does not exist in user stores. Probably a federated user.
            if (log.isDebugEnabled()) {
                log.debug("No claims found for " + fullQualifiedUsername + " from user store.");
            }
            return userClaimsMappedToOIDCDialect;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Number of user claims retrieved for " + fullQualifiedUsername + " from user store: " +
                        userClaims.size());
            }
            // Map the local roles to SP defined roles.
            handleServiceProviderRoleMappings(serviceProvider, FrameworkUtils.getMultiAttributeSeparator(),
                    userClaims);

            // Get the user claims in oidc dialect to be returned in the id_token.
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(serviceProvider.getTenantDomain(),
                    userClaims);
            userClaimsMappedToOIDCDialect.putAll(userClaimsInOIDCDialect);
        }

        return userClaimsMappedToOIDCDialect;
    }

    /**
     * Resolve the userId of the organization SSO user from username.
     *
     * @param authenticatedUser authorized user from the token request.
     * @return the userId of the organization SSO user from username.
     */
    private static String resolveUserIdForOrganizationSsoUser(AuthenticatedUser authenticatedUser) {

        String userName = MultitenantUtils.getTenantAwareUsername(authenticatedUser.getUserName());
        return UserCoreUtil.removeDomainFromName(userName);
    }

    private static Map<String, String> getUserClaimsInLocalDialect(String username, UserRealm realm,
                                                                   List<String> claimURIList)
            throws UserStoreException {

        return realm.getUserStoreManager().getUserClaimValues(MultitenantUtils.getTenantAwareUsername(username),
                claimURIList.toArray(new String[0]), null);
    }

    /**
     * Get app associated roles of the user.
     *
     * @param authenticatedUser Authenticated user.
     * @param applicationId     Application id.
     * @return App associated roles of the user.
     * @throws ApplicationRolesException If an error occurred while getting app associated roles.
     */
    private static String[] getAppAssociatedRolesOfUser(AuthenticatedUser authenticatedUser, String applicationId)
            throws ApplicationRolesException {

        ApplicationRolesResolver appRolesResolver =
                OpenIDConnectServiceComponentHolder.getInstance().getHighestPriorityApplicationRolesResolver();
        if (appRolesResolver == null) {
            log.debug("No application roles resolver found. So not adding application roles claim to the id_token.");
            return new String[0];
        }
        return appRolesResolver.getRoles(authenticatedUser, applicationId);
    }

    /**
     * Set the roles claim for local user.
     *
     * @param userClaims         User claims in local dialect.
     * @param appAssociatedRoles App associated roles of the user.
     */
    private static void setRoleClaimInLocalDialect(Map<String, String> userClaims, String[] appAssociatedRoles) {

        String rolesClaimURI = IdentityUtil.getLocalGroupsClaimURI();
        if (ArrayUtils.isNotEmpty(appAssociatedRoles)) {
            userClaims.put(rolesClaimURI,
                    String.join(FrameworkUtils.getMultiAttributeSeparator(), appAssociatedRoles));
        }
    }

    /**
     * Set the application roles claim for local user.
     *
     * @param userClaims         User claims in local dialect.
     * @param appAssociatedRoles App associated roles of the user.
     */
    private static void setAppRoleClaimInLocalDialect(Map<String, String> userClaims, String[] appAssociatedRoles) {

        if (ArrayUtils.isNotEmpty(appAssociatedRoles)) {
            userClaims.put(APP_ROLES_CLAIM,
                    String.join(FrameworkUtils.getMultiAttributeSeparator(), appAssociatedRoles));
        }
    }

    private static boolean isSharedUserAccessingSharedOrg(AuthenticatedUser authenticatedUser) {

        return StringUtils.isNotEmpty(authenticatedUser.getUserSharedOrganizationId()) &&
                StringUtils.isNotEmpty(authenticatedUser.getAccessingOrganization()) &&
                StringUtils.equals(authenticatedUser.getUserSharedOrganizationId(),
                        authenticatedUser.getAccessingOrganization());
    }

    private static void addSharedUserGroupsFromSharedOrganization(AuthenticatedUser authenticatedUser,
                                                           Map<String, String> userClaims) throws
            OrganizationManagementException, UserStoreException, IdentityException {

        String userAccessingTenantDomain;
        List<String> requestedClaimForSharedUser = new ArrayList<>();
        requestedClaimForSharedUser.add(GROUPS_CLAIM);
        // Getting the accessing tenant domain to get the userstore manager of the shared organization.
        userAccessingTenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                .resolveTenantDomain(authenticatedUser.getAccessingOrganization());
        AbstractUserStoreManager userStoreManager =
                (AbstractUserStoreManager) OAuthComponentServiceHolder.getInstance().getRealmService()
                        .getTenantUserRealm(IdentityTenantUtil.getTenantId(userAccessingTenantDomain))
                        .getUserStoreManager();
        String fullQualifiedSharedUsername = userStoreManager.getUser(authenticatedUser.getSharedUserId(), null)
                .getFullQualifiedUsername();
        UserRealm sharedUserRealm = IdentityTenantUtil.getRealm(userAccessingTenantDomain,
                fullQualifiedSharedUsername);
        // Getting the shared user's group claim from the shared organization.
        Map<String, String> sharedUserGroupClaim = getUserClaimsInLocalDialect(fullQualifiedSharedUsername,
                sharedUserRealm, requestedClaimForSharedUser);
        userClaims.put(GROUPS_CLAIM, sharedUserGroupClaim.get(GROUPS_CLAIM));
    }

    private static void handleServiceProviderRoleMappings(ServiceProvider serviceProvider, String claimSeparator,
                                                   Map<String, String> userClaims) throws FrameworkException {
        for (String roleGroupClaimURI : IdentityUtil.getRoleGroupClaims()) {
            handleSPRoleMapping(serviceProvider, claimSeparator, userClaims, roleGroupClaimURI);
        }
    }

    private static void handleSPRoleMapping(ServiceProvider serviceProvider, String claimSeparator, Map<String, String>
            userClaims, String roleGroupClaimURI) throws FrameworkException {

        if (MapUtils.isNotEmpty(userClaims) && userClaims.containsKey(roleGroupClaimURI)) {
            String roleClaim = userClaims.get(roleGroupClaimURI);
            if (StringUtils.isNotBlank(roleClaim)) {
                List<String> rolesList = Arrays.asList(roleClaim.split(Pattern.quote(claimSeparator)));
                String spMappedRoleClaim =
                        OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
                userClaims.put(roleGroupClaimURI, spMappedRoleClaim);
            }
        }
    }


    private static Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain,
                                                           Map<String, String> userClaims)
            throws ClaimMetadataException {

        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        // Get user claims in OIDC dialect.
        return getUserClaimsInOidcDialect(oidcToLocalClaimMappings, userClaims);
    }

    /**
     * Get user claims in OIDC claim dialect.
     *
     * @param oidcToLocalClaimMappings OIDC dialect to Local dialect claim mappings
     * @param userClaims               User claims in local dialect
     * @return Map of user claim values in OIDC dialect.
     */
    private static Map<String, Object> getUserClaimsInOidcDialect(Map<String, String> oidcToLocalClaimMappings,
                                                           Map<String, String> userClaims) {

        Map<String, Object> userClaimsInOidcDialect = new HashMap<>();
        if (MapUtils.isNotEmpty(userClaims)) {
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
     * This method retrieves the user attributes cached against the access token or the authorization code.
     * Currently, this is supported for the code grant and the refresh grant.
     *
     * @param requestMsgCtx The context of the OAuth token request containing necessary properties.
     * @return A map of cached user attributes against the code or the access token.
     * @throws OAuthSystemException    If there is an error while generating the access token hash.
     * @throws IdentityOAuth2Exception If an error occurs while selecting the OAuth2 token issuer.
     */
    public static Map<ClaimMapping, String> getCachedUserAttributes(OAuthTokenReqMessageContext requestMsgCtx)
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
     * Get user attributes cached against the authorization code.
     *
     * @param authorizationCode Authorization Code.
     * @return User attributes.
     */
    private static Map<ClaimMapping, String> getUserAttributesCachedAgainstAuthorizationCode(String authorizationCode) {

        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (authorizationCode != null) {
            // Get the cached user claims against the authorization code if any.
            userAttributes = getUserAttributesFromCacheUsingCode(authorizationCode);
        }
        return userAttributes;
    }

    /**
     * Get user attributes cached against the authorization code.
     *
     * @param authorizationCode Authorization Code.
     * @return User attributes cached against the authorization code.
     */
    private static Map<ClaimMapping, String> getUserAttributesFromCacheUsingCode(String authorizationCode) {

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
     * Get user attributes cached against the token.
     *
     * @param accessToken Access Token.
     * @return User attributes.
     */
    public static Map<ClaimMapping, String> getUserAttributesCachedAgainstToken(String accessToken) {

        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (accessToken != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(accessToken);
        }
        return userAttributes;
    }

    /**
     * Get user attributes cached against the access token.
     *
     * @param accessToken Access Token.
     * @return User attributes.
     */
    private static Map<ClaimMapping, String> getUserAttributesFromCacheUsingToken(String accessToken) {
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
     * Get user attributes cached against the device code
     *
     * @param deviceCode Device code
     * @return User attributes
     */
    private static Map<ClaimMapping, String> getUserAttributesCachedAgainstDeviceCode(String deviceCode) {

        if (StringUtils.isEmpty(deviceCode)) {
            return Collections.emptyMap();
        }
        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                DeviceAuthorizationGrantCache.getInstance().getValueFromCache(cacheKey);
        return cacheEntry == null ? Collections.emptyMap() : cacheEntry.getUserAttributes();
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
    private static String getLatestAccessTokenHash(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
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

    /**
     * To check whether a token has custom user claims.
     *
     * @param refreshTokenValidationDataDO RefreshTokenValidationDataDO.
     * @return true if the token user attributes has non OIDC claims.
     */
    private static boolean isTokenHasCustomUserClaims(RefreshTokenValidationDataDO refreshTokenValidationDataDO) {

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
     * Get oidc claims mapping.
     *
     * @param userAttributes    User attributes.
     * @param requestMsgCtx     Request Context.
     * @return User attributes Map.
     */
    public static Map<String, Object> getOIDCClaimsFromUserAttributes(Map<ClaimMapping, String> userAttributes,
                                                                OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
        Map<String, String> claims = new HashMap<>();
        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue().toString());
            }
        }
        return OIDCClaimUtil.getMergedUserClaimsInOIDCDialect(spTenantDomain, claims);
    }

    /**
     * Check whether an organization SSO user is trying to switch the organization.
     *
     * @param authorizedUser authorized user from the token request.
     * @return true if an organization SSO user is trying to switch the organization.
     */
    public static boolean isOrganizationSsoUserSwitchingOrganization(AuthenticatedUser authorizedUser) {

        String accessingOrganization = authorizedUser.getAccessingOrganization();
        String userResidentOrganization = authorizedUser.getUserResidentOrganization();
        /* A federated user with resident organization is considered as an organization SSO user. When the accessing
           organization is different to the resident organization, it means the user is trying to switch the
           organization. */
        return authorizedUser.isFederatedUser() && userResidentOrganization != null && !userResidentOrganization.equals
                (accessingOrganization);
    }

    /**
     * Check organization grant type.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return true if the grant type is organization switch.
     */
    public static boolean isOrganizationSwitchGrantType(OAuthTokenReqMessageContext requestMsgCtx) {

        return StringUtils.equals(requestMsgCtx.getOauth2AccessTokenReqDTO().getGrantType(),
                OAuthConstants.GrantTypes.ORGANIZATION_SWITCH);
    }

    /**
     * Get authorization code.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return Authorization Code.
     */
    private static String getAuthorizationCode(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(AUTHZ_CODE);
    }

    /**
     * Get access token.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return Access Token.
     */
    public static String getAccessToken(OAuthAuthzReqMessageContext authzReqMessageContext) {

        return (String) authzReqMessageContext.getProperty(ACCESS_TOKEN);
    }

    /**
     * Get access token.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return Access Token.
     */
    private static String getAccessToken(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(ACCESS_TOKEN);
    }

    /**
     * Get device code.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return Device Code.
     */
    private static String getDeviceCode(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(DEVICE_CODE);
    }

    /**
     * Check whether the user is a local user.
     *
     * @param authenticatedUser Authenticated User.
     * @return true if the user is a local user.
     */
    public static boolean isLocalUser(AuthenticatedUser authenticatedUser) {

        return !authenticatedUser.isFederatedUser();
    }

    /**
     * Check whether the user is a local user.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return true if the user is a local user.
     */
    public static boolean isLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return !authzReqMessageContext.getAuthorizationReqDTO().getUser().isFederatedUser();
    }

    /**
     * Get claims map.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    public static Map<String, Object> getOIDCClaimMapFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<>();
        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    /**
     * Retrieve the claim set of the AuthenticatedUser from the OAuthAuthzReqMessageContext.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return Map of user attributes.
     */
    public static Map<String, Object> retrieveClaimsForFederatedUser(OAuthAuthzReqMessageContext
                                                                             authzReqMessageContext) {

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

    /**
     * Check preserver claim uris in assertion.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return true if the claim uris should be preserved in the assertion.
     */
    public static boolean isPreserverClaimUrisInAssertion(OAuthTokenReqMessageContext requestMsgCtx) {

        return !OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect() &&
                requestMsgCtx.getAuthorizedUser().isFederatedUser();
    }

    /**
     * Get the tenant domain of the service provider.
     *
     * @param requestMsgCtx OAuthTokenReqMessageContext.
     * @return Tenant domain of the service provider.
     */
    public static String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    /**
     * Get the tenant domain of the service provider.
     *
     * @param requestMsgCtx OAuthAuthzReqMessageContext.
     * @return Tenant domain of the service provider.
     */
    public static String getServiceProviderTenantDomain(OAuthAuthzReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    /**
     * Get service provider.
     *
     * @param spTenantDomain Tenant domain of the service provider.
     * @param clientId       Client Id.
     * @return Service Provider.
     * @throws IdentityApplicationManagementException If an error occurred while getting the service provider.
     */
    public static ServiceProvider getServiceProvider(String spTenantDomain,
                                                     String clientId) throws IdentityApplicationManagementException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, OAUTH2, spTenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving service provider for clientId: " + clientId + " in tenantDomain: " + spTenantDomain);
        }
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }

    /**
     * Set user claims in OIDC dialect to the JWTClaimSet. Additionally we process multi values attributes here.
     *
     * @param jwtClaimsSetBuilder     JWTClaimsSet.Builder
     * @param userClaimsInOIDCDialect User claims in OIDC dialect.
     */
    public static JWTClaimsSet setClaimsToJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder, Map<String, Object>
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
    private static boolean isMultiValuedAttribute(String claimKey, String claimValue, String multiAttributeSeparator) {

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
}
