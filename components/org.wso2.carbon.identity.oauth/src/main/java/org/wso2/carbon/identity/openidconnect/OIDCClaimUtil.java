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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.SubjectType;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.apache.commons.lang.ArrayUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.InternalRoleDomains.
        APPLICATION_DOMAIN;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.InternalRoleDomains.
        WORKFLOW_DOMAIN;

/**
 * Utility to handle OIDC Claim related functionality.
 */
public class OIDCClaimUtil {

    private static final Log log = LogFactory.getLog(OIDCClaimUtil.class);
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String SEND_ONLY_SP_MAPPED_ROLES = "SPRoleManagement.ReturnOnlyMappedLocalRoles";
    public static final String DEFAULT_SUBJECT_TYPE = "OAuth.OpenIDConnect.DefaultSubjectType";

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

    private static SubjectType getSubjectType(OAuthAppDO authAppDO) {

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
}
