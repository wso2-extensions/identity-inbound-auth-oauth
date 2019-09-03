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
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
            boolean returnOnlyMappedLocalRoles = Boolean.parseBoolean(IdentityUtil.getProperty(SEND_ONLY_SP_MAPPED_ROLES));
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

        if (isConsentBasedClaimFilteringApplicable(grantType) && !FrameworkUtils.isConsentPageSkippedForSP(serviceProvider)) {
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

    private static boolean isConsentBasedClaimFilteringApplicable(String grantType) {

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
}
