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
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class ClaimUtil {
    static final String SP_DIALECT = "http://wso2.org/oidc/claim";
    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private static final Log log = LogFactory.getLog(ClaimUtil.class);

    private ClaimUtil() {

    }

    public static Map<String, Object> getClaimsFromUserStore(OAuth2TokenValidationResponseDTO tokenResponse) throws
            UserInfoEndpointException {
        String username = tokenResponse.getAuthorizedUser();
        String userTenantDomain = MultitenantUtils.getTenantDomain(tokenResponse.getAuthorizedUser());
        UserRealm realm;
        List<String> claimURIList = new ArrayList<>();
        Map<String, Object> mappedAppClaims = new HashMap<>();

        try {
            realm = IdentityTenantUtil.getRealm(userTenantDomain, username);

            if (realm == null) {
                log.warn("No valid tenant domain provider. Empty claim returned back");
                return new HashMap<>();
            }

            AccessTokenDO accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(tokenResponse
                    .getAuthorizationContextToken().getTokenString());

            // If the authenticated user is a federated user, no requirement to retrieve claims from local users tore.
            if (accessTokenDO != null) {
                AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
                if (StringUtils.isNotEmpty(authenticatedUser.getUserStoreDomain())) {
                    String userstoreDomain = authenticatedUser.getUserStoreDomain();
                    if (userstoreDomain.startsWith(OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX) ||
                            authenticatedUser.isFederatedUser()) {
                        return new HashMap<>();
                    }
                }
            }

            Map<String, String> spToLocalClaimMappings;
            UserStoreManager userstore = realm.getUserStoreManager();
            ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
            String clientId;
            if (accessTokenDO != null) {
                clientId = accessTokenDO.getConsumerKey();
            } else {
                // this means the token is not active so we can't proceed further
                throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN,
                        "Invalid Access Token. Access token is not ACTIVE.");
            }

            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            String spTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);

            String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, INBOUND_AUTH2_TYPE,
                    spTenantDomain);
            ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName,
                    spTenantDomain);
            if (serviceProvider == null) {
                return mappedAppClaims;
            }
            ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();
            String subjectClaimURI = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
            if (serviceProvider.getClaimConfig().getClaimMappings() != null) {
                for (ClaimMapping claimMapping : serviceProvider.getClaimConfig().getClaimMappings()) {
                    if (claimMapping.getRemoteClaim().getClaimUri().equals(subjectClaimURI)) {
                        subjectClaimURI = claimMapping.getLocalClaim().getClaimUri();
                        break;
                    }
                }
            }

            if (subjectClaimURI != null) {
                claimURIList.add(subjectClaimURI);
            }

            boolean isSubjectClaimInRequested = false;
            if (subjectClaimURI != null || requestedLocalClaimMap != null && requestedLocalClaimMap.length > 0) {
                for (ClaimMapping claimMapping : requestedLocalClaimMap) {
                    if (claimMapping.isRequested()) {
                        claimURIList.add(claimMapping.getLocalClaim().getClaimUri());
                        if (claimMapping.getLocalClaim().getClaimUri().equals(subjectClaimURI)) {
                            isSubjectClaimInRequested = true;
                        }
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("Requested number of local claims: " + claimURIList.size());
                }

                spToLocalClaimMappings = ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon
                        (SP_DIALECT, null, userTenantDomain, true);

                Map<String, String> userClaims = userstore.getUserClaimValues(MultitenantUtils.getTenantAwareUsername
                        (username), claimURIList.toArray(new    String[claimURIList.size()]), null);
                if (log.isDebugEnabled()) {
                    log.debug("User claims retrieved from user store: " + userClaims.size());
                }

                if (MapUtils.isEmpty(userClaims)) {
                    return new HashMap<>();
                }

                for (Map.Entry<String, String> entry : userClaims.entrySet()) {
                    //set local2sp role mappings
                    if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI.equals(entry.getKey())) {
                        String domain = IdentityUtil.extractDomainFromName(username);
                        RealmConfiguration realmConfiguration = realm.getUserStoreManager().getSecondaryUserStoreManager(domain)
                                .getRealmConfiguration();
                        String claimSeparator = realmConfiguration
                                .getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                        if (StringUtils.isBlank(claimSeparator)) {
                            claimSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
                        }

                        String roleClaim = entry.getValue();
                        List<String> rolesList = new LinkedList<>(Arrays.asList(roleClaim.split(claimSeparator)));
                        roleClaim = getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
                        entry.setValue(roleClaim);
                    }

                    String value = spToLocalClaimMappings.get(entry.getKey());
                    if (value != null) {
                        if (entry.getKey().equals(subjectClaimURI)) {
                            mappedAppClaims.put("sub", entry.getValue());
                            if (!isSubjectClaimInRequested) {
                                continue;
                            }
                        }
                        mappedAppClaims.put(value, entry.getValue());
                        if (log.isDebugEnabled() &&
                                IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                            log.debug("Mapped claim: key -  " + value + " value -" + entry.getValue());
                        }
                    }
                }
            }

        } catch (Exception e) {
            if (e instanceof UserStoreException){
                if (e.getMessage().contains("UserNotFound")) {
                    if (log.isDebugEnabled()) {
                        log.debug("User " + username + " not found in user store");
                    }
                }
            } else {
                log.error("Error while retrieving the claims from user store for " + username, e);
                throw new UserInfoEndpointException("Error while retrieving the claims from user store for " + username);
            }
        }
        return mappedAppClaims;
    }

    /**
     * @param serviceProvider
     * @param locallyMappedUserRoles
     */
    public static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
            List<String> locallyMappedUserRoles, String claimSeparator) throws FrameworkException {
        if (CollectionUtils.isNotEmpty(locallyMappedUserRoles)) {
            RoleMapping[] localToSpRoleMapping = serviceProvider.getPermissionAndRoleConfig().getRoleMappings();
            if (ArrayUtils.isEmpty(localToSpRoleMapping)) {
                return null;
            }

            StringBuilder spMappedUserRoles = new StringBuilder();
            for (RoleMapping roleMapping : localToSpRoleMapping) {
                if (locallyMappedUserRoles.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                    spMappedUserRoles.append(roleMapping.getRemoteRole()).append(claimSeparator);
                    locallyMappedUserRoles.remove(roleMapping.getLocalRole().getLocalRoleName());
                }
            }

            for (String remainingRole : locallyMappedUserRoles) {
                spMappedUserRoles.append(remainingRole).append(claimSeparator);
            }

            return spMappedUserRoles.length() > 0 ?
                    spMappedUserRoles.toString().substring(0, spMappedUserRoles.length() - 1) :
                    null;
        }

        return null;
    }
}