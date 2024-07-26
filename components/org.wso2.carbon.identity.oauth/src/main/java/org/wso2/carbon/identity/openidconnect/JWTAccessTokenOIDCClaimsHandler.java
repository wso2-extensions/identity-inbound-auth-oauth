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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.APP_ROLES_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.GROUPS_CLAIM;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;

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

        String clientId = request.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = getServiceProviderTenantDomain(request);
        AuthenticatedUser authenticatedUser = request.getAuthorizedUser();

        Map<String, Object> claims = getJWTAccessTokenUserClaims(authenticatedUser, clientId, spTenantDomain);
        if (claims == null || claims.isEmpty()) {
            return builder.build();
        }
        handleClaimsFormat(claims, spTenantDomain);
        return setClaimsToJwtClaimSet(builder, claims);
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        return builder.build();
    }

    private Map<String, Object> getJWTAccessTokenUserClaims(AuthenticatedUser authenticatedUser, String clientId,
                                                           String spTenantDomain)
            throws IdentityOAuth2Exception {

        // Get allowed JWT access token claims.
        List<String> allowedClaims = getJWTAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }

        // Get OIDC to Local claim mappings.
        Map<String, String> oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(spTenantDomain);
        if (oidcToLocalClaimMappings.isEmpty()) {
            return new HashMap<>();
        }
        List<String> localClaimURIs = allowedClaims.stream().map(oidcToLocalClaimMappings::get).filter(Objects::nonNull)
                .collect(Collectors.toList());
        try {
            return getUserClaimsFromUserStore(authenticatedUser, clientId, spTenantDomain, localClaimURIs);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException |
                 OrganizationManagementException e) {
            if (FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()) {
                log.error("Error occurred while getting claims for user: " + authenticatedUser +
                        " from userstore.", e);
            } else {
                throw new IdentityOAuth2Exception("Error occurred while getting claims for user: " +
                        authenticatedUser + " from userstore.", e);
            }
        }
        return null;
    }

    /**
     * This method retrieves user claims from the user store.
     *
     * @param authenticatedUser Authenticated user.
     * @param clientId Client Id.
     * @param spTenantDomain SP tenant domain.
     * @param claimURIList List of claim URIs.
     * @return Map of user claims.
     */
    private Map<String, Object> getUserClaimsFromUserStore(AuthenticatedUser authenticatedUser, String clientId,
                                                           String spTenantDomain, List<String> claimURIList)
            throws IdentityApplicationManagementException, UserStoreException, OrganizationManagementException,
            IdentityException {

        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();
        ServiceProvider serviceProvider = getServiceProvider(spTenantDomain, clientId);
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
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) OAuthComponentServiceHolder
                    .getInstance().getRealmService().getTenantUserRealm(IdentityTenantUtil
                            .getTenantId(userResidentTenantDomain)).getUserStoreManager();
            userTenantDomain = userResidentTenantDomain;
            fullQualifiedUsername = userStoreManager.getUser(userId, null).getFullQualifiedUsername();
        }

        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, fullQualifiedUsername);
        if (realm == null) {
            return new HashMap<>();
        }
        boolean isRoleClaimExists = false;
        String rolesClaimURI = IdentityUtil.getLocalGroupsClaimURI();
        if (claimURIList.contains(rolesClaimURI)) {
            claimURIList.remove(rolesClaimURI);
            isRoleClaimExists = true;
        }
        boolean isAppRoleClaimExists = false;
        if (claimURIList.contains(APP_ROLES_CLAIM)) {
            claimURIList.remove(APP_ROLES_CLAIM);
            isAppRoleClaimExists = true;
        }
        Map<String, String> userClaims = getUserClaimsInLocalDialect(fullQualifiedUsername, realm, claimURIList);
        if (isRoleClaimExists || isAppRoleClaimExists) {
            String[] userRoles = getUserRoles(authenticatedUser, clientId);
            if (ArrayUtils.isNotEmpty(userRoles)) {
                if (isRoleClaimExists) {
                    userClaims.put(rolesClaimURI, String.join(FrameworkUtils.getMultiAttributeSeparator(), userRoles));
                }
                if (isAppRoleClaimExists) {
                    userClaims.put(APP_ROLES_CLAIM, String.join(FrameworkUtils.getMultiAttributeSeparator(),
                            userRoles));
                }
            }
        }
        if (claimURIList.contains(GROUPS_CLAIM) && isSharedUserAccessingSharedOrg(authenticatedUser) &&
                StringUtils.isNotEmpty(authenticatedUser.getSharedUserId())) {
            addSharedUserGroupsFromSharedOrganization(authenticatedUser, userClaims);
        }
        if (isEmpty(userClaims)) {
            // User claims can be empty if user does not exist in user stores. Probably a federated user.
            return userClaimsMappedToOIDCDialect;
        } else {
            // Map the local roles to SP defined roles.
            handleServiceProviderRoleMappings(serviceProvider, FrameworkUtils.getMultiAttributeSeparator(),
                    userClaims);

            // Get the user claims in oidc dialect to be returned in the id_token.
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOidcDialect(spTenantDomain, userClaims);
            userClaimsMappedToOIDCDialect.putAll(userClaimsInOIDCDialect);
        }
        return userClaimsMappedToOIDCDialect;
    }

    private Map<String, Object> getUserClaimsInOidcDialect(String spTenantDomain, Map<String, String> userClaims)
            throws IdentityOAuth2Exception {

        Map<String, String> oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(spTenantDomain);
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

    private Map<String, String> getUserClaimsInLocalDialect(String username, UserRealm realm, List<String> claimURIList)
            throws UserStoreException {

        return realm.getUserStoreManager().getUserClaimValues(MultitenantUtils.getTenantAwareUsername(username),
                claimURIList.toArray(new String[0]), null);
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
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, tenantDomain, false);
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
     * Get user roles.
     *
     * @param authenticatedUser Authenticated user.
     * @param clientId Client Id.
     * @return Array of user roles.
     */
    private String[] getUserRoles(AuthenticatedUser authenticatedUser, String clientId)
            throws IdentityOAuth2Exception {

        String applicationId = getApplicationId(clientId, authenticatedUser.getTenantDomain());
        List<String> userRoleIds = AuthzUtil.getUserRoles(authenticatedUser, applicationId);
        List<RoleV2> rolesAssociatedWithApp = getRolesAssociatedWithApplication(applicationId,
                authenticatedUser.getTenantDomain());
        return rolesAssociatedWithApp.stream().filter(role -> userRoleIds.contains(role.getId())).map(RoleV2::getName)
                .map(this::appendInternalDomain).toArray(String[]::new);
    }

    /**
     * Get roles associated with the application.
     *
     * @param applicationId Application Id.
     * @param tenantDomain Tenant Domain.
     * @return List of roles associated with the application.
     */
    private List<RoleV2> getRolesAssociatedWithApplication(String applicationId, String tenantDomain)
            throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            return applicationMgtService.getAssociatedRolesOfApplication(applicationId, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while getting roles associated with application : " + applicationId
                    + " tenant : " +  tenantDomain);
        }
    }

    /**
     * Get JWT access token claims.
     *
     * @param clientId Client Id.
     * @param tenantDomain Tenant Domain.
     * @return List of JWT access token claims.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    private List<String> getJWTAccessTokenClaims(String clientId, String tenantDomain) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
            String[] claimsArray = oAuthAppDO.getJwtAccessTokenClaims();
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
    private void handleClaimsFormat(Map<String, Object> userClaims, String tenantDomain) {

        OpenIDConnectServiceComponentHolder.getInstance().getHighestPriorityOpenIDConnectClaimFilter()
                .handleClaimsFormatting(userClaims, tenantDomain);
    }

    /**
     * Get application Id.
     *
     * @param clientId     Client Id.
     * @param tenantDomain Tenant Domain.
     * @return Application Id.
     */
    private String getApplicationId(String clientId, String tenantDomain) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String applicationId;
        try {
            applicationId = applicationMgtService.getApplicationResourceIDByInboundKey(clientId, OAUTH2, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while getting application id for client id : " + clientId
                    + " tenant : " +  tenantDomain);
        }
        return applicationId;
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
     * Add shared user groups from shared organization.
     *
     * @param authenticatedUser Authenticated user.
     * @param userClaims User claims.
     */
    private void addSharedUserGroupsFromSharedOrganization(AuthenticatedUser authenticatedUser,
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

    /**
     * Handle service provider role mappings.
     *
     * @param serviceProvider Service Provider.
     * @param claimSeparator  Claim separator.
     * @param userClaims      User claims.
     * @throws FrameworkException FrameworkException.
     */
    private void handleServiceProviderRoleMappings(ServiceProvider serviceProvider, String claimSeparator,
                                                   Map<String, String> userClaims) throws FrameworkException {
        for (String roleGroupClaimURI : IdentityUtil.getRoleGroupClaims()) {
            handleSPRoleMapping(serviceProvider, claimSeparator, userClaims, roleGroupClaimURI);
        }
    }

    /**
     * Handle SP role mapping.
     *
     * @param serviceProvider   Service Provider
     * @param claimSeparator    Claim separator
     * @param userClaims        User claims
     * @param roleGroupClaimURI Role group claim URI
     * @throws FrameworkException FrameworkException
     */
    private void handleSPRoleMapping(ServiceProvider serviceProvider, String claimSeparator, Map<String, String>
            userClaims, String roleGroupClaimURI) throws FrameworkException {

        if (isNotEmpty(userClaims) && userClaims.containsKey(roleGroupClaimURI)) {
            String roleClaim = userClaims.get(roleGroupClaimURI);
            if (StringUtils.isNotBlank(roleClaim)) {
                List<String> rolesList = Arrays.asList(roleClaim.split(Pattern.quote(claimSeparator)));
                String spMappedRoleClaim =
                        OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
                userClaims.put(roleGroupClaimURI, spMappedRoleClaim);
            }
        }
    }

    /**
     * Append internal domain to the role name.
     *
     * @param roleName Role name.
     * @return Role name with internal domain.
     */
    private String appendInternalDomain(String roleName) {

        if (!roleName.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
            return UserCoreConstants.INTERNAL_DOMAIN + UserCoreConstants.DOMAIN_SEPARATOR + roleName;
        }
        return roleName;
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
     * Resolve user id for organization SSO user.
     *
     * @param authenticatedUser Authenticated user.
     * @return
     */
    private String resolveUserIdForOrganizationSsoUser(AuthenticatedUser authenticatedUser) {

        String userName = MultitenantUtils.getTenantAwareUsername(authenticatedUser.getUserName());
        return UserCoreUtil.removeDomainFromName(userName);
    }

    /**
     * Check whether the shared user is accessing the shared organization.
     *
     * @param authenticatedUser Authenticated user.
     * @return True if shared user is accessing the shared organization.
     */
    private boolean isSharedUserAccessingSharedOrg(AuthenticatedUser authenticatedUser) {

        return StringUtils.isNotEmpty(authenticatedUser.getUserSharedOrganizationId()) &&
                StringUtils.isNotEmpty(authenticatedUser.getAccessingOrganization()) &&
                StringUtils.equals(authenticatedUser.getUserSharedOrganizationId(),
                        authenticatedUser.getAccessingOrganization());
    }
}
