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
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ROLES;

/**
 * A class that provides OIDC claims for JWT access tokens.
 */
public class JWTAccessTokenOIDCClaimsHandler implements CustomClaimsCallbackHandler {

    private static final String OAUTH2 = "oauth2";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        String clientId = request.getOauth2AccessTokenReqDTO().getClientId();
        String tenantDomain = request.getOauth2AccessTokenReqDTO().getTenantDomain();

        // Get allowed JWT access token claims.
        List<String> allowedClaims = OAuth2Util.getAllowedJWTAccessTokenClaims(clientId, tenantDomain);
        // Get OIDC to Local claim mappings.
        Map<String, String> oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(tenantDomain);

        Map<String, Object> claims = getUserClaimsFromUserStore(request.getAuthorizedUser()
                .getAuthenticatedSubjectIdentifier(), allowedClaims , oidcToLocalClaimMappings);
        // Resolve application roles if roles claim is allowed.
        if (allowedClaims.contains(ROLES)) {
            String[] userRoles = getUserRoles(request.getAuthorizedUser(), clientId);
            claims.put(ROLES, String.join(FrameworkUtils.getMultiAttributeSeparator(), userRoles));
        }
        return setClaimsToJwtClaimSet(builder, claims);
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        return null;
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
     * This method retrieves user claims from the user store.
     *
     * @param subjectIdentifier Subject identifier of the authenticated user.
     * @param allowedClaims List of allowed claims.
     * @param oidcToLocalClaimMappings OIDC to Local claim mappings.
     * @return Map of user claims in OIDC dialect.
     */
    private Map<String, Object> getUserClaimsFromUserStore(String subjectIdentifier, List<String> allowedClaims,
                                                           Map<String, String> oidcToLocalClaimMappings)
            throws IdentityOAuth2Exception {

        List<String> localClaimURIs = allowedClaims.stream().map(oidcToLocalClaimMappings::get).filter(Objects::nonNull)
                .collect(Collectors.toList());
        Map<String, String> localToOidcClaimMappings = oidcToLocalClaimMappings.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey, (v1, v2) -> v1, HashMap::new));

        try {
            Map<String, String> userClaims = getUserClaimsFromUserStore(subjectIdentifier, localClaimURIs);

            return userClaims.entrySet().stream().filter(entry -> localToOidcClaimMappings.containsKey(entry.getKey()))
                    .collect(Collectors.toMap(entry -> localToOidcClaimMappings.get(entry.getKey()),
                            Map.Entry::getValue));
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving user claims from user store.", e);
        }
    }

    /**
     * This method retrieves user claims from the user store.
     *
     * @param userId User Id of the authenticated user.
     * @param claimURIList List of claim URIs.
     * @return Map of user claims.
     */
    private static Map<String, String> getUserClaimsFromUserStore(String userId, List<String> claimURIList)
            throws UserStoreException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager)
                CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();
        if (userStoreManager == null) {
            throw new UserStoreException("Unable to retrieve UserStoreManager");
        }
        return userStoreManager.getUserClaimValuesWithID(userId, claimURIList.toArray(new String[0]), null);
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
     * Get application Id.
     *
     * @param clientId Client Id.
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
}
