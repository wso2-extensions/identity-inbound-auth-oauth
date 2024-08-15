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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;

/**
 * A class that provides OIDC claims for JWT access tokens.
 */
public class JWTAccessTokenOIDCClaimsHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(JWTAccessTokenOIDCClaimsHandler.class);

    private static final String OAUTH2 = "oauth2";

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        String clientId = request.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = getServiceProviderTenantDomain(request);
        AuthenticatedUser authenticatedUser = request.getAuthorizedUser();

        Map<String, Object> claims = getAccessTokenUserClaims(authenticatedUser, clientId, spTenantDomain);
        if (claims == null || claims.isEmpty()) {
            return builder.build();
        }
        Map<String, Object> filteredClaims = handleClaimsFormat(claims, clientId, spTenantDomain);
        return setClaimsToJwtClaimSet(builder, filteredClaims);
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        // TODO : Implement this method for implicit flow and hybrid flow.
        return builder.build();
    }

    private Map<String, Object> getAccessTokenUserClaims(AuthenticatedUser authenticatedUser, String clientId,
                                                           String spTenantDomain)
            throws IdentityOAuth2Exception {

        // Get allowed access token claims.
        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
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
        if (serviceProvider == null) {
            log.warn("Unable to find a service provider associated with client_id: " + clientId + " in tenantDomain: " +
                    spTenantDomain + ". Returning empty claim map for user.");
            return userClaimsMappedToOIDCDialect;
        }
        return OIDCClaimUtil.getUserClaimsInOIDCDialect(serviceProvider, authenticatedUser, claimURIList);
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
                    .getMappingsMapFromOtherDialectToCarbon(OAuthConstants.OIDC_DIALECT, null,
                            tenantDomain, false);
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
     * Get access token claims.
     *
     * @param clientId Client Id.
     * @param tenantDomain Tenant Domain.
     * @return List of JWT access token claims.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    private List<String> getAccessTokenClaims(String clientId, String tenantDomain) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppDO;

        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
            String[] claimsArray = oAuthAppDO.getAccessTokenClaims();
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
    private Map<String, Object> handleClaimsFormat(Map<String, Object> userClaims, String clientId,
                                                   String tenantDomain) throws IdentityOAuth2Exception {

        List<String> registeredScopes = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO()
                .getScopeNames(IdentityTenantUtil.getTenantId(tenantDomain));
        return OpenIDConnectServiceComponentHolder.getInstance().getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, registeredScopes.toArray(new String[0]),
                        clientId, tenantDomain);
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
}
