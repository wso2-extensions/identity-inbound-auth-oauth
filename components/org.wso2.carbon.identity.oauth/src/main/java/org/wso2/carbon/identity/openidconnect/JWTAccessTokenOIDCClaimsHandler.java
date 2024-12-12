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
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
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
import java.util.stream.Collectors;

import static org.apache.commons.collections.MapUtils.isEmpty;

/**
 * A class that provides OIDC claims for JWT access tokens.
 */
public class JWTAccessTokenOIDCClaimsHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(JWTAccessTokenOIDCClaimsHandler.class);

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        Map<String, Object> claims;
        try {
            claims = getUserClaimsInOIDCDialect(request);
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception("Error occurred while getting user claims for the access token.", e);
        }
        return OIDCClaimUtil.setClaimsToJwtClaimSet(builder, claims);
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        /*
          Handling the user attributes for the access token. There is no requirement of the consent
          to manage user attributes for the access token.
         */
        Map<String, Object> claims = getUserClaimsInOIDCDialect(request);
        return OIDCClaimUtil.setClaimsToJwtClaimSet(builder, claims);
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
            return filterClaims(userClaimsInOIDCDialect, requestMsgCtx);
        }
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

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
        return filterClaims(userClaimsInOIDCDialect, authzReqMessageContext);
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

    private Map<String, Object> filterClaims(Map<String, Object> userClaimsInOIDCDialect,
                                             OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        String spTenantDomain = OIDCClaimUtil.getServiceProviderTenantDomain(authzReqMessageContext);
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        // Get allowed access token claims.
        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, Object> claims = allowedClaims.stream()
                .filter(userClaimsInOIDCDialect::containsKey)
                .collect(Collectors.toMap(claim -> claim, userClaimsInOIDCDialect::get));
        return handleClaimsFormat(claims, clientId, spTenantDomain);
    }

    private Map<String, Object> filterClaims(Map<String, Object> userClaimsInOIDCDialect,
                                             OAuthTokenReqMessageContext requestMsgCtx) throws IdentityOAuth2Exception {

        String spTenantDomain = OIDCClaimUtil.getServiceProviderTenantDomain(requestMsgCtx);
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        // Get allowed access token claims.
        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, Object> claims = allowedClaims.stream()
                .filter(userClaimsInOIDCDialect::containsKey)
                .collect(Collectors.toMap(claim -> claim, userClaimsInOIDCDialect::get));
        return handleClaimsFormat(claims, clientId, spTenantDomain);
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
        List<String> allowedClaims = getAccessTokenClaims(clientId, spTenantDomain);
        if (allowedClaims.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, String> oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(spTenantDomain);
        if (oidcToLocalClaimMappings.isEmpty()) {
            return new HashMap<>();
        }
        List<String> localClaimURIs = allowedClaims.stream().map(oidcToLocalClaimMappings::get).filter(Objects::nonNull)
                .collect(Collectors.toList());
        return OIDCClaimUtil.getUserClaimsInOIDCDialect(serviceProvider, authenticatedUser, localClaimURIs);
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
}
