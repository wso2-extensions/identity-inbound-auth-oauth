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

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.ApplicationRolesResolver;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.exception.ApplicationRolesException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
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
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.APP_ROLES_CLAIM;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_CODE;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.ID_TOKEN_USER_CLAIMS_PROP_KEY;

/**
 * Default implementation of {@link CustomClaimsCallbackHandler}. This callback handler populates available user
 * claims after filtering them through requested scopes using {@link OpenIDConnectClaimFilter}.
 */
public class DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandler.class);
    private static final String OAUTH2 = "oauth2";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String CNF_CLAIM = "cnf";
    private static final String CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND";
    private static final String JAVAX_SERVLET_REQUEST_CERTIFICATE = "javax.servlet.request.X509Certificate";

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthTokenReqMessageContext
            tokenReqMessageContext) throws IdentityOAuth2Exception {
        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(tokenReqMessageContext);
            tokenReqMessageContext.addProperty(ID_TOKEN_USER_CLAIMS_PROP_KEY, userClaimsInOIDCDialect.keySet());
            String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
            try {
                if (OAuth2Util.isFapiConformantApp(clientId) ||
                        isTlsClientCertificateBoundAccessTokensEnabled(clientId)) {
                    addCnfClaimToOIDCDialect(tokenReqMessageContext, userClaimsInOIDCDialect);
                }
            } catch (IdentityOAuth2ClientException e) {
                throw new IdentityOAuth2Exception("Could not find an existing app for clientId: " + clientId, e);
            } catch (IdentityOAuth2Exception e) {
                throw new IdentityOAuth2Exception("Error while obtaining the service provider for client_id: " +
                        clientId, e);
            }
            return setClaimsToJwtClaimSet(jwtClaimsSetBuilder, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while adding claims of user: " + tokenReqMessageContext.getAuthorizedUser() +
                        " to the JWTClaimSet used to build the id_token.", e);
            }
        }
        return null;
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSet,
                                           OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(authzReqMessageContext);
            return setClaimsToJwtClaimSet(jwtClaimsSet, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " +
                    authzReqMessageContext.getAuthorizationReqDTO().getUser() + " to the JWTClaimSet used to " +
                    "build the id_token.", e);
        }
        return null;
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
                .getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, serviceProviderTenantDomain);
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
        Map<ClaimMapping, String> userAttributes = getCachedUserAttributes(requestMsgCtx);
        if (isEmpty(userAttributes) && isLocalUser(requestMsgCtx.getAuthorizedUser())) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache against the access token or authorization code. " +
                        "Retrieving claims for local user: " + requestMsgCtx.getAuthorizedUser() + " from userstore.");
            }
            // Get claim in oidc dialect from user store.
            userClaimsInOIDCDialect = retrieveClaimsForLocalUser(requestMsgCtx);
        } else {
            // Get claim map from the cached attributes
            userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
        }

        Object hasNonOIDCClaimsProperty = requestMsgCtx.getProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS);
        if (isPreserverClaimUrisInAssertion(requestMsgCtx) || (hasNonOIDCClaimsProperty != null
                && (Boolean) hasNonOIDCClaimsProperty)) {
            return userClaimsInOIDCDialect;
        } else {
            return filterOIDCClaims(requestMsgCtx, userClaimsInOIDCDialect);
        }
    }

    private Map<String, Object> filterOIDCClaims(OAuthTokenReqMessageContext requestMsgCtx,
                                                 Map<String, Object> userClaimsInOIDCDialect)
            throws OAuthSystemException {

        AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        String[] approvedScopes = requestMsgCtx.getScope();
        String token = getAccessToken(requestMsgCtx);
        String authorizationCode = getAuthorizationCode(requestMsgCtx);
        String grantType = requestMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();
        // Get the flag which has the record whether the token is a consented one or not.
        boolean isConsentedToken = false;
        if (requestMsgCtx.isConsentedToken()) {
            isConsentedToken = requestMsgCtx.isConsentedToken();
        }

        return filterOIDCClaims(token, authorizationCode, grantType, userClaimsInOIDCDialect, user,
                approvedScopes, clientId, spTenantDomain, isConsentedToken);
    }


    private Map<String, Object> filterOIDCClaims(String accessToken,
                                                 String authorizationCode,
                                                 String grantType,
                                                 Map<String, Object> userClaimsInOIDCDialect,
                                                 AuthenticatedUser authenticatedUser,
                                                 String[] approvedScopes,
                                                 String clientId,
                                                 String spTenantDomain,
                                                 boolean isConsentedToken) throws OAuthSystemException {
        Map<String, Object> filteredUserClaimsByOIDCScopes =
                filterClaimsByScope(userClaimsInOIDCDialect, approvedScopes, clientId, spTenantDomain);

        // TODO: Get claims filtered by essential claims and add to returning claims
        // https://github.com/wso2/product-is/issues/2680

        if (accessToken != null) {
            if (StringUtils.isNotBlank(authorizationCode)) {
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
                AuthorizationGrantCacheEntry cacheEntry =
                        AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
                if (cacheEntry != null && cacheEntry.isRequestObjectFlow()) {
                    // Handle essential claims of the request object
                    Map<String, Object> claimsFromRequestObject =
                            filterClaimsFromRequestObject(userClaimsInOIDCDialect, accessToken);
                    filteredUserClaimsByOIDCScopes.putAll(claimsFromRequestObject);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("The request does not contains request object. So skipping " +
                                "filterClaimsFromRequestObject");
                    }
                }
            }
        }

        // Restrict the claims based on user consent given
        return getUserConsentedClaims(filteredUserClaimsByOIDCScopes, authenticatedUser, grantType, clientId,
                spTenantDomain, isConsentedToken);
    }

    private boolean isPreserverClaimUrisInAssertion(OAuthTokenReqMessageContext requestMsgCtx) {

        return !OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect() &&
                requestMsgCtx.getAuthorizedUser().isFederatedUser();
    }

    private Map<String, Object> filterClaimsFromRequestObject(Map<String, Object> userAttributes,
                                                              String token) throws OAuthSystemException {

        try {
            List<RequestedClaim> requestedClaims = OpenIDConnectServiceComponentHolder.getRequestObjectService().
                    getRequestedClaimsForIDToken(token);
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByEssentialClaims(userAttributes, requestedClaims);
        } catch (RequestObjectException e) {
            throw new OAuthSystemException("Unable to retrieve requested claims from Request Object." + e);
        }
    }

    private Map<String, Object> getUserConsentedClaims(Map<String, Object> userClaims,
                                                       AuthenticatedUser authenticatedUser,
                                                       String grantType,
                                                       String clientId,
                                                       String spTenantDomain,
                                                       boolean isConsentedToken) throws OAuthSystemException {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = getServiceProvider(spTenantDomain, clientId);
        } catch (IdentityApplicationManagementException e) {
            throw new OAuthSystemException(
                    "Error while obtaining service provider for tenant domain: " + spTenantDomain + " client id: "
                            + clientId, e);
        }

        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, authenticatedUser, clientId,
                spTenantDomain, grantType, serviceProvider, isConsentedToken);
    }

    private Map<ClaimMapping, String> getCachedUserAttributes(OAuthTokenReqMessageContext requestMsgCtx) {

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
            if (log.isDebugEnabled()) {
                log.debug("Retrieving claims cached against authorization_code for user: " +
                        requestMsgCtx.getAuthorizedUser());
            }
        }
        // Check for claims cached against the device code.
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the authorization_code for user: " +
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
            Object previousAccessTokenObject = requestMsgCtx.getProperty(RefreshGrantHandler.PREV_ACCESS_TOKEN);

            if (previousAccessTokenObject != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieving claims from previous access token of user : " + requestMsgCtx
                            .getAuthorizedUser());
                }
                RefreshTokenValidationDataDO refreshTokenValidationDataDO =
                        (RefreshTokenValidationDataDO) previousAccessTokenObject;
                userAttributes = getUserAttributesCachedAgainstToken(refreshTokenValidationDataDO.getAccessToken());
                requestMsgCtx.addProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS,
                        isTokenHasCustomUserClaims(refreshTokenValidationDataDO));
            }
        }
        return userAttributes;
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
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

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstDeviceCode(String deviceCode) {

        if (StringUtils.isEmpty(deviceCode)) {
            return Collections.emptyMap();
        }
        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                DeviceAuthorizationGrantCache.getInstance().getValueFromCache(cacheKey);
        return cacheEntry == null ? Collections.emptyMap() : cacheEntry.getUserAttributes();
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws OAuthSystemException, IdentityOAuth2Exception {

        Map<String, Object> userClaimsInOIDCDialect;
        Map<ClaimMapping, String> userAttributes =
                getUserAttributesCachedAgainstToken(getAccessToken(authzReqMessageContext));

        if (isEmpty(userAttributes)) {
            if (isLocalUser(authzReqMessageContext)) {
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
                    userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute for federated " +
                            "user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                userClaimsInOIDCDialect = retrieveClaimsForFederatedUser(authzReqMessageContext);
            }
        } else {
            userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
        }

        return filterOIDCClaims(authzReqMessageContext, userClaimsInOIDCDialect);
    }

    /**
     * Retrieve the claim set of the AuthenticatedUser from the OAuthAuthzReqMessageContext.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return Map of user attributes.
     */
    private Map<String, Object> retrieveClaimsForFederatedUser(OAuthAuthzReqMessageContext authzReqMessageContext) {

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

    private Map<String, Object> filterOIDCClaims(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                 Map<String, Object> userClaimsInOIDCDialect)
            throws OAuthSystemException {

        AuthenticatedUser user = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String[] approvedScopes = authzReqMessageContext.getApprovedScope();
        String accessToken = getAccessToken(authzReqMessageContext);
        String grantType = OAuthConstants.GrantTypes.IMPLICIT;
        boolean isConsentedGrant = OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(grantType);
        return filterOIDCClaims(accessToken, StringUtils.EMPTY, grantType, userClaimsInOIDCDialect, user,
                approvedScopes, clientId, spTenantDomain, isConsentedGrant);
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(authzReqMessageContext);
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

    /**
     * Get claims map.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private Map<String, Object> getOIDCClaimMapFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<>();
        if (isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain,
                                                           String clientId,
                                                           AuthenticatedUser authenticatedUser)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException,
            OrganizationManagementException {

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
        String userTenantDomain;
        String fullQualifiedUsername;
        if (StringUtils.isNotBlank(authenticatedUser.getUserId())) {
            String userId = authenticatedUser.getUserId();
            userTenantDomain = authenticatedUser.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(userTenantDomain);
            Tenant tenant =
                    OAuthComponentServiceHolder.getInstance().getRealmService().getTenantManager().getTenant(tenantId);
            if (tenant != null && StringUtils.isNotBlank(tenant.getAssociatedOrganizationUUID())) {
                Optional<User> user = OAuth2ServiceComponentHolder.getOrganizationUserResidentResolverService()
                        .resolveUserFromResidentOrganization(null, userId, tenant.getAssociatedOrganizationUUID());
                if (!user.isPresent()) {
                    return userClaimsMappedToOIDCDialect;
                }
                userTenantDomain = user.get().getTenantDomain();
                fullQualifiedUsername = user.get().getFullQualifiedUsername();
            } else {
                userTenantDomain = authenticatedUser.getTenantDomain();
                fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
            }
        } else {
            userTenantDomain = authenticatedUser.getTenantDomain();
            fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
        }
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, fullQualifiedUsername);
        if (realm == null) {
            log.warn("Invalid tenant domain: " + userTenantDomain + " provided. Cannot get claims for user: "
                    + fullQualifiedUsername);
            return userClaimsMappedToOIDCDialect;
        }

        List<String> requestedClaimUris = getRequestedClaimUris(requestClaimMappings);
        // Improve runtime claim value storage in cache through https://github.com/wso2/product-is/issues/15056
        requestedClaimUris.removeIf(claim -> claim.startsWith("http://wso2.org/claims/runtime/"));

        boolean requestedAppRoleClaim = false;
        if (requestedClaimUris.contains(APP_ROLES_CLAIM)) {
            requestedClaimUris.remove(APP_ROLES_CLAIM);
            requestedAppRoleClaim = true;
        }
        Map<String, String> userClaims = getUserClaimsInLocalDialect(fullQualifiedUsername, realm, requestedClaimUris);
        if (requestedAppRoleClaim) {
            handleAppRoleClaimInLocalDialect(userClaims, authenticatedUser, serviceProvider.getApplicationResourceId());
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
                                                           Map<String, String> userClaims)
            throws ClaimMetadataException {
        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        // Get user claims in OIDC dialect.
        return getUserClaimsInOidcDialect(oidcToLocalClaimMappings, userClaims);
    }

    private Map<String, String> getUserClaimsInLocalDialect(String username,
                                                            UserRealm realm,
                                                            List<String> claimURIList)
            throws UserStoreException {
        return realm.getUserStoreManager()
                .getUserClaimValues(
                        MultitenantUtils.getTenantAwareUsername(username),
                        claimURIList.toArray(new String[claimURIList.size()]),
                        null);
    }

    /**
     * Adds the application roles claim for local user.
     *
     * @param userClaims User claims in local dialect.
     * @param authenticatedUser Authenticated user.
     * @param applicationId Application ID.
     * @throws ApplicationRolesException Error while getting application roles.
     */
    private void handleAppRoleClaimInLocalDialect(Map<String, String> userClaims, AuthenticatedUser authenticatedUser,
                                                  String applicationId) throws ApplicationRolesException {

        ApplicationRolesResolver appRolesResolver =
                OpenIDConnectServiceComponentHolder.getInstance().getHighestPriorityApplicationRolesResolver();
        if (appRolesResolver == null) {
            log.debug("No application roles resolver found. So not adding application roles claim to the id_token.");
            return;
        }
        String[] appRoles = appRolesResolver.getRoles(authenticatedUser, applicationId);
        if (ArrayUtils.isNotEmpty(appRoles)) {
            userClaims.put(APP_ROLES_CLAIM, String.join(FrameworkUtils.getMultiAttributeSeparator(), appRoles));
        }
    }

    private void handleServiceProviderRoleMappings(ServiceProvider serviceProvider, String claimSeparator,
                                                   Map<String, String> userClaims) throws FrameworkException {
        for (String roleGroupClaimURI : IdentityUtil.getRoleGroupClaims()) {
            handleSPRoleMapping(serviceProvider, claimSeparator, userClaims, roleGroupClaimURI);
        }
    }

    private void handleSPRoleMapping(ServiceProvider serviceProvider, String claimSeparator, Map<String, String>
            userClaims, String roleGroupClaimURI) throws FrameworkException {

        if (isNotEmpty(userClaims) && userClaims.containsKey(roleGroupClaimURI)) {
            String roleClaim = userClaims.get(roleGroupClaimURI);
            List<String> rolesList = Arrays.asList(roleClaim.split(Pattern.quote(claimSeparator)));
            String spMappedRoleClaim =
                    OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
            userClaims.put(roleGroupClaimURI, spMappedRoleClaim);
        }
    }

    private String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
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
     * Get user claims in OIDC claim dialect.
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
     * To check whether a token has custom user claims.
     *
     * @param refreshTokenValidationDataDO RefreshTokenValidationDataDO.
     * @return true if the token user attributes has non OIDC claims.
     */
    private boolean isTokenHasCustomUserClaims(RefreshTokenValidationDataDO refreshTokenValidationDataDO) {

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
     * Get user attribute cached against the access token.
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
     * Get user attributes cached against the authorization code.
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
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Set user claims in OIDC dialect to the JWTClaimSet. Additionally we process multi values attributes here.
     *
     * @param jwtClaimsSetBuilder
     * @param userClaimsInOIDCDialect
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

    private String getAuthorizationCode(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(AUTHZ_CODE);
    }

    private String getAccessToken(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(ACCESS_TOKEN);
    }

    private String getAccessToken(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return (String) authzReqMessageContext.getProperty(ACCESS_TOKEN);
    }

    private String getDeviceCode(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(DEVICE_CODE);
    }

    private boolean isLocalUser(AuthenticatedUser authenticatedUser) {
        return !authenticatedUser.isFederatedUser();
    }

    private boolean isLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return !authzReqMessageContext.getAuthorizationReqDTO().getUser().isFederatedUser();
    }

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
     * Add the CNF claim to the OIDC dialect when a TLS certificate is passed in the request.
     *
     * @param tokenReqMessageContext       Token request message context.
     * @param userClaimsInOIDCDialect      Map of the user claims in the OIDC dialect.
     * @throws IdentityOAuth2Exception     An exception is thrown if the cert could not be obtained from the request.
     */
    private void addCnfClaimToOIDCDialect(OAuthTokenReqMessageContext tokenReqMessageContext,
                                          Map<String, Object> userClaimsInOIDCDialect)
            throws IdentityOAuth2Exception {
        
        Base64URL certThumbprint;
        X509Certificate certificate = null;
        String headerName = Optional.ofNullable(IdentityUtil.getProperty(OAuthConstants.MTLS_AUTH_HEADER))
                .orElse(CONFIG_NOT_FOUND);

        HttpRequestHeader[] requestHeaders = tokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getHttpRequestHeaders();
        Object certObject = Optional.ofNullable(tokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getHttpServletRequestWrapper().getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).orElse(null);

        if (requestHeaders != null && requestHeaders.length != 0) {
            Optional<HttpRequestHeader> certHeader =
                    Arrays.stream(requestHeaders).filter(h -> headerName.equals(h.getName())).findFirst();
            if (certHeader.isPresent()) {
                try {
                    certificate = OAuth2Util.parseCertificate(certHeader.get().getValue()[0]);
                } catch (CertificateException e) {
                    throw new IdentityOAuth2Exception("Error occurred while extracting the certificate", e);
                }
            }
        } else if (certObject instanceof X509Certificate) {
            certificate = (X509Certificate) certObject;
        }
        if (certificate != null) {
            certThumbprint = X509CertUtils.computeSHA256Thumbprint(certificate);
            userClaimsInOIDCDialect.put(CNF_CLAIM, Collections.singletonMap("x5t#S256", certThumbprint));
        }
    }

    /**
     * Retrieve whether the application is configured to issue TLS client certificate bound access tokens.
     *
     * @param  clientId      Client ID of the application.
     * @throws IdentityOAuth2Exception An exception is thrown if app information cannot be extracted from the client ID.
     */
    private boolean isTlsClientCertificateBoundAccessTokensEnabled(String clientId) throws IdentityOAuth2Exception {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
            return oAuthAppDO.isTlsClientCertificateBoundAccessTokens();
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving app information for client id: " +
                    clientId + " of tenantDomain: " + tenantDomain, e);
        }
    }
}
