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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.USERINFO;

/**
 * Abstract user info response builder.
 */
public abstract class AbstractUserInfoResponseBuilder implements UserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(AbstractUserInfoResponseBuilder.class);

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        String clientId;
        Optional<AccessTokenDO> optionalAccessTokenDO = OAuth2Util.getAccessTokenDO(tokenResponse);
        if (optionalAccessTokenDO.isPresent()) {
            AccessTokenDO accessTokenDO = optionalAccessTokenDO.get();
            clientId = accessTokenDO.getConsumerKey();
        } else {
            throw new IllegalArgumentException(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);
        }
        String spTenantDomain = getServiceProviderTenantDomain(tokenResponse);

        // Retrieve user claims.
        Map<String, Object> userClaims = retrieveUserClaims(tokenResponse);
        Map<String, Object> filteredUserClaims = filterOIDCClaims(tokenResponse, clientId, spTenantDomain, userClaims);

        // Handle subject claim.
        String subjectClaim = getSubjectClaim(userClaims, clientId, spTenantDomain, tokenResponse);
        subjectClaim = getOIDCSubjectClaim(clientId, spTenantDomain, subjectClaim);
        filteredUserClaims.put(OAuth2Util.SUB, subjectClaim);

        return buildResponse(tokenResponse, spTenantDomain, filteredUserClaims);
    }

    private String getOIDCSubjectClaim(String clientId, String spTenantDomain, String subjectClaim)
            throws UserInfoEndpointException {

        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, spTenantDomain);
            // Get subject identifier according to the configured subject type.
            return OIDCClaimUtil.getSubjectClaim(subjectClaim, oAuthAppDO);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new UserInfoEndpointException("Error while getting subject claim for client_id: " + clientId +
                    " of tenantDomain: " + spTenantDomain, e);
        }
    }

    private Map<String, Object> filterOIDCClaims(OAuth2TokenValidationResponseDTO tokenResponse,
                                                 String clientId,
                                                 String spTenantDomain,
                                                 Map<String, Object> userClaims)
            throws OAuthSystemException, UserInfoEndpointException {

        AccessTokenDO accessTokenDO;
        String accessToken;
        try {
            accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(tokenResponse.getAuthorizationContextToken().getTokenString(), false);
            accessToken = accessTokenDO == null ? null : accessTokenDO.getAccessToken();
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while obtaining access token.", e);
        }
        if (MapUtils.isEmpty(userClaims)) {
            if (log.isDebugEnabled()) {
                AuthenticatedUser authenticatedUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);
                log.debug("No user claims available to be filtered for user: " +
                        authenticatedUser.toFullQualifiedUsername() + " for client_id: " + clientId +
                        " of tenantDomain: " + spTenantDomain);
            }
            return new HashMap<>();
        }

        // Filter user claims based on the requested scopes
        Map<String, Object> userClaimsFilteredByScope =
                getUserClaimsFilteredByScope(tokenResponse, userClaims, tokenResponse.getScope(), clientId,
                        spTenantDomain);

        // Handle essential claims
        Map<String, Object> essentialClaims = getEssentialClaims(tokenResponse, userClaims);
        userClaimsFilteredByScope.putAll(essentialClaims);
        //Handle essential claims of the request object
        Map<String, Object> filteredClaimsFromRequestObject = filterClaimsFromRequestObject(userClaims, accessToken);
        userClaimsFilteredByScope.putAll(filteredClaimsFromRequestObject);

        AuthenticatedUser authenticatedUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);

        // User consent checking is skipped for API based authentication flow.
        if (isApiBasedAuthFlow(accessToken)) {
            if (log.isDebugEnabled()) {
                String msg = "Filtering user claims based on user consent skipped due api based auth flow. Returning " +
                        "original user claims for user:%s, for clientId:%s of tenantDomain:%s";
                log.debug(String.format(msg, authenticatedUser.toFullQualifiedUsername(),
                        clientId, spTenantDomain));
            }
            return userClaimsFilteredByScope;
        }

        // Filter the user claims based on user consent
        return getUserClaimsFilteredByConsent(tokenResponse, userClaimsFilteredByScope, authenticatedUser, clientId,
                spTenantDomain);
    }

    private String getGrantType(AccessTokenDO accessTokenDO) {

        return accessTokenDO.getGrantType();
    }

    private Map<String, Object> filterClaimsFromRequestObject(Map<String, Object> userAttributes,
                                                              String token) throws OAuthSystemException {
        try {
            List<RequestedClaim> requestedClaims = OpenIDConnectServiceComponentHolder.getRequestObjectService().
                    getRequestedClaimsForUserInfo(token);
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByEssentialClaims(userAttributes, requestedClaims);
        } catch (RequestObjectException e) {
            throw new OAuthSystemException("Unable to retrieve requested claims from Request Object." + e);
        }


    }

    /**
     * Get the 'sub' claim. By append the userStoreDomain or tenantDomain for local users based on the Service
     * Provider's local and outbound authentication configurations.
     *
     * @param userClaims
     * @param clientId
     * @param spTenantDomain
     * @param tokenResponse
     * @return
     * @throws UserInfoEndpointException
     * @throws OAuthSystemException
     */
    protected String getSubjectClaim(Map<String, Object> userClaims,
                                     String clientId,
                                     String spTenantDomain,
                                     OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        AuthenticatedUser authenticatedUser;
        try {
            authenticatedUser = OAuth2Util.getAuthenticatedUser(OAuth2ServiceComponentHolder.getInstance()
                    .getTokenProvider().getVerifiedAccessToken(
                            tokenResponse.getAuthorizationContextToken().getTokenString(), false));
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while obtaining access token.", e);
        }
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }

    /**
     * Filter user claims requested by the Service Provider based on the requested scopes.
     *
     * @param userClaims
     * @param requestedScopes
     * @param clientId
     * @param tenantDomain
     * @return
     */
    protected Map<String, Object> getUserClaimsFilteredByScope(OAuth2TokenValidationResponseDTO validationResponseDTO,
                                                               Map<String, Object> userClaims,
                                                               String[] requestedScopes,
                                                               String clientId,
                                                               String tenantDomain) throws UserInfoEndpointException {

        return OpenIDConnectServiceComponentHolder.getInstance()
                .getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, tenantDomain);
    }

    /**
     * Filter user claims requested by the Service Provider based on the requested scopes.
     *
     * @param userClaims
     * @param user
     * @param clientId
     * @param tenantDomain
     * @return
     */
    protected Map<String, Object> getUserClaimsFilteredByConsent(OAuth2TokenValidationResponseDTO validationResponseDTO,
                                                                 Map<String, Object> userClaims,
                                                                 AuthenticatedUser user,
                                                                 String clientId,
                                                                 String tenantDomain) throws UserInfoEndpointException {

        String grantType;
        try {
            String accessToken = validationResponseDTO.getAuthorizationContextToken().getTokenString();
            AccessTokenDO accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(accessToken, false);
            grantType = getGrantType(accessTokenDO);
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                // Get the Access Token details from the database/cache to check if the token is consented or not.
                boolean isConsentedToken = accessTokenDO.isConsentedToken();
                return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, user, clientId, tenantDomain, grantType,
                        getServiceProvider(tenantDomain, clientId), isConsentedToken);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("An error occurred while fetching the access token details.", e);
        }
        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, user, clientId, tenantDomain, grantType,
                getServiceProvider(tenantDomain, clientId));
    }



    protected Map<String, Object> getEssentialClaims(OAuth2TokenValidationResponseDTO tokenResponse,
                                                     Map<String, Object> claims) throws UserInfoEndpointException {

        Map<String, Object> essentialClaimMap = new HashMap<>();
        List<String> essentialClaims = getEssentialClaimUris(tokenResponse);
        if (isNotEmpty(essentialClaims)) {
            for (String key : essentialClaims) {
                essentialClaimMap.put(key, claims.get(key));
            }
        }
        return essentialClaimMap;
    }

    /**
     * Retrieve User claims in OIDC Dialect.
     *
     * @param tokenValidationResponse
     * @return Map of user claims, Map<"oidc_claim_uri", "claimValue">
     * @throws UserInfoEndpointException
     */
    protected abstract Map<String, Object> retrieveUserClaims(OAuth2TokenValidationResponseDTO tokenValidationResponse)
            throws UserInfoEndpointException;

    /**
     * Build UserInfo response to be sent back to the client.
     *
     * @param tokenResponse      {@link OAuth2TokenValidationResponseDTO} Token Validation response containing metadata
     *                           about the access token used for user info call.
     * @param spTenantDomain     Service Provider tenant domain.
     * @param filteredUserClaims Filtered user claims based on the requested scopes.
     * @return UserInfo Response String to be sent in the response.
     * @throws UserInfoEndpointException
     */
    protected abstract String buildResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                            String spTenantDomain,
                                            Map<String, Object> filteredUserClaims) throws UserInfoEndpointException;

    private String getServiceProviderTenantDomain(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        String clientId = null;
        OAuthAppDO oAuthAppDO;
        try {

            Optional<AccessTokenDO> optionalAccessTokenDO = OAuth2Util.getAccessTokenDO(tokenResponse);
            if (optionalAccessTokenDO.isPresent()) {
                AccessTokenDO accessTokenDO = optionalAccessTokenDO.get();
                clientId = accessTokenDO.getConsumerKey();
                oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            } else {
                throw new IllegalArgumentException(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);
            }
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new UserInfoEndpointException(
                    "Error while retrieving OAuth app information for clientId: " + clientId);
        }
        return OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
    }

    private ServiceProvider getServiceProvider(String tenantDomain, String clientId) throws UserInfoEndpointException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        ServiceProvider serviceProvider;
        try {
            // Get the Service Provider.
            serviceProvider = applicationMgtService.getServiceProviderByClientId(
                    clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new UserInfoEndpointException("Error while obtaining the service provider for client_id: " +
                    clientId + " of tenantDomain: " + tenantDomain, e);
        }
        return serviceProvider;
    }

    private List<String> getEssentialClaimUris(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(
                OAuth2Util.getAccessTokenIdentifier(tokenResponse));
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry != null) {
            if (isNotEmpty(cacheEntry.getEssentialClaims())) {
                return OAuth2Util.getEssentialClaims(cacheEntry.getEssentialClaims(), USERINFO);
            }
        }
        return new ArrayList<>();
    }

    private boolean isApiBasedAuthFlow(String accessToken) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry != null) {
            return cacheEntry.isApiBasedAuthRequest();
        }
        return false;
    }
}
