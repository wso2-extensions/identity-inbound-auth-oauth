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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
import org.wso2.carbon.identity.openidconnect.model.RequestObject;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.USERINFO;

public abstract class AbstractUserInfoResponseBuilder implements UserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(AbstractUserInfoResponseBuilder.class);

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        String clientId = getClientId(getAccessToken(tokenResponse));
        String spTenantDomain = getServiceProviderTenantDomain(tokenResponse);
        // Retrieve user claims.
        Map<String, Object> userClaims = retrieveUserClaims(tokenResponse);

        // Filter user claims based on the requested scopes
        Map<String, Object> filteredUserClaims =
                getUserClaimsFilteredByScope(userClaims, tokenResponse.getScope(), clientId, spTenantDomain);

        // Handle subject claim.
        String subjectClaim = getSubjectClaim(userClaims, clientId, spTenantDomain, tokenResponse);
        filteredUserClaims.put(OAuth2Util.SUB, subjectClaim);

        // Handle essential claims
        Map<String, Object> essentialClaims = getEssentialClaims(tokenResponse, userClaims);
        filteredUserClaims.putAll(essentialClaims);

        //Handle essential claims of the request object
        filterEssentialClaimsFromRequestObject(tokenResponse, userClaims, filteredUserClaims);

        return buildResponse(tokenResponse, spTenantDomain, filteredUserClaims);
    }

    private void filterEssentialClaimsFromRequestObject(OAuth2TokenValidationResponseDTO tokenResponse,
                                                        Map<String, Object> userClaims,
                                                        Map<String, Object> filteredUserClaims)
            throws UserInfoEndpointException {

        List<String> essentialClaimsFromRequestObject = new ArrayList<>();
        RequestObjectService requestObjectService = OpenIDConnectServiceComponentHolder.getRequestObjectService();
        try {
            if (requestObjectService != null) {
                essentialClaimsFromRequestObject = requestObjectService.getEssentialClaims(getAccessToken(tokenResponse)
                        , null, true);
            }
        } catch (RequestObjectException e) {
            throw new UserInfoEndpointException(e.getErrorMessage());
        }
        for (String essentialClaim : essentialClaimsFromRequestObject) {
            filteredUserClaims.put(essentialClaim, userClaims.get(essentialClaim));
            if (log.isDebugEnabled()) {
                log.debug("The " + essentialClaim + " is marked as an essentialClaim for userinfo in the OIDC Request" +
                        " Object.");
            }
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
        // Get sub claim from AuthorizationGrantCache.
        String subjectClaim = OIDCClaimUtil.getSubjectClaimCachedAgainstAccessToken(getAccessToken(tokenResponse));
        if (StringUtils.isNotBlank(subjectClaim)) {
            // We expect the subject claim cached to have the correct format.
            return subjectClaim;
        }

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(getAccessToken(tokenResponse));
        // Subject claim returned among claims user claims.
        subjectClaim = (String) userClaims.get(OAuth2Util.SUB);
        if (StringUtils.isBlank(subjectClaim)) {
            // Subject claim was not found among user claims too. Let's send back some sensible defaults.
            if (authenticatedUser.isFederatedUser()) {
                subjectClaim = authenticatedUser.getAuthenticatedSubjectIdentifier();
            } else {
                subjectClaim = authenticatedUser.getUserName();
            }
        }

        if (isLocalUser(authenticatedUser)) {
            // For a local user we need to do format the subject claim to honour the SP configurations to append
            // userStoreDomain and tenantDomain.
            subjectClaim = buildSubjectClaim(subjectClaim, authenticatedUser.getTenantDomain(),
                    authenticatedUser.getUserStoreDomain(), clientId, spTenantDomain);
        }
        return subjectClaim;
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
    protected Map<String, Object> getUserClaimsFilteredByScope(Map<String, Object> userClaims,
                                                               String[] requestedScopes,
                                                               String clientId,
                                                               String tenantDomain) {

        return OpenIDConnectServiceComponentHolder.getInstance()
                .getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, tenantDomain);
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

    private AuthenticatedUser getAuthenticatedUser(String accessToken) throws OAuthSystemException {

        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessToken);
            return OAuth2Util.getAuthenticatedUser(accessTokenDO);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException();
        }
    }

    private String getServiceProviderTenantDomain(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        String clientId = getClientId(getAccessToken(tokenResponse));
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new UserInfoEndpointException("Error while retrieving OAuth app information for clientId: " + clientId);
        }
        return OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
    }

    private String buildSubjectClaim(String sub,
                                     String userTenantDomain,
                                     String userStoreDomain,
                                     String clientId,
                                     String spTenantDomain) throws UserInfoEndpointException {

        ServiceProvider serviceProvider = getServiceProvider(spTenantDomain, clientId);

        if (serviceProvider != null) {
            boolean isUseTenantDomainInLocalSubject = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                    .isUseTenantDomainInLocalSubjectIdentifier();
            boolean isUseUserStoreDomainInLocalSubject = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                    .isUseUserstoreDomainInLocalSubjectIdentifier();

            if (isNotEmpty(sub)) {
                // Build subject in accordance with Local and Outbound Authentication Configuration preferences
                if (isUseUserStoreDomainInLocalSubject) {
                    sub = IdentityUtil.addDomainToName(sub, userStoreDomain);
                }
                if (isUseTenantDomainInLocalSubject) {
                    sub = UserCoreUtil.addTenantDomainToEntry(sub, userTenantDomain);
                }
            }
        }
        return sub;
    }

    private String getClientId(String accessToken) throws UserInfoEndpointException {

        try {
            return OAuth2Util.getClientIdForAccessToken(accessToken);
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error while obtaining the client_id from accessToken.", e);
        }
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

    private List<String> getEssentialClaimUris(OAuth2TokenValidationResponseDTO tokenResponse) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(getAccessToken(tokenResponse));
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry != null) {
            if (isNotEmpty(cacheEntry.getEssentialClaims())) {
                return OAuth2Util.getEssentialClaims(cacheEntry.getEssentialClaims(), USERINFO);
            }
        }
        return new ArrayList<>();
    }

    private RequestObject getRequestObject(OAuth2TokenValidationResponseDTO tokenResponse) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(getAccessToken(tokenResponse));
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);
        RequestObject requestObject = null;

        if (cacheEntry != null) {
            requestObject = cacheEntry.getRequestObject();
        }
        return requestObject;
    }

    private boolean isLocalUser(AuthenticatedUser authenticatedUser) {

        return !authenticatedUser.isFederatedUser();
    }

    private String getAccessToken(OAuth2TokenValidationResponseDTO tokenResponse) {

        return tokenResponse.getAuthorizationContextToken().getTokenString();
    }
}
