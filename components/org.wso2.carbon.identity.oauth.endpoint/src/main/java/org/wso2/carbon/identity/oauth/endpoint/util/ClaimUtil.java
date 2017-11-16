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
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoEndpointConfig;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.core.util.IdentityUtil.isTokenLoggable;

public class ClaimUtil {
    private static final String SP_DIALECT = "http://wso2.org/oidc/claim";
    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private static final Log log = LogFactory.getLog(ClaimUtil.class);

    private ClaimUtil() {
    }

    public static Map<String, Object> getClaimsFromUserStore(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {
        try {
            String username = tokenResponse.getAuthorizedUser();
            String userTenantDomain = MultitenantUtils.getTenantDomain(tokenResponse.getAuthorizedUser());
            UserRealm realm;
            List<String> claimURIList = new ArrayList<>();
            Map<String, Object> mappedAppClaims = new HashMap<>();
            String subjectClaimValue = null;

            try {
                AccessTokenDO accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(getAccessToken(tokenResponse));
                // If the authenticated user is a federated user and had not mapped to local users, no requirement to
                // retrieve claims from local userstore.
                if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && accessTokenDO != null) {
                    AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
                    if (isNotEmpty(authenticatedUser.getUserStoreDomain())) {
                        String userstoreDomain = authenticatedUser.getUserStoreDomain();
                        if (OAuth2Util.isFederatedUser(authenticatedUser)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Federated user store prefix available in domain " + userstoreDomain + ". Hence" +
                                        "returning without retrieving claims from user store");
                            }
                            // Add the sub claim.
                            subjectClaimValue = tokenResponse.getAuthorizedUser();
                            mappedAppClaims.put(OAuth2Util.SUB, tokenResponse.getAuthorizedUser());
                            if (log.isDebugEnabled() && isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                                log.debug("Subject claim(sub) value: " + subjectClaimValue + " set in returned claims.");
                            }
                            return mappedAppClaims;
                        }
                    }
                }

                Map<String, String> spToLocalClaimMappings;
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
//                    subjectClaimValue = getUsernameForUser(tokenResponse);
//                    mappedAppClaims.put(OAuth2Util.SUB, subjectClaimValue);
//                    if (log.isDebugEnabled() && isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
//                        log.debug("Subject claim(sub) value: " + subjectClaimValue + " set in returned claims.");
//                    }
//                    return mappedAppClaims;
                    throw new UserInfoEndpointException("Cannot retrieve service provider: " + spName);
                }
                ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();
                String subjectClaimURI = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
                if (requestedLocalClaimMap != null) {
                    for (ClaimMapping claimMapping : requestedLocalClaimMap) {
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
                if (subjectClaimURI != null || ArrayUtils.isNotEmpty(requestedLocalClaimMap)) {
                    if (requestedLocalClaimMap != null) {
                        for (ClaimMapping claimMapping : requestedLocalClaimMap) {
                            if (claimMapping.isRequested()) {
                                claimURIList.add(claimMapping.getLocalClaim().getClaimUri());
                                if (claimMapping.getLocalClaim().getClaimUri().equals(subjectClaimURI)) {
                                    isSubjectClaimInRequested = true;
                                }
                            }
                        }
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Requested number of local claims: " + claimURIList.size());
                    }

                    spToLocalClaimMappings = ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon
                            (SP_DIALECT, null, userTenantDomain, true);

                    realm = IdentityTenantUtil.getRealm(userTenantDomain, username);
                    if (realm == null) {
                        log.warn("No valid tenant domain provider. Empty claim returned back");
//                        subjectClaimValue = getUsernameForUser(tokenResponse);
//                        mappedAppClaims.put(OAuth2Util.SUB, subjectClaimValue);
//                        if (log.isDebugEnabled() && isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
//                            log.debug("Subject claim(sub) value: " + subjectClaimValue + " set in returned claims.");
//                        }
//                        return mappedAppClaims;
                        throw new UserInfoEndpointException("Invalid User Domain provided: " + userTenantDomain +
                                "Cannot retrieve user claims.");
                    }
                    UserStoreManager userstore = realm.getUserStoreManager();
                    Map<String, String> userClaims = userstore.getUserClaimValues(MultitenantUtils.getTenantAwareUsername
                            (username), claimURIList.toArray(new String[claimURIList.size()]), null);
                    if (log.isDebugEnabled()) {
                        log.debug("User claims retrieved from user store: " + userClaims.size());
                    }

                    if (MapUtils.isNotEmpty(userClaims)) {
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
                                roleClaim = OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
                                entry.setValue(roleClaim);
                            }

                            String value = spToLocalClaimMappings.get(entry.getKey());
                            if (value != null) {
                                if (entry.getKey().equals(subjectClaimURI)) {
                                    subjectClaimValue = entry.getValue();
                                    if (!isSubjectClaimInRequested) {
                                        if (log.isDebugEnabled()) {
                                            log.debug("Subject claim: " + entry.getKey() + " is not a requested claim. " +
                                                    "Not adding to claim map.");
                                        }
                                        continue;
                                    }
                                }
                                mappedAppClaims.put(value, entry.getValue());
                                if (log.isDebugEnabled() &&
                                        isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                                    log.debug("Mapped claim: key -  " + value + " value -" + entry.getValue());
                                }
                            }
                        }
                    }
                }

                if (StringUtils.isBlank(subjectClaimValue)) {
                    if (log.isDebugEnabled()) {
                        log.debug("No subject claim found. Defaulting to username as the sub claim.");
                    }
                    subjectClaimValue = getUsernameForUser(tokenResponse);
                }

                if (log.isDebugEnabled() && isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Subject claim(sub) value: " + subjectClaimValue + " set in returned claims.");
                }
                mappedAppClaims.put(OAuth2Util.SUB, subjectClaimValue);
            } catch (Exception e) {
                if (e instanceof UserStoreException) {
                    if (e.getMessage().contains("UserNotFound")) {
                        if (log.isDebugEnabled()) {
                            log.debug("User " + username + " not found in user store");
                        }
                    }
                } else {
                    log.error("Error while retrieving the claims from user store for " + username, e);
                    throw new IdentityOAuth2Exception("Error while retrieving the claims from user store for " + username);
                }
            }
            return mappedAppClaims;
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error while retrieving claims for user", e);
        }
    }

    private static String getUsernameForUser(OAuth2TokenValidationResponseDTO tokenResponse) {
        String tenantAwareUsername =
                MultitenantUtils.getTenantAwareUsername(tokenResponse.getAuthorizedUser());
        return UserCoreUtil.removeDomainFromName(tenantAwareUsername);
    }

    /**
     * @param serviceProvider
     * @param locallyMappedUserRoles
     * @deprecated use {@link OIDCClaimUtil#getServiceProviderMappedUserRoles(ServiceProvider, List, String)} instead.
     */
    public static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                           List<String> locallyMappedUserRoles,
                                                           String claimSeparator) throws FrameworkException {
        return OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, locallyMappedUserRoles, claimSeparator);
    }


    public static Map<String, Object> getUserClaimsFromTokenResponse(OAuth2TokenValidationResponseDTO
                                                                             tokenValidationResponse)
            throws UserInfoEndpointException {
        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenValidationResponse);
        Map<String, Object> claims;

        if (isEmpty(userAttributes)) {
            claims = getClaimsFromUserStore(tokenValidationResponse);
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache against the token. Retrieved claims from user store.");
            }
        } else {
            UserInfoClaimRetriever retriever = UserInfoEndpointConfig.getInstance().getUserInfoClaimRetriever();
            claims = retriever.getClaimsMap(userAttributes);
        }

        if (claims == null) {
            claims = new HashMap<>();
        }

        return claims;
    }

    private static Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse) {
        AuthorizationGrantCacheKey cacheKey =
                new AuthorizationGrantCacheKey(getAccessToken(tokenResponse));
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
        if (cacheEntry == null) {
            return new HashMap<>();
        }
        return cacheEntry.getUserAttributes();
    }

    private static String getAccessToken(OAuth2TokenValidationResponseDTO tokenResponse) {
        return tokenResponse.getAuthorizationContextToken().getTokenString();
    }

}