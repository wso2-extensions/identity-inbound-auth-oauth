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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthTokenExpiryTimeDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;

public class OAuthAdminService extends AbstractAdmin {

    public static final String IMPLICIT = "implicit";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    private static List<String> allowedGrants = null;
    protected Log log = LogFactory.getLog(OAuthAdminService.class);

    /**
     * Registers an consumer secret against the logged in user. A given user can only have a single
     * consumer secret at a time. Calling this method again and again will update the existing
     * consumer secret key.
     *
     * @return An array containing the consumer key and the consumer secret correspondingly.
     * @throws IdentityOAuthAdminException Error when persisting the data in the persistence store.
     */
    public String[] registerOAuthConsumer() throws IdentityOAuthAdminException {

        String loggedInUser = CarbonContext.getThreadLocalCarbonContext().getUsername();

        if (log.isDebugEnabled()) {
            log.debug("Adding a consumer secret for the logged in user " + loggedInUser);
        }

        String tenantUser = MultitenantUtils.getTenantAwareUsername(loggedInUser);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userDomain = IdentityUtil.extractDomainFromName(loggedInUser);
        OAuthAppDAO dao = new OAuthAppDAO();
        return dao.addOAuthConsumer(UserCoreUtil.removeDomainFromName(tenantUser), tenantId, userDomain);
    }

    /**
     * Get all registered OAuth applications for the logged in user.
     *
     * @return An array of <code>OAuthConsumerAppDTO</code> objecting containing the application
     * information of the user
     * @throws IdentityOAuthAdminException Error when reading the data from the persistence store.
     */
    public OAuthConsumerAppDTO[] getAllOAuthApplicationData() throws IdentityOAuthAdminException {

        String userName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        OAuthConsumerAppDTO[] dtos = new OAuthConsumerAppDTO[0];

        if (userName == null) {
            if (log.isDebugEnabled()) {
                log.debug("User not logged in to get all registered OAuth Applications");
            }
            throw new IdentityOAuthAdminException("User not logged in to get all registered OAuth Applications");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        OAuthAppDAO dao = new OAuthAppDAO();
        OAuthAppDO[] apps = dao.getOAuthConsumerAppsOfUser(userName, tenantId);
        if (apps != null && apps.length > 0) {
            dtos = new OAuthConsumerAppDTO[apps.length];
            OAuthConsumerAppDTO dto;
            OAuthAppDO app;
            for (int i = 0; i < apps.length; i++) {
                app = apps[i];
                dto = new OAuthConsumerAppDTO();
                dto.setApplicationName(app.getApplicationName());
                dto.setCallbackUrl(app.getCallbackUrl());
                dto.setOauthConsumerKey(app.getOauthConsumerKey());
                dto.setOauthConsumerSecret(app.getOauthConsumerSecret());
                dto.setOAuthVersion(app.getOauthVersion());
                dto.setGrantTypes(app.getGrantTypes());
                dto.setUsername(app.getUser().toString());
                dto.setPkceMandatory(app.isPkceMandatory());
                dto.setPkceSupportPlain(app.isPkceSupportPlain());
                dto.setUserAccessTokenExpiryTime(app.getUserAccessTokenExpiryTime());
                dto.setApplicationAccessTokenExpiryTime(app.getApplicationAccessTokenExpiryTime());
                dto.setRefreshTokenExpiryTime(app.getRefreshTokenExpiryTime());
                dtos[i] = dto;
            }
        }
        return dtos;
    }

    /**
     * Get OAuth application data by the consumer key.
     *
     * @param consumerKey Consumer Key
     * @return <code>OAuthConsumerAppDTO</code> with application information
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException {

        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        OAuthAppDAO dao = new OAuthAppDAO();
        try {
            OAuthAppDO app = dao.getAppInformation(consumerKey);
            if (app != null) {
                dto.setApplicationName(app.getApplicationName());
                dto.setCallbackUrl(app.getCallbackUrl());
                dto.setOauthConsumerKey(app.getOauthConsumerKey());
                dto.setOauthConsumerSecret(app.getOauthConsumerSecret());
                dto.setOAuthVersion(app.getOauthVersion());
                dto.setGrantTypes(app.getGrantTypes());
                dto.setPkceMandatory(app.isPkceMandatory());
                dto.setPkceSupportPlain(app.isPkceSupportPlain());
                dto.setUserAccessTokenExpiryTime(app.getUserAccessTokenExpiryTime());
                dto.setApplicationAccessTokenExpiryTime(app.getApplicationAccessTokenExpiryTime());
                dto.setRefreshTokenExpiryTime(app.getRefreshTokenExpiryTime());

                if (log.isDebugEnabled()) {
                    log.debug("Found App :" + dto.getApplicationName() + " for consumerKey: " + consumerKey);
                }
            }
            return dto;
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw handleError("Error while retrieving the app information using consumerKey: " + consumerKey, e);
        }

    }

    /**
     * Get OAuth application data by the application name.
     *
     * @param appName OAuth application name
     * @return <code>OAuthConsumerAppDTO</code> with application information
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName) throws IdentityOAuthAdminException {

        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        OAuthAppDAO dao = new OAuthAppDAO();
        try {
            OAuthAppDO app = dao.getAppInformationByAppName(appName);
            if (app != null) {
                dto.setApplicationName(app.getApplicationName());
                dto.setCallbackUrl(app.getCallbackUrl());
                dto.setOauthConsumerKey(app.getOauthConsumerKey());
                dto.setOauthConsumerSecret(app.getOauthConsumerSecret());
                dto.setOAuthVersion(app.getOauthVersion());
                dto.setGrantTypes(app.getGrantTypes());
                dto.setPkceMandatory(app.isPkceMandatory());
                dto.setPkceSupportPlain(app.isPkceSupportPlain());
                dto.setTbMandatory(app.isTbMandatory());
                dto.setUserAccessTokenExpiryTime(app.getUserAccessTokenExpiryTime());
                dto.setApplicationAccessTokenExpiryTime(app.getApplicationAccessTokenExpiryTime());
                dto.setRefreshTokenExpiryTime(app.getRefreshTokenExpiryTime());
            }
            return dto;
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw handleError("Error while retrieving the app information by app name: " + appName, e);
        }
    }

    /**
     * Registers an OAuth consumer application.
     *
     * @param application <code>OAuthConsumerAppDTO</code> with application information
     * @throws Exception Error when persisting the application information to the persistence store
     */
    public void registerOAuthApplicationData(OAuthConsumerAppDTO application) throws IdentityOAuthAdminException {

        String tenantAwareUser = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (tenantAwareUser != null) {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

            OAuthAppDAO dao = new OAuthAppDAO();
            OAuthAppDO app = new OAuthAppDO();
            if (application != null) {
                app.setApplicationName(application.getApplicationName());
                if ((application.getGrantTypes().contains(AUTHORIZATION_CODE) || application.getGrantTypes()
                        .contains(IMPLICIT)) && StringUtils.isEmpty(application.getCallbackUrl())) {
                    throw new IdentityOAuthAdminException("Callback Url is required for Code or Implicit grant types");
                }
                app.setCallbackUrl(application.getCallbackUrl());
                if (application.getOauthConsumerKey() == null) {
                    app.setOauthConsumerKey(OAuthUtil.getRandomNumber());
                    app.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
                } else {
                    app.setOauthConsumerKey(application.getOauthConsumerKey());
                    app.setOauthConsumerSecret(application.getOauthConsumerSecret());
                }

                AuthenticatedUser user = buildAuthenticatedUser(tenantAwareUser, tenantDomain);
                String applicationUser = application.getUsername();

                if (StringUtils.isNotBlank(applicationUser)) {
                    try {
                        if (CarbonContext.getThreadLocalCarbonContext().getUserRealm().
                                getUserStoreManager().isExistingUser(applicationUser)) {

                            user.setUserName(UserCoreUtil.removeDomainFromName(applicationUser));
                            user.setUserStoreDomain(IdentityUtil.extractDomainFromName(applicationUser));

                        } else {
                            log.warn("OAuth application registrant user name " + applicationUser +
                                    " does not exist in the user store. Using logged-in user name " + tenantAwareUser +
                                    " as registrant name");
                        }
                    } catch (UserStoreException e) {
                        throw handleError("Error while retrieving the user store manager for user: "+ applicationUser, e);
                    }

                }
                app.setUser(user);
                if (application.getOAuthVersion() != null) {
                    app.setOauthVersion(application.getOAuthVersion());
                } else {   // by default, assume OAuth 2.0, if it is not set.
                    app.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
                }
                if (OAuthConstants.OAuthVersions.VERSION_2.equals(application.getOAuthVersion())) {
                    List<String> allowedGrantTypes = new ArrayList<>(Arrays.asList(getAllowedGrantTypes()));
                    String[] requestGrants = application.getGrantTypes().split("\\s");
                    for (String requestedGrant : requestGrants) {
                        if (StringUtils.isBlank(requestedGrant)) {
                            continue;
                        }
                        if (!allowedGrantTypes.contains(requestedGrant)) {
                            throw new IdentityOAuthAdminException(requestedGrant + " not allowed");
                        }
                    }
                    app.setGrantTypes(application.getGrantTypes());
                    app.setPkceMandatory(application.getPkceMandatory());
                    app.setPkceSupportPlain(application.getPkceSupportPlain());
                    // Validate access token expiry configurations.
                    validateTokenExpiryConfigurations(application);
                    app.setUserAccessTokenExpiryTime(application.getUserAccessTokenExpiryTime());
                    app.setApplicationAccessTokenExpiryTime(application.getApplicationAccessTokenExpiryTime());
                    app.setRefreshTokenExpiryTime(application.getRefreshTokenExpiryTime());
                    app.setTbMandatory(application.getTbMandatory());
                }
                dao.addOAuthApplication(app);
                AppInfoCache.getInstance().addToCache(app.getOauthConsumerKey(), app);
                if (log.isDebugEnabled()) {
                    log.debug("Oauth Application registration success : " + application.getApplicationName() + " in " +
                            "tenant domain: "+ tenantDomain);
                }
            } else {
                String message = "No application details in the request. Failed to register OAuth App";
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new IdentityOAuthAdminException(message);
            }
        } else {
            if (log.isDebugEnabled()) {
                if (application != null) {
                    log.debug("No authenticated user found. Failed to register OAuth App: " + application.getApplicationName());
                } else {
                    log.debug("No authenticated user found. Failed to register OAuth App");
                }
            }
            throw new IdentityOAuthAdminException("No authenticated user found. Failed to register OAuth App");
        }
    }

    /**
     * Update existing consumer application.
     *
     * @param consumerAppDTO <code>OAuthConsumerAppDTO</code> with updated application information
     * @throws IdentityOAuthAdminException Error when updating the underlying identity persistence store.
     */
    public void updateConsumerApplication(OAuthConsumerAppDTO consumerAppDTO) throws IdentityOAuthAdminException {

        String errorMessage = "Error while updating the app information.";
        if (StringUtils.isEmpty(consumerAppDTO.getOauthConsumerKey()) || StringUtils.isEmpty(consumerAppDTO
                .getOauthConsumerSecret())) {
            errorMessage = "OauthConsumerKey or OauthConsumerSecret is not provided for " +
                    "updating the OAuth application.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new IdentityOAuthAdminException(errorMessage);
        }
        String userName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        OAuthAppDAO dao = new OAuthAppDAO();
        OAuthAppDO oauthappdo = null;
        try {
            oauthappdo = dao.getAppInformation(consumerAppDTO.getOauthConsumerKey());
            if (oauthappdo == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving the app information using " +
                            "provided OauthConsumerKey: " + consumerAppDTO.getOauthConsumerKey());
                }
                throw new IdentityOAuthAdminException(errorMessage);
            }
            if (!consumerAppDTO.getOauthConsumerSecret().equals(oauthappdo.getOauthConsumerSecret())) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid oauthConsumerSecret is provided for updating the OAuth" +
                            " application with ConsumerKey: " + consumerAppDTO.getOauthConsumerKey());
                }
                throw new IdentityOAuthAdminException(errorMessage);
            }
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException("Error while updating the app information.", e);
        }

        String consumerKey = consumerAppDTO.getOauthConsumerKey();
        oauthappdo.setOauthConsumerKey(consumerKey);
        oauthappdo.setOauthConsumerSecret(consumerAppDTO.getOauthConsumerSecret());
        oauthappdo.setCallbackUrl(consumerAppDTO.getCallbackUrl());
        oauthappdo.setApplicationName(consumerAppDTO.getApplicationName());
        oauthappdo.setPkceMandatory(consumerAppDTO.getPkceMandatory());
        oauthappdo.setPkceSupportPlain(consumerAppDTO.getPkceSupportPlain());
        // Validate access token expiry configurations.
        validateTokenExpiryConfigurations(consumerAppDTO);
        oauthappdo.setUserAccessTokenExpiryTime(consumerAppDTO.getUserAccessTokenExpiryTime());
        oauthappdo.setApplicationAccessTokenExpiryTime(consumerAppDTO.getApplicationAccessTokenExpiryTime());
        oauthappdo.setRefreshTokenExpiryTime(consumerAppDTO.getRefreshTokenExpiryTime());
        oauthappdo.setTbMandatory(consumerAppDTO.getTbMandatory());
        if (OAuthConstants.OAuthVersions.VERSION_2.equals(consumerAppDTO.getOAuthVersion())) {
            List<String> allowedGrantsTypes = new ArrayList<>(Arrays.asList(getAllowedGrantTypes()));
            String[] requestGrants = consumerAppDTO.getGrantTypes().split("\\s");
            for (String requestedGrant : requestGrants) {
                if (StringUtils.isBlank(requestedGrant)) {
                    continue;
                }
                if (!allowedGrantsTypes.contains(requestedGrant)) {
                    throw new IdentityOAuthAdminException(requestedGrant + " not allowed for OAuth App with " +
                            "consumerKey: " + consumerKey);
                }
            }
            oauthappdo.setGrantTypes(consumerAppDTO.getGrantTypes());
        }
        dao.updateConsumerApplication(oauthappdo);
        AppInfoCache.getInstance().addToCache(oauthappdo.getOauthConsumerKey(), oauthappdo);
        if (log.isDebugEnabled()) {
            log.debug("Oauth Application update success : " + consumerAppDTO.getApplicationName() + " in " +
                    "tenant domain: "+ tenantDomain);
        }
    }

    /**
     * @return
     * @throws IdentityOAuthAdminException
     */
    public String getOauthApplicationState(String consumerKey) throws IdentityOAuthAdminException {
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        return oAuthAppDAO.getConsumerAppState(consumerKey);
    }

    /**
     * @param consumerKey
     * @param newState
     * @throws IdentityOAuthAdminException
     */
    public void updateConsumerAppState(String consumerKey, String newState) throws IdentityOAuthAdminException {

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(consumerKey);
            if (oAuthAppDO == null) {
                oAuthAppDO = oAuthAppDAO.getAppInformation(consumerKey);
            }
            // change the state
            oAuthAppDO.setState(newState);

            Properties properties = new Properties();
            properties.setProperty(OAuthConstants.OAUTH_APP_NEW_STATE, newState);
            properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REVOKE);
            updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);
            AppInfoCache.getInstance().addToCache(consumerKey, oAuthAppDO);

            if (log.isDebugEnabled()) {
                log.debug("App state is updated to:" + newState + " in the AppInfoCache for OAuth App with " +
                        "consumerKey: " + consumerKey);
            }

        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw handleError("Error while updating state of OAuth app with consumerKey: " + consumerKey, e);
        }
    }

    /**
     * @param consumerKey
     * @throws IdentityOAuthAdminException
     */
    public void updateOauthSecretKey(String consumerKey) throws IdentityOAuthAdminException {

        String newSecretKey = OAuthUtil.getRandomNumber();
        CacheEntry clientCredentialDO = new ClientCredentialDO(newSecretKey);
        Properties properties = new Properties();
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY, newSecretKey);
        properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REGENERATE);
        updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);
        OAuthCache.getInstance().addToCache(new OAuthCacheKey(consumerKey), clientCredentialDO);
        if (log.isDebugEnabled()) {
            log.debug("Client Secret for OAuth app with consumerKey: " + consumerKey + " updated in OAuthCache.");
        }
    }

    private void updateAppAndRevokeTokensAndAuthzCodes(String consumerKey,
                                                       Properties properties) throws IdentityOAuthAdminException {
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        int countToken = 0;
        try {
            Set<AccessTokenDO> activeDetailedTokens = tokenMgtDAO.getActiveDetailedTokensForConsumerKey(consumerKey);
            String[] accessTokens = new String[activeDetailedTokens.size()];

            for (AccessTokenDO detailToken : activeDetailedTokens) {
                String token = detailToken.getAccessToken();
                accessTokens[countToken] = token;
                countToken++;

                OAuthCacheKey cacheKeyToken = new OAuthCacheKey(token);
                OAuthCache.getInstance().clearCacheEntry(cacheKeyToken);

                String scope = OAuth2Util.buildScopeString(detailToken.getScope());
                String authorizedUser = detailToken.getAuthzUser().toString();
                boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
                String cacheKeyString;
                if (isUsernameCaseSensitive) {
                    cacheKeyString = consumerKey + ":" + authorizedUser + ":" + scope;
                } else {
                    cacheKeyString = consumerKey + ":" + authorizedUser.toLowerCase() + ":" + scope;
                }
                OAuthCacheKey cacheKeyUser = new OAuthCacheKey(cacheKeyString);
                OAuthCache.getInstance().clearCacheEntry(cacheKeyUser);
            }

            if (log.isDebugEnabled()) {
                log.debug("Access tokens and token of users are removed from the cache for OAuth App with " +
                        "consumerKey: " + consumerKey);
            }

            Set<String> authorizationCodes = tokenMgtDAO.getActiveAuthorizationCodesForConsumerKey(consumerKey);
            for (String authorizationCode : authorizationCodes) {
                OAuthCacheKey cacheKey = new OAuthCacheKey(authorizationCode);
                OAuthCache.getInstance().clearCacheEntry(cacheKey);
            }
            if (log.isDebugEnabled()) {
                log.debug("Access tokens are removed from the cache for OAuth App with consumerKey: " + consumerKey);
            }

            tokenMgtDAO.updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties,
                    authorizationCodes.toArray(new String[authorizationCodes.size()]),
                    accessTokens);

        } catch (IdentityOAuth2Exception | IdentityApplicationManagementException e) {
            throw handleError("Error in updating oauth app & revoking access tokens and authz " +
                    "codes for OAuth App with consumerKey: " + consumerKey, e);
        }
    }

    /**
     * Removes an OAuth consumer application.
     *
     * @param consumerKey Consumer Key
     * @throws IdentityOAuthAdminException Error when removing the consumer information from the database.
     */
    public void removeOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException {

        OAuthAppDAO dao = new OAuthAppDAO();
        dao.removeConsumerApplication(consumerKey);
        // remove client credentials from cache
        OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(consumerKey));
        AppInfoCache.getInstance().clearCacheEntry(consumerKey);
        if (log.isDebugEnabled()) {
            log.debug("Client credentials are removed from the cache for OAuth App with consumerKey: " + consumerKey);
        }

    }

    /**
     * Get apps that are authorized by the given user
     *
     * @return OAuth applications authorized by the user that have tokens in ACTIVE or EXPIRED state
     */
    public OAuthConsumerAppDTO[] getAppsAuthorizedByUser() throws IdentityOAuthAdminException {

        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        OAuthAppDAO appDAO = new OAuthAppDAO();

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String tenantAwareUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUserName));
        authenticatedUser.setUserStoreDomain(IdentityUtil.extractDomainFromName(tenantAwareUserName));
        authenticatedUser.setTenantDomain(tenantDomain);
        String username = UserCoreUtil.addTenantDomainToEntry(tenantAwareUserName, tenantDomain);

        String userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while getting user store domain for User ID : " + authenticatedUser;
                throw handleError(errorMsg, e);
            }
        }

        Set<String> clientIds;
        try {
            clientIds = tokenMgtDAO.getAllTimeAuthorizedClientIds(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while retrieving apps authorized by User ID : " + username;
            throw handleError(errorMsg, e);
        }
        Set<OAuthConsumerAppDTO> appDTOs = new HashSet<>();
        for (String clientId : clientIds) {
            Set<AccessTokenDO> accessTokenDOs;
            try {
                accessTokenDOs = tokenMgtDAO.retrieveAccessTokens(clientId, authenticatedUser, userStoreDomain, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while retrieving access tokens issued for " +
                        "Client ID : " + clientId + ", User ID : " + username;
                throw handleError(errorMsg, e);
            }
            if (!accessTokenDOs.isEmpty()) {
                Set<String> distinctClientUserScopeCombo = new HashSet<>();
                for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                    AccessTokenDO scopedToken;
                    String scopeString = OAuth2Util.buildScopeString(accessTokenDO.getScope());
                    try {
                        scopedToken = tokenMgtDAO.retrieveLatestAccessToken(
                                clientId, authenticatedUser, userStoreDomain, scopeString, true);
                        if (scopedToken != null && !distinctClientUserScopeCombo.contains(clientId + ":" + username)) {
                            OAuthConsumerAppDTO appDTO = new OAuthConsumerAppDTO();
                            OAuthAppDO appDO;
                            try {
                                appDO = appDAO.getAppInformation(scopedToken.getConsumerKey());
                                appDTO.setOauthConsumerKey(scopedToken.getConsumerKey());
                                appDTO.setApplicationName(appDO.getApplicationName());
                                appDTO.setUsername(appDO.getUser().toString());
                                appDTO.setGrantTypes(appDO.getGrantTypes());
                                appDTO.setPkceMandatory(appDO.isPkceMandatory());
                                appDTO.setPkceSupportPlain(appDO.isPkceSupportPlain());
                                appDTO.setUserAccessTokenExpiryTime(appDO.getUserAccessTokenExpiryTime());
                                appDTO.setApplicationAccessTokenExpiryTime(appDO.getApplicationAccessTokenExpiryTime());
                                appDTO.setRefreshTokenExpiryTime(appDO.getRefreshTokenExpiryTime());
                                appDTOs.add(appDTO);
                                if (log.isDebugEnabled()) {
                                    log.debug("Found App: " + appDO.getApplicationName() + " for user: " + username);
                                }
                            } catch (InvalidOAuthClientException e) {
                                String errorMsg = "Invalid Client ID : " + scopedToken.getConsumerKey();
                                log.error(errorMsg, e);
                                throw new IdentityOAuthAdminException(errorMsg);
                            } catch (IdentityOAuth2Exception e) {
                                String errorMsg = "Error occurred while retrieving app information " +
                                        "for Client ID : " + scopedToken.getConsumerKey();
                                log.error(errorMsg, e);
                                throw new IdentityOAuthAdminException(errorMsg);
                            }
                            distinctClientUserScopeCombo.add(clientId + ":" + username);
                        }
                    } catch (IdentityOAuth2Exception e) {
                        String errorMsg = "Error occurred while retrieving latest access token issued for Client ID :" +
                                " " + clientId + ", User ID : " + username + " and Scope : " + scopeString;
                        throw handleError(errorMsg, e);
                    }
                }
            }
        }
        return appDTOs.toArray(new OAuthConsumerAppDTO[appDTOs.size()]);
    }

    /**
     * Revoke authorization for OAuth apps by resource owners
     *
     * @param revokeRequestDTO DTO representing authorized user and apps[]
     * @return revokeRespDTO DTO representing success or failure message
     */
    public OAuthRevocationResponseDTO revokeAuthzForAppsByResoureOwner(
            OAuthRevocationRequestDTO revokeRequestDTO) throws IdentityOAuthAdminException {

        triggerPreRevokeListeners(revokeRequestDTO);
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        if (revokeRequestDTO.getApps() != null && revokeRequestDTO.getApps().length > 0) {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String tenantAwareUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            AuthenticatedUser user = new AuthenticatedUser();
            user.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUserName));
            user.setUserStoreDomain(IdentityUtil.extractDomainFromName(tenantAwareUserName));
            user.setTenantDomain(tenantDomain);
            String userName = UserCoreUtil.addTenantDomainToEntry(tenantAwareUserName, tenantDomain);

            String userStoreDomain = null;
            if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
                try {
                    userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(user);
                } catch (IdentityOAuth2Exception e) {
                    throw handleError("Error occurred while getting user store domain from User ID : " + user, e);
                }
            }
            OAuthConsumerAppDTO[] appDTOs = getAppsAuthorizedByUser();
            for (String appName : revokeRequestDTO.getApps()) {
                for (OAuthConsumerAppDTO appDTO : appDTOs) {
                    if (appDTO.getApplicationName().equals(appName)) {
                        Set<AccessTokenDO> accessTokenDOs;
                        try {
                            // retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                            accessTokenDOs = tokenMgtDAO.retrieveAccessTokens(
                                    appDTO.getOauthConsumerKey(), user, userStoreDomain, true);
                        } catch (IdentityOAuth2Exception e) {
                            String errorMsg = "Error occurred while retrieving access tokens issued for " +
                                    "Client ID : " + appDTO.getOauthConsumerKey() + ", User ID : " + userName;
                            throw handleError(errorMsg, e);
                        }
                        User authzUser;
                        for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                            //Clear cache with AccessTokenDO
                            authzUser = accessTokenDO.getAuthzUser();

                            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), authzUser,
                                    OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), authzUser);
                            OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());
                            AccessTokenDO scopedToken;
                            try {
                                // retrieve latest access token for particular client, user and scope combination if its ACTIVE or EXPIRED
                                scopedToken = tokenMgtDAO.retrieveLatestAccessToken(
                                        appDTO.getOauthConsumerKey(), user, userStoreDomain,
                                        OAuth2Util.buildScopeString(accessTokenDO.getScope()), true);
                            } catch (IdentityOAuth2Exception e) {
                                String errorMsg = "Error occurred while retrieving latest " +
                                        "access token issued for Client ID : " +
                                        appDTO.getOauthConsumerKey() + ", User ID : " + userName +
                                        " and Scope : " + OAuth2Util.buildScopeString(accessTokenDO.getScope());
                                throw handleError(errorMsg, e);
                            }
                            if (scopedToken != null) {
                                //Revoking token from database
                                try {
                                    tokenMgtDAO.revokeTokens(new String[]{scopedToken.getAccessToken()});
                                } catch (IdentityOAuth2Exception e) {
                                    String errorMsg = "Error occurred while revoking " + "Access Token : " +
                                            scopedToken.getAccessToken();
                                    throw handleError(errorMsg, e);
                                }
                                //Revoking the oauth consent from database.
                                try {
                                    tokenMgtDAO.revokeOAuthConsentByApplicationAndUser(((AuthenticatedUser) authzUser)
                                            .getAuthenticatedSubjectIdentifier(), tenantDomain, appName);
                                } catch (IdentityOAuth2Exception e) {
                                    String errorMsg = "Error occurred while removing OAuth Consent of Application " + appName +
                                            " of user " + userName;
                                    throw handleError(errorMsg, e);
                                }
                            }
                            triggerPostRevokeListeners(revokeRequestDTO, new OAuthRevocationResponseDTO
                                    (), accessTokenDOs.toArray(new AccessTokenDO[accessTokenDOs.size()]));
                        }
                    }
                }
            }
        } else {
            OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
            revokeRespDTO.setErrorMsg("Invalid revocation request");

            //passing a single element array with null element to make sure listeners are triggered at least once
            triggerPostRevokeListeners(revokeRequestDTO, revokeRespDTO, new AccessTokenDO[]{null});
            return revokeRespDTO;
        }
        return new OAuthRevocationResponseDTO();
    }

    /**
     * Revoke approve always of the consent for OAuth apps by resource owners
     *
     * @param appName name of the app
     * @param state   state of the approve always
     * @return revokeRespDTO DTO representing success or failure message
     */
    public OAuthRevocationResponseDTO updateApproveAlwaysForAppConsentByResourceOwner(String appName, String state)
            throws IdentityOAuthAdminException {
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String tenantAwareUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();

        try {
            tokenMgtDAO.updateApproveAlwaysForAppConsentByResourceOwner(tenantAwareUserName, tenantDomain, appName, state);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while revoking OAuth Consent approve always of Application " + appName +
                    " of user " + tenantAwareUserName;
            log.error(errorMsg, e);
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
            revokeRespDTO.setErrorMsg("Invalid revocation request");
        }
        return revokeRespDTO;
    }

    private void triggerPreRevokeListeners(OAuthRevocationRequestDTO
                                                   revokeRequestDTO) throws IdentityOAuthAdminException {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy.onPreTokenRevocationByResourceOwner(revokeRequestDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error occurred with Oauth pre-revoke listener ", e);
            }
        }
    }

    private void triggerPostRevokeListeners(OAuthRevocationRequestDTO revokeRequestDTO,
                                            OAuthRevocationResponseDTO revokeRespDTO, AccessTokenDO[] accessTokenDOs) {
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        for (AccessTokenDO accessTokenDO : accessTokenDOs) {
            if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
                try {
                    Map<String, Object> paramMap = new HashMap<>();
                    oAuthEventInterceptorProxy.onPostTokenRevocationByResourceOwner(revokeRequestDTO, revokeRespDTO,
                            accessTokenDO, paramMap);
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error occurred with post revocation listener ", e);
                }
            }
        }
    }

    public String[] getAllowedGrantTypes() {

        if (allowedGrants == null) {
            synchronized (OAuthAdminService.class) {
                if (allowedGrants == null) {
                    Set<String> allowedGrantSet =
                            OAuthServerConfiguration.getInstance().getSupportedGrantTypes().keySet();
                    Set<String> modifiableGrantSet = new HashSet(allowedGrantSet);
                    if (OAuthServerConfiguration.getInstance().getSupportedResponseTypes().containsKey("token")) {
                        modifiableGrantSet.add(IMPLICIT);
                    }
                    allowedGrants = new ArrayList<>(modifiableGrantSet);
                }
            }
        }
        return allowedGrants.toArray(new String[allowedGrants.size()]);
    }

    /**
     * @return true if PKCE is supported by the database, false if not
     */
    public boolean isPKCESupportEnabled() {
        return OAuth2Util.isPKCESupportEnabled();
    }

    public OAuthTokenExpiryTimeDTO getTokenExpiryTimes() {

        OAuthTokenExpiryTimeDTO tokenExpiryTime = new OAuthTokenExpiryTimeDTO();
        tokenExpiryTime.setUserAccessTokenExpiryTime(OAuthServerConfiguration
                .getInstance().getUserAccessTokenValidityPeriodInSeconds());
        tokenExpiryTime.setApplicationAccessTokenExpiryTime(OAuthServerConfiguration
                .getInstance().getApplicationAccessTokenValidityPeriodInSeconds());
        tokenExpiryTime.setRefreshTokenExpiryTime(OAuthServerConfiguration
                .getInstance().getRefreshTokenValidityPeriodInSeconds());
        return tokenExpiryTime;
    }

    private AuthenticatedUser buildAuthenticatedUser(String tenantAwareUser, String tenantDomain) {
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUser));
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(IdentityUtil.extractDomainFromName(tenantAwareUser));
        return user;
    }

    private void validateTokenExpiryConfigurations(OAuthConsumerAppDTO oAuthConsumerAppDTO) {
        if (oAuthConsumerAppDTO.getUserAccessTokenExpiryTime() == 0) {
            oAuthConsumerAppDTO.setUserAccessTokenExpiryTime(
                    OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds());
            logOnInvalidConfig(oAuthConsumerAppDTO.getApplicationName(), "user access token",
                    oAuthConsumerAppDTO.getUserAccessTokenExpiryTime());
        }

        if (oAuthConsumerAppDTO.getApplicationAccessTokenExpiryTime() == 0) {
            oAuthConsumerAppDTO.setApplicationAccessTokenExpiryTime(
                    OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds());
            logOnInvalidConfig(oAuthConsumerAppDTO.getApplicationName(), "application access token",
                    oAuthConsumerAppDTO.getApplicationAccessTokenExpiryTime());
        }

        if (oAuthConsumerAppDTO.getRefreshTokenExpiryTime() == 0) {
            oAuthConsumerAppDTO.setRefreshTokenExpiryTime(
                    OAuthServerConfiguration.getInstance().getRefreshTokenValidityPeriodInSeconds());
            logOnInvalidConfig(oAuthConsumerAppDTO.getApplicationName(), "refresh token",
                    oAuthConsumerAppDTO.getRefreshTokenExpiryTime());
        }
    }

    private void logOnInvalidConfig(String appName, String tokenType, long defaultValue) {
        if (log.isDebugEnabled()) {
            log.debug("Invalid expiry time value '0' set for " + tokenType + " in ServiceProvider: " + appName + ". " +
                    "Defaulting to expiry value: " + defaultValue + " seconds.");
        }
    }
}

