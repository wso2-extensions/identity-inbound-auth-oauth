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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
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
import org.wso2.carbon.identity.oauth.dto.OAuthIDTokenAlgorithmDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthTokenExpiryTimeDTO;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.model.TokenIssuerDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
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
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;

public class OAuthAdminService extends AbstractAdmin {

    public static final String IMPLICIT = "implicit";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_ID_TOKEN = "id_token";
    private static List<String> allowedGrants = null;
    private static String[] allowedScopeValidators = null;
    private static List<String> supportedTokenTypes = null;
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
            OAuthAppDO app;
            for (int i = 0; i < apps.length; i++) {
                app = apps[i];
                dtos[i] = OAuthUtil.buildConsumerAppDTO(app);
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

        OAuthConsumerAppDTO dto;
        OAuthAppDAO dao = new OAuthAppDAO();
        try {
            OAuthAppDO app = dao.getAppInformation(consumerKey);
            if (app != null) {
                dto = OAuthUtil.buildConsumerAppDTO(app);
                if (log.isDebugEnabled()) {
                    log.debug("Found App :" + dto.getApplicationName() + " for consumerKey: " + consumerKey);
                }
            } else {
                dto = new OAuthConsumerAppDTO();
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

        OAuthConsumerAppDTO dto;
        OAuthAppDAO dao = new OAuthAppDAO();
        try {
            OAuthAppDO app = dao.getAppInformationByAppName(appName);
            if (app != null) {
                dto = OAuthUtil.buildConsumerAppDTO(app);
            } else {
                dto = new OAuthConsumerAppDTO();
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
     * @throws IdentityOAuthAdminException Error when persisting the application information to the persistence store.
     */
    public void registerOAuthApplicationData(OAuthConsumerAppDTO application) throws IdentityOAuthAdminException {

        registerAndRetrieveOAuthApplicationData(application);
    }

    /**
     * Registers an OAuth consumer application and retrieve application details.
     *
     * @param application <code>OAuthConsumerAppDTO</code> with application information.
     * @return OAuthConsumerAppDTO Created OAuth application details.
     * @throws IdentityOAuthAdminException Error when persisting the application information to the persistence store.
     */
    public OAuthConsumerAppDTO registerAndRetrieveOAuthApplicationData(OAuthConsumerAppDTO application)
            throws IdentityOAuthAdminException {

        String tenantAwareLoggedInUser = CarbonContext.getThreadLocalCarbonContext().getUsername();
        OAuthAppDO app = new OAuthAppDO();
        if (tenantAwareLoggedInUser != null) {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

            OAuthAppDAO dao = new OAuthAppDAO();
            if (application != null) {
                app.setApplicationName(application.getApplicationName());
                if ((application.getGrantTypes().contains(AUTHORIZATION_CODE) || application.getGrantTypes()
                        .contains(IMPLICIT)) && StringUtils.isEmpty(application.getCallbackUrl())) {
                    throw new IdentityOAuthAdminException("Callback Url is required for Code or Implicit grant types");
                }
                app.setCallbackUrl(application.getCallbackUrl());
                app.setState(APP_STATE_ACTIVE);
                if (StringUtils.isEmpty(application.getOauthConsumerKey())) {
                    app.setOauthConsumerKey(OAuthUtil.getRandomNumber());
                    app.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
                } else {
                    app.setOauthConsumerKey(application.getOauthConsumerKey());
                    if (StringUtils.isEmpty(application.getOauthConsumerSecret())) {
                        app.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
                    } else {
                        app.setOauthConsumerSecret(application.getOauthConsumerSecret());
                    }
                }

                AuthenticatedUser appOwner = getAppOwner(application, tenantAwareLoggedInUser, tenantDomain);
                app.setAppOwner(appOwner);

                if (application.getOAuthVersion() != null) {
                    app.setOauthVersion(application.getOAuthVersion());
                } else {   // by default, assume OAuth 2.0, if it is not set.
                    app.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
                }
                if (OAuthConstants.OAuthVersions.VERSION_2.equals(app.getOauthVersion())) {
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
                    app.setScopeValidators(filterScopeValidators(application));
                    app.setAudiences(application.getAudiences());
                    app.setPkceMandatory(application.getPkceMandatory());
                    app.setPkceSupportPlain(application.getPkceSupportPlain());
                    // Validate access token expiry configurations.
                    validateTokenExpiryConfigurations(application);
                    app.setUserAccessTokenExpiryTime(application.getUserAccessTokenExpiryTime());
                    app.setApplicationAccessTokenExpiryTime(application.getApplicationAccessTokenExpiryTime());
                    app.setRefreshTokenExpiryTime(application.getRefreshTokenExpiryTime());
                    app.setIdTokenExpiryTime(application.getIdTokenExpiryTime());

                    // Set OIDC Config Properties.
                    app.setRequestObjectSignatureValidationEnabled(application
                            .isRequestObjectSignatureValidationEnabled());
                    app.setIdTokenEncryptionEnabled(application.isIdTokenEncryptionEnabled());
                    app.setIdTokenEncryptionAlgorithm(application.getIdTokenEncryptionAlgorithm());
                    app.setIdTokenEncryptionMethod(application.getIdTokenEncryptionMethod());
                    app.setBackChannelLogoutUrl(application.getBackChannelLogoutUrl());
                    app.setFrontchannelLogoutUrl(application.getFrontchannelLogoutUrl());
                    app.setTokenType(application.getTokenType());
                    app.setBypassClientCredentials(application.isBypassClientCredentials());
                    app.setRenewRefreshTokenEnabled(application.getRenewRefreshTokenEnabled());
                }
                dao.addOAuthApplication(app);
                AppInfoCache.getInstance().addToCache(app.getOauthConsumerKey(), app);
                if (log.isDebugEnabled()) {
                    log.debug("Oauth Application registration success : " + application.getApplicationName() + " in " +
                            "tenant domain: " + tenantDomain);
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
                    log.debug("No authenticated user found. Failed to register OAuth App: " +
                            application.getApplicationName());
                } else {
                    log.debug("No authenticated user found. Failed to register OAuth App");
                }
            }
            throw new IdentityOAuthAdminException("No authenticated user found. Failed to register OAuth App");
        }
        return OAuthUtil.buildConsumerAppDTO(app);
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

        String loggedInUserName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantAwareLoggedInUserName = MultitenantUtils.getTenantAwareUsername(loggedInUserName);
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        OAuthAppDAO dao = new OAuthAppDAO();
        OAuthAppDO oauthappdo;
        try {
            oauthappdo = dao.getAppInformation(consumerAppDTO.getOauthConsumerKey());
            if (oauthappdo == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving the app information using " +
                            "provided OauthConsumerKey: " + consumerAppDTO.getOauthConsumerKey());
                }
                throw new IdentityOAuthAdminException(errorMessage);
            }
            if (!StringUtils.equals(consumerAppDTO.getOauthConsumerSecret(), oauthappdo.getOauthConsumerSecret())) {
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

        AuthenticatedUser appOwner = getAppOwner(consumerAppDTO, tenantAwareLoggedInUserName, tenantDomain);
        oauthappdo.setAppOwner(appOwner);

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
        oauthappdo.setIdTokenExpiryTime(consumerAppDTO.getIdTokenExpiryTime());
        oauthappdo.setTokenType(consumerAppDTO.getTokenType());
        oauthappdo.setBypassClientCredentials(consumerAppDTO.isBypassClientCredentials());
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
            oauthappdo.setAudiences(consumerAppDTO.getAudiences());
            oauthappdo.setScopeValidators(filterScopeValidators(consumerAppDTO));
            oauthappdo.setRequestObjectSignatureValidationEnabled(consumerAppDTO
                    .isRequestObjectSignatureValidationEnabled());
            oauthappdo.setIdTokenEncryptionEnabled(consumerAppDTO.isIdTokenEncryptionEnabled());
            oauthappdo.setIdTokenEncryptionAlgorithm(consumerAppDTO.getIdTokenEncryptionAlgorithm());
            oauthappdo.setIdTokenEncryptionMethod(consumerAppDTO.getIdTokenEncryptionMethod());
            oauthappdo.setBackChannelLogoutUrl(consumerAppDTO.getBackChannelLogoutUrl());
            oauthappdo.setFrontchannelLogoutUrl(consumerAppDTO.getFrontchannelLogoutUrl());
            oauthappdo.setRenewRefreshTokenEnabled(consumerAppDTO.getRenewRefreshTokenEnabled());
        }
        dao.updateConsumerApplication(oauthappdo);
        AppInfoCache.getInstance().addToCache(oauthappdo.getOauthConsumerKey(), oauthappdo);
        if (log.isDebugEnabled()) {
            log.debug("Oauth Application update success : " + consumerAppDTO.getApplicationName() + " in " +
                    "tenant domain: " + tenantDomain);
        }
    }

    /**
     * @return
     * @throws IdentityOAuthAdminException
     */
    public String getOauthApplicationState(String consumerKey) throws IdentityOAuthAdminException {

        return getOAuth2Service().getOauthApplicationState(consumerKey);
    }

    /**
     * To insert oidc scopes and claims in the related db tables.
     *
     * @param scope an oidc scope
     * @throws IdentityOAuthAdminException if an error occurs when inserting scopes or claims.
     */
    public void addScope(String scope, String[] claims)
            throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            if (StringUtils.isNotEmpty(scope)) {
                OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().addScope(tenantId, scope, claims);
            } else {
                throw new IdentityOAuthAdminException("The scope can not be empty.");
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while inserting OIDC scopes and claims.", e);
        }
    }

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @return all persisted scopes and claims
     * @throws IdentityOAuth2Exception if an error occurs when loading scopes and claims.
     */
    public ScopeDTO[] getScopes() throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            List<ScopeDTO> scopeDTOList = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getScopes(tenantId);
            if (CollectionUtils.isNotEmpty(scopeDTOList)) {
                return scopeDTOList.toArray(new ScopeDTO[scopeDTOList.size()]);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Could not find scope claim mapping. Hence returning an empty array.");
                }
                return new ScopeDTO[0];
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while loading OIDC scopes and claims for tenant: " + tenantId, e);
        }
    }

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope oidc scope
     * @throws IdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     */
    public void deleteScope(String scope) throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().deleteScope(scope, tenantId);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while deleting OIDC scope: " + scope, e);
        }
    }

    /**
     * To retrieve all persisted oidc scopes.
     *
     * @return list of scopes persisted.
     * @throws IdentityOAuth2Exception if an error occurs when loading oidc scopes.
     */
    public String[] getScopeNames() throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            List<String> scopeDTOList = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getScopeNames(tenantId);
            if (CollectionUtils.isNotEmpty(scopeDTOList)) {
                return scopeDTOList.toArray(new String[scopeDTOList.size()]);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Could not load oidc scopes. Hence returning an empty array.");
                }
                return new String[0];
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while loading OIDC scopes and claims for tenant: " + tenantId, e);
        }
    }

    /**
     * To retrieve oidc claims mapped to an oidc scope.
     *
     * @param scope scope
     * @return list of claims which are mapped to the oidc scope.
     * @throws IdentityOAuth2Exception if an error occurs when lading oidc claims.
     */
    public String[] getClaims(String scope) throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            ScopeDTO scopeDTO = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getClaims(scope, tenantId);
            if (scopeDTO != null && ArrayUtils.isNotEmpty(scopeDTO.getClaim())) {
                return scopeDTO.getClaim();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Could not load oidc claims. Hence returning an empty array.");
                }
                return new String[0];
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while loading OIDC claims for the scope: " + scope + " in tenant: " + tenantId, e);
        }
    }

    /**
     * To add new claims for an existing scope.
     *
     * @param scope        scope name
     * @param addClaims    list of oidc claims to be added
     * @param deleteClaims list of oidc claims to be deleted
     * @throws IdentityOAuth2Exception if an error occurs when adding a new claim for a scope.
     */
    public void updateScope(String scope, String[] addClaims, String[] deleteClaims)
            throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    updateScope(scope, tenantId, Arrays.asList(addClaims), Arrays.asList(deleteClaims));
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while updating OIDC claims for the scope: " + scope + " in tenant: " + tenantId, e);
        }
    }

    /**
     * To load id of the scope table.
     *
     * @param scope scope name
     * @return id of the given scope
     * @throws IdentityOAuth2Exception if an error occurs when loading scope id.
     */
    public boolean isScopeExist(String scope) throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            return OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().isScopeExist(scope, tenantId);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while inserting the scopes.", e);
        }
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
     * Regenerate consumer secret for the application.
     *
     * @param consumerKey Consumer key for the application.
     * @throws IdentityOAuthAdminException Error while regenerating the consumer secret.
     */
    public void updateOauthSecretKey(String consumerKey) throws IdentityOAuthAdminException {

        updateAndRetrieveOauthSecretKey(consumerKey);
    }

    /**
     * Regenerate consumer secret for the application and retrieve application details.
     *
     * @param consumerKey Consumer key for the application.
     * @return OAuthConsumerAppDTO OAuth application details.
     * @throws IdentityOAuthAdminException Error while regenerating the consumer secret.
     */
    public OAuthConsumerAppDTO updateAndRetrieveOauthSecretKey(String consumerKey) throws IdentityOAuthAdminException {

        OAuthConsumerAppDTO oAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        String newSecretKey = OAuthUtil.getRandomNumber();
        CacheEntry clientCredentialDO = new ClientCredentialDO(newSecretKey);
        oAuthConsumerAppDTO.setOauthConsumerKey(consumerKey);
        oAuthConsumerAppDTO.setOauthConsumerSecret(newSecretKey);
        Properties properties = new Properties();
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY, newSecretKey);
        properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REGENERATE);
        updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);
        OAuthCache.getInstance().addToCache(new OAuthCacheKey(consumerKey), clientCredentialDO);
        if (log.isDebugEnabled()) {
            log.debug("Client Secret for OAuth app with consumerKey: " + consumerKey + " updated in OAuthCache.");
        }
        return oAuthConsumerAppDTO;

    }

    private void updateAppAndRevokeTokensAndAuthzCodes(String consumerKey,
                                                       Properties properties) throws IdentityOAuthAdminException {

        int countToken = 0;
        try {
            Set<AccessTokenDO> activeDetailedTokens = OAuthTokenPersistenceFactory.getInstance()
                    .getAccessTokenDAO().getActiveAcessTokenDataByConsumerKey(consumerKey);
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

            Set<String> authorizationCodes = OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().getActiveAuthorizationCodesByConsumerKey(consumerKey);
            for (String authorizationCode : authorizationCodes) {
                OAuthCacheKey cacheKey = new OAuthCacheKey(authorizationCode);
                OAuthCache.getInstance().clearCacheEntry(cacheKey);
            }
            if (log.isDebugEnabled()) {
                log.debug("Access tokens are removed from the cache for OAuth App with consumerKey: " + consumerKey);
            }

            OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                    .updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties,
                            authorizationCodes.toArray(new String[authorizationCodes.size()]), accessTokens);

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

        OAuthAppDAO appDAO = new OAuthAppDAO();

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String tenantAwareLoggedInUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        AuthenticatedUser loggedInUser = buildAuthenticatedUser(tenantAwareLoggedInUserName, tenantDomain);

        String username = UserCoreUtil.addTenantDomainToEntry(tenantAwareLoggedInUserName, tenantDomain);
        String userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(loggedInUser);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while getting user store domain for User ID : " + loggedInUser;
                throw handleError(errorMsg, e);
            }
        }

        Set<String> clientIds;
        try {
            clientIds = OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                    .getAllTimeAuthorizedClientIds(loggedInUser);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while retrieving apps authorized by User ID : " + username;
            throw handleError(errorMsg, e);
        }
        Set<OAuthConsumerAppDTO> appDTOs = new HashSet<>();
        for (String clientId : clientIds) {
            Set<AccessTokenDO> accessTokenDOs;
            try {
                accessTokenDOs = OAuthTokenPersistenceFactory.getInstance()
                        .getAccessTokenDAO().getAccessTokens(clientId, loggedInUser, userStoreDomain, true);
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
                        scopedToken = OAuthTokenPersistenceFactory.getInstance().
                                getAccessTokenDAO().getLatestAccessToken(clientId,
                                loggedInUser, userStoreDomain, scopeString, true);
                        if (scopedToken != null && !distinctClientUserScopeCombo.contains(clientId + ":" + username)) {
                            OAuthAppDO appDO;
                            try {
                                appDO = appDAO.getAppInformation(scopedToken.getConsumerKey());
                                appDTOs.add(OAuthUtil.buildConsumerAppDTO(appDO));
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
        if (revokeRequestDTO.getApps() != null && revokeRequestDTO.getApps().length > 0) {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String tenantAwareLoggedInUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
            AuthenticatedUser user = buildAuthenticatedUser(tenantAwareLoggedInUserName, tenantDomain);

            String userName = UserCoreUtil.addTenantDomainToEntry(tenantAwareLoggedInUserName, tenantDomain);
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
                            // Retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                            accessTokenDOs = OAuthTokenPersistenceFactory.getInstance()
                                    .getAccessTokenDAO().getAccessTokens(appDTO.getOauthConsumerKey(),
                                            user, userStoreDomain, true);
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
                                // Retrieve latest access token for particular client, user and scope combination if
                                // its ACTIVE or EXPIRED.
                                scopedToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                                        .getLatestAccessToken(appDTO.getOauthConsumerKey(), user, userStoreDomain,
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
                                    OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                                            .revokeAccessTokens(new String[]{scopedToken.getAccessToken()});
                                } catch (IdentityOAuth2Exception e) {
                                    String errorMsg = "Error occurred while revoking " + "Access Token : " +
                                            scopedToken.getAccessToken();
                                    throw handleError(errorMsg, e);
                                }
                                //Revoking the oauth consent from database.
                                try {
                                    OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                                            .revokeOAuthConsentByApplicationAndUser(((AuthenticatedUser) authzUser)
                                                    .getAuthenticatedSubjectIdentifier(), tenantDomain, appName);
                                } catch (IdentityOAuth2Exception e) {
                                    String errorMsg = "Error occurred while removing OAuth Consent of Application " +
                                            appName + " of user " + userName;
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

        OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String tenantAwareUserName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();

        try {
            OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                    .updateApproveAlwaysForAppConsentByResourceOwner(tenantAwareUserName, tenantDomain, appName, state);
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

                    if (isImplicitGrantEnabled()) {
                        modifiableGrantSet.add(IMPLICIT);
                    }
                    allowedGrants = new ArrayList<>(modifiableGrantSet);
                }
            }
        }
        return allowedGrants.toArray(new String[allowedGrants.size()]);
    }

    private boolean isImplicitGrantEnabled() {
        Map<String, ResponseTypeHandler> responseTypeHandlers =
                OAuthServerConfiguration.getInstance().getSupportedResponseTypes();
        for (String responseType : responseTypeHandlers.keySet()) {
            if (responseType.contains(RESPONSE_TYPE_TOKEN) || responseType.contains(RESPONSE_TYPE_ID_TOKEN)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get the registered scope validators from OAuth server configuration file.
     *
     * @return List of string containing simple names of the registered validator class.
     */
    public String[] getAllowedScopeValidators() {

        if (allowedScopeValidators == null) {
            Set<OAuth2ScopeValidator> oAuth2ScopeValidators = OAuthServerConfiguration.getInstance()
                    .getOAuth2ScopeValidators();
            ArrayList<String> validators = new ArrayList<>();
            for (OAuth2ScopeValidator validator : oAuth2ScopeValidators) {
                validators.add(validator.getValidatorName());
            }
            allowedScopeValidators = validators.toArray(new String[validators.size()]);
        }
        return allowedScopeValidators;
    }

    /**
     * Get the registered oauth token types from OAuth server configuration file.
     *
     * @return List of supported oauth token types
     */
    public List<String> getSupportedTokenTypes() {

        if (supportedTokenTypes == null) {
            supportedTokenTypes = new ArrayList<>();
            Map<String, TokenIssuerDO> supportedTokenTypesMap = OAuthServerConfiguration.getInstance()
                    .getSupportedTokenIssuers();
            for (Object tokenTypeObj : supportedTokenTypesMap.keySet()) {
                supportedTokenTypes.add(tokenTypeObj.toString());
            }
        }
        return supportedTokenTypes;
    }

    /**
     * Get the renew refresh token property value from identity.xml file.
     *
     * @return renew refresh token property value
     */
    public boolean isRefreshTokenRenewalEnabled() {

        return OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();
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
        tokenExpiryTime.setIdTokenExpiryTime(OAuthServerConfiguration
                .getInstance().getOpenIDConnectIDTokenExpiryTimeInSeconds());
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

        if (oAuthConsumerAppDTO.getIdTokenExpiryTime() == 0) {
            oAuthConsumerAppDTO.setIdTokenExpiryTime(
                    OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenExpiryTimeInSeconds());
            logOnInvalidConfig(oAuthConsumerAppDTO.getApplicationName(), "id token",
                    oAuthConsumerAppDTO.getIdTokenExpiryTime());
        }
    }

    private void logOnInvalidConfig(String appName, String tokenType, long defaultValue) {

        if (log.isDebugEnabled()) {
            log.debug("Invalid expiry time value '0' set for " + tokenType + " in ServiceProvider: " + appName + ". "
                    + "Defaulting to expiry value: " + defaultValue + " seconds.");
        }
    }

    /**
     * Get the scope validators registered by the user and filter the allowed ones.
     *
     * @param application Application user have registered.
     * @return List of scope validators.
     * @throws IdentityOAuthAdminException Identity OAuthAdmin exception.
     */
    private String[] filterScopeValidators(OAuthConsumerAppDTO application) throws IdentityOAuthAdminException {

        List<String> scopeValidators = new ArrayList<>(Arrays.asList(getAllowedScopeValidators()));
        String[] requestedScopeValidators = application.getScopeValidators();
        if (requestedScopeValidators == null) {
            requestedScopeValidators = new String[0];
        }
        for (String requestedScopeValidator : requestedScopeValidators) {
            if (!scopeValidators.contains(requestedScopeValidator)) {
                throw new IdentityOAuthAdminException(requestedScopeValidator + " not allowed");
            }
        }
        return requestedScopeValidators;
    }

    /**
     * Get supported algorithms from OAuthServerConfiguration and construct an OAuthIDTokenAlgorithmDTO object.
     *
     * @return Constructed OAuthIDTokenAlgorithmDTO object with supported algorithms.
     */
    public OAuthIDTokenAlgorithmDTO getSupportedIDTokenAlgorithms() {

        OAuthIDTokenAlgorithmDTO oAuthIDTokenAlgorithmDTO = new OAuthIDTokenAlgorithmDTO();
        oAuthIDTokenAlgorithmDTO.setDefaultIdTokenEncryptionAlgorithm(
                OAuthServerConfiguration.getInstance().getDefaultIdTokenEncryptionAlgorithm());
        oAuthIDTokenAlgorithmDTO.setDefaultIdTokenEncryptionMethod(
                OAuthServerConfiguration.getInstance().getDefaultIdTokenEncryptionMethod());
        oAuthIDTokenAlgorithmDTO.setSupportedIdTokenEncryptionAlgorithms(
                OAuthServerConfiguration.getInstance().getSupportedIdTokenEncryptionAlgorithm());
        oAuthIDTokenAlgorithmDTO.setSupportedIdTokenEncryptionMethods(
                OAuthServerConfiguration.getInstance().getSupportedIdTokenEncryptionMethods());
        return oAuthIDTokenAlgorithmDTO;
    }

    /**
     * Check whether hashing oauth keys (consumer secret, access token, refresh token and authorization code)
     * configuration is disabled or not in identity.xml file.
     *
     * @return Whether hash feature is disabled or not.
     */
    public boolean isHashDisabled() {

        return OAuth2Util.isHashDisabled();
    }


    private AuthenticatedUser getAppOwner(OAuthConsumerAppDTO application,
                                          String tenantAwareLoggedInUser,
                                          String tenantDomain) throws IdentityOAuthAdminException {

        // We first set the logged in user as the owner.
        AuthenticatedUser appOwner = buildAuthenticatedUser(tenantAwareLoggedInUser, tenantDomain);

        String applicationOwnerInRequest = application.getUsername();
        if (StringUtils.isNotBlank(applicationOwnerInRequest)) {
            String tenantAwareAppOwnerInRequest = MultitenantUtils.getTenantAwareUsername(applicationOwnerInRequest);
            try {
                if (CarbonContext.getThreadLocalCarbonContext().getUserRealm().
                        getUserStoreManager().isExistingUser(tenantAwareAppOwnerInRequest)) {
                    // Since the app owner sent in OAuthConsumerAppDTO is a valid one we set the appOwner to be
                    // the one sent in the OAuthConsumerAppDTO.
                    appOwner = buildAuthenticatedUser(tenantAwareAppOwnerInRequest, tenantDomain);
                } else {
                    log.warn("OAuth application owner user name " + applicationOwnerInRequest +
                            " does not exist in the user store. Using logged-in user name " +
                            tenantAwareLoggedInUser + " as app owner name");
                }
            } catch (UserStoreException e) {
                throw handleError("Error while retrieving the user store manager for user: " +
                        applicationOwnerInRequest, e);
            }

        }
        return appOwner;
    }

    private OAuth2Service getOAuth2Service() {

        return OAuthComponentServiceHolder.getInstance().getOauth2Service();
    }

}
