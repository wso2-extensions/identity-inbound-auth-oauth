/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthAppRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthIDTokenAlgorithmDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthTokenExpiryTimeDTO;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.dto.TokenBindingMetaDataDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.oauth.Error.AUTHENTICATED_USER_NOT_FOUND;
import static org.wso2.carbon.identity.oauth.Error.INVALID_OAUTH_CLIENT;
import static org.wso2.carbon.identity.oauth.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;
import static org.wso2.carbon.identity.oauth.OAuthUtil.handleErrorWithExceptionType;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildScopeString;

/**
 * OAuth OSGi service implementation.
 */
public class OAuthAdminServiceImpl {

    public static final String IMPLICIT = "implicit";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    static final String RESPONSE_TYPE_TOKEN = "token";
    static final String RESPONSE_TYPE_ID_TOKEN = "id_token";
    static final String BINDING_TYPE_NONE = "None";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    static List<String> allowedGrants = null;
    static String[] allowedScopeValidators = null;

    protected static final Log LOG = LogFactory.getLog(OAuthAdminServiceImpl.class);
    private static final String SCOPE_VALIDATION_REGEX = "^[^?#/()]*$";
    private static final int MAX_RETRY_ATTEMPTS = 3;

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

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding a consumer secret for the logged in user:" + loggedInUser);
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
            String msg = "User not logged in to get all registered OAuth Applications.";
            if (LOG.isDebugEnabled()) {
                LOG.debug(msg);
            }
            throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, msg);
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
        try {
            OAuthAppDO app = getOAuthApp(consumerKey);
            if (app != null) {
                dto = OAuthUtil.buildConsumerAppDTO(app);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found App :" + dto.getApplicationName() + " for consumerKey: " + consumerKey);
                }
            } else {
                dto = new OAuthConsumerAppDTO();
            }
            return dto;
        } catch (InvalidOAuthClientException e) {
            String msg = "Cannot find a valid OAuth client for consumerKey: " + consumerKey;
            throw handleClientError(INVALID_OAUTH_CLIENT, msg, e);
        } catch (IdentityOAuth2Exception e) {
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
        } catch (InvalidOAuthClientException e) {
            String msg = "Cannot find a valid OAuth client with application name: " + appName;
            throw handleClientError(INVALID_OAUTH_CLIENT, msg);
        } catch (IdentityOAuth2Exception e) {
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

                validateCallbackURI(application);
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

                AuthenticatedUser defaultAppOwner = buildAuthenticatedUser(tenantAwareLoggedInUser, tenantDomain);
                AuthenticatedUser appOwner = getAppOwner(application, defaultAppOwner);
                app.setAppOwner(appOwner);

                if (application.getOAuthVersion() != null) {
                    app.setOauthVersion(application.getOAuthVersion());
                } else {   // by default, assume OAuth 2.0, if it is not set.
                    app.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
                }
                if (OAuthConstants.OAuthVersions.VERSION_2.equals(app.getOauthVersion())) {
                    validateGrantTypes(application);
                    app.setGrantTypes(application.getGrantTypes());

                    app.setScopeValidators(filterScopeValidators(application));

                    validateAudiences(application);
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
                    app.setRequestObjectSignatureValidationEnabled(
                            application.isRequestObjectSignatureValidationEnabled());

                    // Validate IdToken Encryption configurations.
                    app.setIdTokenEncryptionEnabled(application.isIdTokenEncryptionEnabled());
                    if (application.isIdTokenEncryptionEnabled()) {
                        app.setIdTokenEncryptionAlgorithm(filterIdTokenEncryptionAlgorithm(application));
                        app.setIdTokenEncryptionMethod(filterIdTokenEncryptionMethod((application)));
                    }

                    app.setBackChannelLogoutUrl(application.getBackChannelLogoutUrl());
                    app.setFrontchannelLogoutUrl(application.getFrontchannelLogoutUrl());
                    if (application.getTokenType() != null) {
                        app.setTokenType(application.getTokenType());
                    } else {
                        app.setTokenType(getDefaultTokenType());
                    }
                    app.setBypassClientCredentials(application.isBypassClientCredentials());
                    app.setRenewRefreshTokenEnabled(application.getRenewRefreshTokenEnabled());
                    validateBindingType(application.getTokenBindingType());
                    app.setTokenBindingType(application.getTokenBindingType());
                    app.setTokenBindingValidationEnabled(application.isTokenBindingValidationEnabled());
                    app.setTokenRevocationWithIDPSessionTerminationEnabled(
                            application.isTokenRevocationWithIDPSessionTerminationEnabled());
                }
                dao.addOAuthApplication(app);
                AppInfoCache.getInstance().addToCache(app.getOauthConsumerKey(), app);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Oauth Application registration success : " + application.getApplicationName() + " in " +
                            "tenant domain: " + tenantDomain);
                }
            } else {
                String message = "No application details in the request. Failed to register OAuth App.";
                if (LOG.isDebugEnabled()) {
                    LOG.debug(message);
                }
                throw handleClientError(INVALID_REQUEST, message);
            }
        } else {
            if (LOG.isDebugEnabled()) {
                if (application != null) {
                    LOG.debug("No authenticated user found. Failed to register OAuth App: " +
                            application.getApplicationName());
                } else {
                    LOG.debug("No authenticated user found. Failed to register OAuth App");
                }
            }
            String message = "No authenticated user found. Failed to register OAuth App.";
            throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, message);
        }
        return OAuthUtil.buildConsumerAppDTO(app);
    }

    private void validateAudiences(OAuthConsumerAppDTO application) throws IdentityOAuthClientException {

        if (application.getAudiences() != null) {
            // Filter out any duplicates and empty audiences here.
            long filteredAudienceSize = Arrays.stream(application.getAudiences()).filter(StringUtils::isNotBlank)
                    .distinct().count();

            if (filteredAudienceSize != application.getAudiences().length) {
                // This means we had duplicates and empty strings.
                throw handleClientError(INVALID_REQUEST, "Audience values cannot contain duplicates or empty values.");
            }
        }
    }

    private void validateGrantTypes(OAuthConsumerAppDTO application) throws IdentityOAuthClientException {

        String[] requestGrants = application.getGrantTypes().split("\\s");

        List<String> allowedGrantTypes = new ArrayList<>(Arrays.asList(getAllowedGrantTypes()));
        for (String requestedGrant : requestGrants) {
            if (StringUtils.isBlank(requestedGrant)) {
                continue;
            }

            if (!allowedGrantTypes.contains(requestedGrant)) {
                String msg = String.format("'%s' grant type is not allowed.", requestedGrant);
                throw handleClientError(INVALID_REQUEST, msg);
            }
        }
    }

    private void validateBindingType(String bindingType) throws IdentityOAuthClientException {

        if (BINDING_TYPE_NONE.equals(bindingType) || bindingType == null) {
            return;
        } else if (OAuth2ServiceComponentHolder.getInstance().getTokenBinder(bindingType).isPresent()) {
            return;
        } else {
            String msg = String.format("'%s' binding type is not allowed.", bindingType);
            throw handleClientError(INVALID_REQUEST, msg);
        }
    }

    private IdentityOAuthClientException handleClientError(Error errorMessage, String msg) {

        return new IdentityOAuthClientException(errorMessage.getErrorCode(), msg);
    }

    /**
     * Throw new IdentityOAuthClientException upon client side error in OIDC scope management.
     *
     * @param errorMessage Error message which defined under Oauth2ScopeConstants.ErrorMessages.
     * @param msg          Message
     * @return throw IdentityOAuthClientException.
     */
    private IdentityOAuthClientException handleClientError(Oauth2ScopeConstants.ErrorMessages errorMessage,
                                                           String msg) {

        return new IdentityOAuthClientException(errorMessage.getCode(), msg);
    }

    private IdentityOAuthClientException handleClientError(Error errorMessage, String msg, Exception ex) {

        return new IdentityOAuthClientException(errorMessage.getErrorCode(), msg, ex);
    }

    private void validateCallbackURI(OAuthConsumerAppDTO application) throws IdentityOAuthClientException {

        boolean isCallbackUriRequired = application.getGrantTypes().contains(AUTHORIZATION_CODE) ||
                application.getGrantTypes().contains(IMPLICIT);

        if (isCallbackUriRequired && StringUtils.isEmpty(application.getCallbackUrl())) {
            throw handleClientError(INVALID_REQUEST, "Callback URI is mandatory for Code or Implicit grant types");
        }
    }

    /**
     * Update existing consumer application.
     *
     * @param consumerAppDTO <code>OAuthConsumerAppDTO</code> with updated application information
     * @throws IdentityOAuthAdminException Error when updating the underlying identity persistence store.
     */
    public void updateConsumerApplication(OAuthConsumerAppDTO consumerAppDTO) throws IdentityOAuthAdminException {

        for (OAuthApplicationMgtListener oAuthApplicationMgtListener : OAuthComponentServiceHolder.getInstance()
                .getOAuthApplicationMgtListeners()) {
            oAuthApplicationMgtListener.doPreUpdateConsumerApplication(consumerAppDTO);
        }

        String errorMessage = "Error while updating the app information.";
        String oauthConsumerKey = consumerAppDTO.getOauthConsumerKey();

        if (StringUtils.isEmpty(oauthConsumerKey) || StringUtils.isEmpty(consumerAppDTO.getOauthConsumerSecret())) {
            errorMessage = "ConsumerKey or ConsumerSecret is not provided for updating the OAuth application.";
            if (LOG.isDebugEnabled()) {
                LOG.debug(errorMessage);
            }
            throw handleClientError(INVALID_REQUEST, errorMessage);
        }

        String loggedInUserName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantAwareLoggedInUserName = MultitenantUtils.getTenantAwareUsername(loggedInUserName);
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        OAuthAppDAO dao = new OAuthAppDAO();
        OAuthAppDO oauthappdo;
        try {
            oauthappdo = getOAuthApp(oauthConsumerKey);
            if (oauthappdo == null) {
                String msg = "OAuth application cannot be found for consumerKey: " + oauthConsumerKey;
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msg);
                }
                throw handleClientError(INVALID_OAUTH_CLIENT, msg);
            }
            if (!StringUtils.equals(consumerAppDTO.getOauthConsumerSecret(), oauthappdo.getOauthConsumerSecret())) {
                errorMessage = "Invalid ConsumerSecret is provided for updating the OAuth application with " +
                        "consumerKey: " + oauthConsumerKey;
                if (LOG.isDebugEnabled()) {
                    LOG.debug(errorMessage);
                }
                throw handleClientError(INVALID_REQUEST, errorMessage);
            }
        } catch (InvalidOAuthClientException e) {
            String msg = "Cannot find a valid OAuth client for consumerKey: " + oauthConsumerKey;
            throw handleClientError(INVALID_OAUTH_CLIENT, msg, e);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while updating the app information.", e);
        }

        AuthenticatedUser defaultAppOwner = oauthappdo.getAppOwner();
        AuthenticatedUser appOwner = getAppOwner(consumerAppDTO, defaultAppOwner);
        oauthappdo.setAppOwner(appOwner);

        oauthappdo.setOauthConsumerKey(oauthConsumerKey);
        oauthappdo.setOauthConsumerSecret(consumerAppDTO.getOauthConsumerSecret());

        validateCallbackURI(consumerAppDTO);
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
            validateGrantTypes(consumerAppDTO);
            oauthappdo.setGrantTypes(consumerAppDTO.getGrantTypes());

            validateAudiences(consumerAppDTO);
            oauthappdo.setAudiences(consumerAppDTO.getAudiences());
            oauthappdo.setScopeValidators(filterScopeValidators(consumerAppDTO));
            oauthappdo.setRequestObjectSignatureValidationEnabled(consumerAppDTO
                    .isRequestObjectSignatureValidationEnabled());

            // Validate IdToken Encryption configurations.
            oauthappdo.setIdTokenEncryptionEnabled(consumerAppDTO.isIdTokenEncryptionEnabled());
            if (consumerAppDTO.isIdTokenEncryptionEnabled()) {
                oauthappdo.setIdTokenEncryptionAlgorithm(filterIdTokenEncryptionAlgorithm(consumerAppDTO));
                oauthappdo.setIdTokenEncryptionMethod(filterIdTokenEncryptionMethod((consumerAppDTO)));
            }

            oauthappdo.setBackChannelLogoutUrl(consumerAppDTO.getBackChannelLogoutUrl());
            oauthappdo.setFrontchannelLogoutUrl(consumerAppDTO.getFrontchannelLogoutUrl());
            oauthappdo.setRenewRefreshTokenEnabled(consumerAppDTO.getRenewRefreshTokenEnabled());
            validateBindingType(consumerAppDTO.getTokenBindingType());
            oauthappdo.setTokenBindingType(consumerAppDTO.getTokenBindingType());
            oauthappdo.setTokenRevocationWithIDPSessionTerminationEnabled(consumerAppDTO
                    .isTokenRevocationWithIDPSessionTerminationEnabled());
            oauthappdo.setTokenBindingValidationEnabled(consumerAppDTO.isTokenBindingValidationEnabled());
        }
        dao.updateConsumerApplication(oauthappdo);
        AppInfoCache.getInstance().addToCache(oauthappdo.getOauthConsumerKey(), oauthappdo);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Oauth Application update success : " + consumerAppDTO.getApplicationName() + " in " +
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
     * @deprecated use {@link #addScope(ScopeDTO)} instead.
     */
    @Deprecated
    public void addScope(String scope, String[] claims) throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            if (StringUtils.isNotEmpty(scope)) {
                validateRegex(scope);
                OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().addScope(tenantId, scope, claims);
            } else {
                throw handleClientError(INVALID_REQUEST, "The scope can not be empty.");
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while inserting OIDC scopes and claims.", e);
        }
    }

    /**
     * Add an oidc scope and it's claims to the related db tables.
     *
     * @param scope An oidc scope.
     * @throws IdentityOAuthAdminException If an error occurs when inserting scopes or claims.
     */
    public void addScope(ScopeDTO scope) throws IdentityOAuthAdminException {

        addScopePreValidation(scope);

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().addScope(scope, tenantId);
        } catch (IdentityOAuth2Exception e) {
            throw handleErrorWithExceptionType(String.format("Error while inserting OIDC scope: %s, %s",
                    scope.getName(), e.getMessage()), e);
        }
    }

    /**
     * To retrieve all persisted oidc scopes with mapped claims.
     *
     * @return all persisted scopes and claims
     * @throws IdentityOAuthAdminException if an error occurs when loading scopes and claims.
     */
    public ScopeDTO[] getScopes() throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            List<ScopeDTO> scopeDTOList = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getScopes(tenantId);
            if (CollectionUtils.isNotEmpty(scopeDTOList)) {
                return scopeDTOList.toArray(new ScopeDTO[scopeDTOList.size()]);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not find scope claim mapping. Hence returning an empty array.");
                }
                return new ScopeDTO[0];
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while loading OIDC scopes and claims for tenant: " + tenantId, e);
        }
    }

    /**
     * Get persisted oidc scope with mapped claims.
     *
     * @return Get a persisted scope and it's mapped claims.
     * @throws IdentityOAuthAdminException If an error occurs when loading scope and claims.
     */
    public ScopeDTO getScope(String scopeName) throws IdentityOAuthAdminException {

        validateScopeName(scopeName);

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            ScopeDTO scopeDTO = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getScope(scopeName, tenantId);

            // If scopeDTO is null then the requested scope is not exist.
            if (scopeDTO == null) {
                throw handleClientError(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE,
                        String.format(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getMessage(),
                                scopeName));
            }
            return scopeDTO;
        } catch (IdentityOAuth2Exception e) {
            throw handleErrorWithExceptionType(String.format("Error while loading OIDC scope: %s for tenant %s",
                    scopeName, tenantId), e);
        }
    }

    /**
     * To remove persisted scopes and claims.
     *
     * @param scope oidc scope
     * @throws IdentityOAuthAdminException if an error occurs when deleting scopes and claims.
     */
    public void deleteScope(String scope) throws IdentityOAuthAdminException {

        validateScopeName(scope);
        // Check whether a scope exists with the provided scope name which to be deleted.
        validateScopeExistence(scope);

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().deleteScope(scope, tenantId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Scope: " + scope + " is deleted from the database.");
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleErrorWithExceptionType("Error while deleting OIDC scope: " + scope, e);
        }
    }

    /**
     * To retrieve all persisted oidc scopes.
     *
     * @return list of scopes persisted.
     * @throws IdentityOAuthAdminException if an error occurs when loading oidc scopes.
     */
    public String[] getScopeNames() throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            List<String> scopeDTOList = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getScopeNames(tenantId);
            if (CollectionUtils.isNotEmpty(scopeDTOList)) {
                return scopeDTOList.toArray(new String[scopeDTOList.size()]);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not load oidc scopes. Hence returning an empty array.");
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
     * @throws IdentityOAuthAdminException if an error occurs when lading oidc claims.
     */
    public String[] getClaims(String scope) throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            ScopeDTO scopeDTO = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getClaims(scope, tenantId);
            if (scopeDTO != null && ArrayUtils.isNotEmpty(scopeDTO.getClaim())) {
                return scopeDTO.getClaim();
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not load oidc claims. Hence returning an empty array.");
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
     * @throws IdentityOAuthAdminException if an error occurs when adding a new claim for a scope.
     * @deprecated use {@link #updateScope(ScopeDTO)} instead.
     */
    @Deprecated
    public void updateScope(String scope, String[] addClaims, String[] deleteClaims)
            throws IdentityOAuthAdminException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    updateScope(scope, tenantId, Arrays.asList(addClaims), Arrays.asList(deleteClaims));
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while updating OIDC claims for the scope: " + scope + " in tenant: " + tenantId,
                    e);
        }
    }

    /**
     * Update an existing scope.
     *
     * @param updatedScope Updated scope name.
     * @throws IdentityOAuthAdminException If an error occurs when adding a new claim for a scope.
     */
    public void updateScope(ScopeDTO updatedScope) throws IdentityOAuthAdminException {

        updateScopePreValidation(updatedScope);
        // Check whether a scope exists with the provided scope name which to be deleted.
        validateScopeExistence(updatedScope.getName());

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    updateScope(updatedScope, tenantId);
        } catch (IdentityOAuth2Exception e) {
            throw handleErrorWithExceptionType(String.format("Error while updating the scope: %s in tenant: %s",
                    updatedScope.getName(), tenantId), e);
        }
    }

    /**
     * To load id of the scope table.
     *
     * @param scope scope name
     * @return id of the given scope
     * @throws IdentityOAuthAdminException if an error occurs when loading scope id.
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

        for (OAuthApplicationMgtListener oAuthApplicationMgtListener : OAuthComponentServiceHolder.getInstance()
                .getOAuthApplicationMgtListeners()) {
            oAuthApplicationMgtListener.doPreUpdateConsumerApplicationState(consumerKey, newState);
        }

        try {
            OAuthAppDO oAuthAppDO = getOAuthApp(consumerKey);
            // change the state
            oAuthAppDO.setState(newState);

            Properties properties = new Properties();
            properties.setProperty(OAuthConstants.OAUTH_APP_NEW_STATE, newState);
            properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REVOKE);

            AppInfoCache.getInstance().clearCacheEntry(consumerKey);
            updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);

            if (LOG.isDebugEnabled()) {
                LOG.debug("App state is updated to:" + newState + " in the AppInfoCache for OAuth App with " +
                        "consumerKey: " + consumerKey);
            }

        } catch (InvalidOAuthClientException e) {
            String msg = "Error while updating state of OAuth app with consumerKey: " + consumerKey;
            throw handleClientError(INVALID_OAUTH_CLIENT, msg, e);
        } catch (IdentityOAuth2Exception e) {
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

        Properties properties = new Properties();
        String newSecret = OAuthUtil.getRandomNumber();
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY, newSecret);
        properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REGENERATE);
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_STATE, APP_STATE_ACTIVE);

        AppInfoCache.getInstance().clearCacheEntry(consumerKey);
        updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client Secret for OAuth app with consumerKey: " + consumerKey + " updated in OAuthCache.");
        }

        OAuthConsumerAppDTO updatedApplication = getOAuthApplicationData(consumerKey);
        updatedApplication.setOauthConsumerSecret(newSecret);

        return updatedApplication;

    }

    void updateAppAndRevokeTokensAndAuthzCodes(String consumerKey,
                                               Properties properties) throws IdentityOAuthAdminException {

        int countToken = 0;
        try {
            Set<AccessTokenDO> activeDetailedTokens = OAuthTokenPersistenceFactory
                    .getInstance().getAccessTokenDAO().getActiveAcessTokenDataByConsumerKey(consumerKey);
            String[] accessTokens = new String[activeDetailedTokens.size()];

            for (AccessTokenDO detailToken : activeDetailedTokens) {
                String token = detailToken.getAccessToken();
                accessTokens[countToken] = token;
                countToken++;

                OAuthCacheKey cacheKeyToken = new OAuthCacheKey(token);
                OAuthCache.getInstance().clearCacheEntry(cacheKeyToken);

                String scope = buildScopeString(detailToken.getScope());
                String authorizedUser = detailToken.getAuthzUser().getUserId();
                String authenticatedIDP = detailToken.getAuthzUser().getFederatedIdPName();
                boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
                String cacheKeyString;
                if (isUsernameCaseSensitive) {
                    cacheKeyString = consumerKey + ":" + authorizedUser + ":" + scope + ":" + authenticatedIDP;
                } else {
                    cacheKeyString = consumerKey + ":" + authorizedUser.toLowerCase() + ":" + scope + ":"
                            + authenticatedIDP;
                }
                OAuthCacheKey cacheKeyUser = new OAuthCacheKey(cacheKeyString);
                OAuthCache.getInstance().clearCacheEntry(cacheKeyUser);
                String tokenBindingRef = NONE;
                if (detailToken.getTokenBinding() != null) {
                    tokenBindingRef = detailToken.getTokenBinding().getBindingReference();
                }
                OAuthUtil.clearOAuthCache(consumerKey, detailToken.getAuthzUser(),
                        OAuth2Util.buildScopeString(detailToken.getScope()), tokenBindingRef);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Access tokens and token of users are removed from the cache for OAuth App with " +
                        "consumerKey: " + consumerKey);
            }

            Set<String> authorizationCodes = OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                    .getActiveAuthorizationCodesByConsumerKey(consumerKey);
            for (String authorizationCode : authorizationCodes) {
                OAuthCacheKey cacheKey = new OAuthCacheKey(authorizationCode);
                OAuthCache.getInstance().clearCacheEntry(cacheKey);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Access tokens are removed from the cache for OAuth App with consumerKey: " + consumerKey);
            }

            OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                    .updateAppAndRevokeTokensAndAuthzCodes(
                            consumerKey, properties, authorizationCodes.toArray(
                                    new String[0]), accessTokens);

        } catch (IdentityOAuth2Exception | IdentityApplicationManagementException | UserIdNotFoundException e) {
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

        for (OAuthApplicationMgtListener oAuthApplicationMgtListener : OAuthComponentServiceHolder.getInstance()
                .getOAuthApplicationMgtListeners()) {
            oAuthApplicationMgtListener.doPreRemoveOAuthApplicationData(consumerKey);
        }

        OAuthAppDAO dao = new OAuthAppDAO();
        try {
            dao.removeConsumerApplication(consumerKey);
        } catch (IdentityOAuthAdminException e) {
            /*
             * For more information read https://github.com/wso2/product-is/issues/12579. This is to overcome the
             * above issue.
             */
            LOG.error(String.format("Error occurred when trying to remove OAuth application date for the " +
                    "application with consumer key: %s. Therefore retrying again.", consumerKey), e);
            boolean isOperationFailed = true;
            for (int attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
                try {
                    Thread.sleep(1000);
                    dao.removeConsumerApplication(consumerKey);
                    isOperationFailed = false;
                    LOG.info(String.format("Oauth application data deleted for the application with consumer key: %s " +
                            "during the retry attempt: %s", consumerKey, attempt));
                    break;
                } catch (Exception exception) {
                    LOG.error(String.format("Retry attempt: %s failed to delete OAuth application data for " +
                            "application with the consumer key: %s", attempt, consumerKey), exception);
                }
            }
            if (isOperationFailed) {
                throw new IdentityOAuthAdminException("Error occurred while deleting OAuth2 application " +
                        "data for application with consumer key: " + consumerKey, e);
            }
        }
        // Remove client credentials from cache.
        OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(consumerKey));
        AppInfoCache.getInstance().clearCacheEntry(consumerKey);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client credentials are removed from the cache for OAuth App with consumerKey: " + consumerKey);
        }

    }

    /**
     * Remove all OAuth consumer applications of a tenant.
     *
     * @param tenantId Id of the tenant
     * @throws IdentityOAuthAdminException
     */
    public void removeAllOAuthApplicationData(int tenantId) throws IdentityOAuthAdminException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Deleting all OAuth Application data of the tenant: " + tenantId);
        }

        OAuthAppDAO dao = new OAuthAppDAO();
        dao.removeConsumerApplicationsByTenantId(tenantId);
    }

    /**
     * Get apps that are authorized by the given user
     *
     * @return OAuth applications authorized by the user that have tokens in ACTIVE or EXPIRED state
     */
    public OAuthConsumerAppDTO[] getAppsAuthorizedByUser() throws IdentityOAuthAdminException {

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
        Set<OAuthConsumerAppDTO> appDTOs = new HashSet<OAuthConsumerAppDTO>();
        for (String clientId : clientIds) {
            Set<AccessTokenDO> accessTokenDOs;
            try {
                accessTokenDOs = OAuthTokenPersistenceFactory.getInstance()
                        .getAccessTokenDAO().getAccessTokens(
                                clientId, loggedInUser, userStoreDomain, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while retrieving access tokens issued for " +
                        "Client ID : " + clientId + ", User ID : " + username;
                throw handleError(errorMsg, e);
            }
            if (!accessTokenDOs.isEmpty()) {
                Set<String> distinctClientUserScopeCombo = new HashSet<String>();
                for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                    AccessTokenDO scopedToken;
                    String scopeString = buildScopeString(accessTokenDO.getScope());
                    try {
                        scopedToken = OAuthTokenPersistenceFactory.getInstance().
                                getAccessTokenDAO().getLatestAccessToken(clientId, loggedInUser, userStoreDomain,
                                scopeString, true);
                        if (scopedToken != null && !distinctClientUserScopeCombo.contains(clientId + ":" + username)) {
                            OAuthAppDO appDO = getOAuthAppDO(scopedToken.getConsumerKey());
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Found App: " + appDO.getApplicationName() + " for user: " + username);
                            }
                            appDTOs.add(OAuthUtil.buildConsumerAppDTO(appDO));
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
        return appDTOs.toArray(new OAuthConsumerAppDTO[0]);
    }

    private OAuthAppDO getOAuthAppDO(String consumerKey) throws IdentityOAuthAdminException {

        OAuthAppDO appDO;
        try {
            appDO = getOAuthApp(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw handleClientError(INVALID_OAUTH_CLIENT, "Invalid ConsumerKey: " + consumerKey, e);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while retrieving app information for Client ID : " + consumerKey, e);
        }
        return appDO;
    }

    /**
     * Revoke authorization for OAuth apps by resource owners
     *
     * @param revokeRequestDTO DTO representing authorized user and apps[]
     * @return revokeRespDTO DTO representing success or failure message
     */
    public OAuthRevocationResponseDTO revokeAuthzForAppsByResourceOwner(
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
                            // Retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this
                            // user
                            accessTokenDOs = OAuthTokenPersistenceFactory.getInstance()
                                    .getAccessTokenDAO().getAccessTokens(
                                            appDTO.getOauthConsumerKey(), user, userStoreDomain, true);
                        } catch (IdentityOAuth2Exception e) {
                            String errorMsg = "Error occurred while retrieving access tokens issued for " +
                                    "Client ID : " + appDTO.getOauthConsumerKey() + ", User ID : " + userName;
                            throw handleError(errorMsg, e);
                        }
                        AuthenticatedUser authzUser;
                        for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                            //Clear cache with AccessTokenDO
                            authzUser = accessTokenDO.getAuthzUser();

                            String tokenBindingReference = NONE;
                            if (accessTokenDO.getTokenBinding() != null && StringUtils
                                    .isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
                                tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
                            }
                            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), authzUser,
                                    buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), authzUser,
                                    buildScopeString(accessTokenDO.getScope()));
                            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), authzUser);
                            OAuthUtil.clearOAuthCache(accessTokenDO);
                            AccessTokenDO scopedToken;
                            try {
                                // Retrieve latest access token for particular client, user and scope combination if
                                // its ACTIVE or EXPIRED.
                                scopedToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                                        .getLatestAccessToken(
                                                appDTO.getOauthConsumerKey(), user,
                                                userStoreDomain,
                                                buildScopeString(
                                                        accessTokenDO.getScope()),
                                                true);
                            } catch (IdentityOAuth2Exception e) {
                                String errorMsg = "Error occurred while retrieving latest " +
                                        "access token issued for Client ID : " +
                                        appDTO.getOauthConsumerKey() + ", User ID : " + userName +
                                        " and Scope : " + buildScopeString(accessTokenDO.getScope());
                                throw handleError(errorMsg, e);
                            }
                            if (scopedToken != null) {
                                //Revoking token from database
                                try {
                                    OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                                            .revokeAccessTokens(new String[]{scopedToken
                                                    .getAccessToken()});
                                } catch (IdentityOAuth2Exception e) {
                                    String errorMsg = "Error occurred while revoking " + "Access Token : " +
                                            scopedToken.getAccessToken();
                                    throw handleError(errorMsg, e);
                                }
                                //Revoking the oauth consent from database.
                                try {
                                    OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                                            .revokeOAuthConsentByApplicationAndUser(
                                                    authzUser.getAuthenticatedSubjectIdentifier(),
                                                    tenantDomain, appName);
                                } catch (IdentityOAuth2Exception e) {
                                    String errorMsg = "Error occurred while removing OAuth Consent of Application: " +
                                            appName + " of user: " + userName;
                                    throw handleError(errorMsg, e);
                                }
                            }
                            triggerPostRevokeListeners(revokeRequestDTO, new OAuthRevocationResponseDTO
                                    (), accessTokenDOs.toArray(new AccessTokenDO[0]));
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
     * Revoke issued tokens for the application.
     *
     * @param application {@link OAuthAppRevocationRequestDTO}
     * @return revokeRespDTO {@link OAuthAppRevocationRequestDTO}
     * @throws IdentityOAuthAdminException Error while revoking the issued tokens
     */
    public OAuthRevocationResponseDTO revokeIssuedTokensByApplication(OAuthAppRevocationRequestDTO application)
            throws IdentityOAuthAdminException {

        triggerPreApplicationTokenRevokeListeners(application);
        OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
        String consumerKey = application.getConsumerKey();

        if (StringUtils.isBlank(consumerKey)) {
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
            revokeRespDTO.setErrorMsg("Consumer key is null or empty.");
            triggerPostApplicationTokenRevokeListeners(application, revokeRespDTO, new ArrayList<>());
            return revokeRespDTO;
        }

        String tenantDomain = getTenantDomain(consumerKey);
        String applicationName = getApplicationName(consumerKey, tenantDomain);
        List<AccessTokenDO> accessTokenDOs = getActiveAccessTokensByConsumerKey(consumerKey);
        if (accessTokenDOs.size() > 0) {
            String[] accessTokens = new String[accessTokenDOs.size()];
            int count = 0;
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                accessTokens[count++] = accessTokenDO.getAccessToken();
                clearCacheByAccessTokenAndConsumerKey(accessTokenDO, consumerKey);
            }

            if (LOG.isDebugEnabled()) {
                String message = String.format("Access tokens and token of users are removed from the cache for " +
                        "OAuth app in tenant domain: %s with consumer key: %s.", tenantDomain, consumerKey);
                LOG.debug(message);
            }

            revokeAccessTokens(accessTokens, consumerKey, tenantDomain);
            revokeOAuthConsentsForApplication(applicationName, tenantDomain);
        }
        triggerPostApplicationTokenRevokeListeners(application, revokeRespDTO, accessTokenDOs);
        return revokeRespDTO;
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
                    .updateApproveAlwaysForAppConsentByResourceOwner(tenantAwareUserName,
                            tenantDomain, appName, state);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while revoking OAuth Consent approve always of Application " + appName +
                    " of user " + tenantAwareUserName;
            LOG.error(errorMsg, e);
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.INVALID_REQUEST);
            revokeRespDTO.setErrorMsg("Invalid revocation request");
        }
        return revokeRespDTO;
    }

    void triggerPreRevokeListeners(OAuthRevocationRequestDTO
                                           revokeRequestDTO) throws IdentityOAuthAdminException {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<String, Object>();
                oAuthEventInterceptorProxy.onPreTokenRevocationByResourceOwner(revokeRequestDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error occurred with Oauth pre-revoke listener ", e);
            }
        }
    }

    void triggerPostRevokeListeners(OAuthRevocationRequestDTO revokeRequestDTO,
                                    OAuthRevocationResponseDTO revokeRespDTO, AccessTokenDO[] accessTokenDOs) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        for (AccessTokenDO accessTokenDO : accessTokenDOs) {
            if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
                try {
                    Map<String, Object> paramMap = new HashMap<String, Object>();
                    oAuthEventInterceptorProxy.onPostTokenRevocationByResourceOwner(revokeRequestDTO, revokeRespDTO,
                            accessTokenDO, paramMap);
                } catch (IdentityOAuth2Exception e) {
                    LOG.error("Error occurred with post revocation listener.", e);
                }
            }
        }
    }

    private void triggerPreApplicationTokenRevokeListeners(OAuthAppRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuthAdminException {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            try {
                oAuthEventInterceptorProxy.onPreTokenRevocationByApplication(revokeRequestDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error occurred when triggering pre revocation listener.", e);
            }
        }
    }

    private void triggerPostApplicationTokenRevokeListeners(OAuthAppRevocationRequestDTO revokeRequestDTO,
                                                            OAuthRevocationResponseDTO revokeRespDTO,
                                                            List<AccessTokenDO> accessTokenDOs)
            throws IdentityOAuthAdminException {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            try {
                oAuthEventInterceptorProxy.onPostTokenRevocationByApplication(revokeRequestDTO, revokeRespDTO,
                        accessTokenDOs, paramMap);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error occurred when triggering post revocation listener.", e);
            }
        }
    }

    private List<AccessTokenDO> getActiveAccessTokensByConsumerKey(String consumerKey)
            throws IdentityOAuthAdminException {

        List<AccessTokenDO> accessTokenDOs;
        try {
            accessTokenDOs = new ArrayList<>(OAuthTokenPersistenceFactory
                    .getInstance().getAccessTokenDAO().getActiveAcessTokenDataByConsumerKey(consumerKey));
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = String.format("Error occurred while retrieving access tokens issued for OAuth " +
                    "app with consumer key: %s.", consumerKey);
            throw handleError(errorMsg, e);
        }
        return accessTokenDOs;
    }

    private void revokeAccessTokens(String[] accessTokens, String consumerKey, String tenantDomain)
            throws IdentityOAuthAdminException {

        try {
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .revokeAccessTokens(accessTokens, OAuth2Util.isHashEnabled());
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = String.format("Error occurred while revoking access tokens for OAuth app in " +
                    "tenant domain: %s with consumer key: %s.", tenantDomain, consumerKey);
            throw handleError(errorMsg, e);
        }
    }

    private String getTenantDomain(String consumerKey) throws IdentityOAuthAdminException {

        String tenantDomain;
        try {
            tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(consumerKey);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = String.format("Error occurred while retrieving tenant domain of OAuth app with " +
                    "consumer key: %s.", consumerKey);
            throw handleError(errorMsg, e);
        } catch (InvalidOAuthClientException e) {
            String errorMsg = String.format("Cannot find a valid OAuth app with consumer key: %s.", consumerKey);
            if (LOG.isDebugEnabled()) {
                LOG.debug(errorMsg, e);
            }
            throw handleClientError(INVALID_OAUTH_CLIENT, errorMsg);
        }
        return tenantDomain;
    }

    private String getApplicationName(String consumerKey, String tenantDomain)
            throws IdentityOAuthAdminException {

        String applicationName;
        try {
            ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder
                    .getApplicationMgtService();
            applicationName = applicationMgtService
                    .getServiceProviderNameByClientId(consumerKey, INBOUND_AUTH2_TYPE, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            String errorMsg = String.format("Error occurred while retrieving application name for OAuth app in " +
                    "tenant domain: %s with consumer key: %s.", tenantDomain, consumerKey);
            throw handleError(errorMsg, e);
        }
        return applicationName;
    }

    private void clearCacheByAccessTokenAndConsumerKey(AccessTokenDO accessTokenDO, String consumerKey) {

        String token = accessTokenDO.getAccessToken();
        AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();

        OAuthCacheKey cacheKeyToken = new OAuthCacheKey(token);
        String scope = buildScopeString(accessTokenDO.getScope());
        TokenBinding tokenBinding = accessTokenDO.getTokenBinding();
        String tokenBindingReference = (tokenBinding != null &&
                StringUtils.isNotBlank(tokenBinding.getBindingReference())) ?
                tokenBinding.getBindingReference() : NONE;

        OAuthCache.getInstance().clearCacheEntry(cacheKeyToken);
        OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser, scope, tokenBindingReference);
        OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser, scope);
        OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser);
        OAuthUtil.clearOAuthCache(accessTokenDO);
    }

    private void revokeOAuthConsentsForApplication(String applicationName, String tenantDomain)
            throws IdentityOAuthAdminException {

        try {
            OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                    .revokeOAuthConsentsByApplication(applicationName, tenantDomain);
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = String.format("Error occurred while revoking all OAuth consents given for " +
                    "application: %s in tenant domain: %s.", applicationName, tenantDomain);
            throw handleError(errorMsg, e);
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
                    allowedGrants = new ArrayList<String>(modifiableGrantSet);
                }
            }
        }
        return allowedGrants.toArray(new String[allowedGrants.size()]);
    }

    boolean isImplicitGrantEnabled() {

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
            ArrayList<String> validators = new ArrayList<String>();
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

        return OAuthServerConfiguration.getInstance().getSupportedTokenTypes();
    }

    /**
     * Return the default token type.
     */
    public String getDefaultTokenType() {

        return OAuthServerConfiguration.DEFAULT_TOKEN_TYPE;
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

    /**
     * Get supported token bindings meta data.
     *
     * @return list of TokenBindingMetaDataDTOs.
     */
    public List<TokenBindingMetaDataDTO> getSupportedTokenBindingsMetaData() {

        return OAuthComponentServiceHolder.getInstance().getTokenBindingMetaDataDTOs();
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

    AuthenticatedUser buildAuthenticatedUser(String tenantAwareUser, String tenantDomain) {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUser));
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(IdentityUtil.extractDomainFromName(tenantAwareUser));
        return user;
    }

    void validateTokenExpiryConfigurations(OAuthConsumerAppDTO oAuthConsumerAppDTO) {

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

    void logOnInvalidConfig(String appName, String tokenType, long defaultValue) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Invalid expiry time value '0' set for token type: " + tokenType + " in ServiceProvider: " +
                    appName + ". Defaulting to expiry value: " + defaultValue + " seconds.");
        }
    }

    /**
     * Get the scope validators registered by the user and filter the allowed ones.
     *
     * @param application Application user have registered.
     * @return List of scope validators.
     * @throws IdentityOAuthAdminException Identity OAuthAdmin exception.
     */
    String[] filterScopeValidators(OAuthConsumerAppDTO application) throws IdentityOAuthAdminException {

        List<String> scopeValidators = new ArrayList<String>(Arrays.asList(getAllowedScopeValidators()));
        String[] requestedScopeValidators = application.getScopeValidators();
        if (requestedScopeValidators == null) {
            requestedScopeValidators = new String[0];
        }
        for (String requestedScopeValidator : requestedScopeValidators) {
            if (!scopeValidators.contains(requestedScopeValidator)) {
                String msg = String.format("'%s' scope validator is not allowed.", requestedScopeValidator);
                throw handleClientError(INVALID_REQUEST, msg);
            }
        }
        return requestedScopeValidators;
    }


    /**
     * Get the IdToken Encryption Method registered by the user and filter the allowed one.
     *
     * @param application Application user have registered
     * @return idTokenEncryptionMethod
     * @throws IdentityOAuthAdminException Identity OAuthAdmin exception.
     */
    private String filterIdTokenEncryptionMethod(OAuthConsumerAppDTO application) throws IdentityOAuthAdminException {

        List<String> supportedIdTokenEncryptionMethods = OAuthServerConfiguration.getInstance()
                .getSupportedIdTokenEncryptionMethods();
        String idTokenEncryptionMethod = application.getIdTokenEncryptionMethod();
        if (!supportedIdTokenEncryptionMethods.contains(idTokenEncryptionMethod)) {
            String msg = String.format("'%s' IdToken Encryption Method is not allowed.", idTokenEncryptionMethod);
            throw handleClientError(INVALID_REQUEST, msg);
        }
        return idTokenEncryptionMethod;
    }

    /**
     * Get the IdToken Encryption Algorithm registered by the user and filter the allowed one.
     *
     * @param application Application user have registered
     * @return idTokenEncryptionAlgorithm
     * @throws IdentityOAuthAdminException Identity OAuthAdmin exception.
     */
    private String filterIdTokenEncryptionAlgorithm(OAuthConsumerAppDTO application)
            throws IdentityOAuthAdminException {

        List<String> supportedIdTokenEncryptionAlgorithms = OAuthServerConfiguration.getInstance()
                .getSupportedIdTokenEncryptionAlgorithm();
        String idTokenEncryptionAlgorithm = application.getIdTokenEncryptionAlgorithm();
        if (!supportedIdTokenEncryptionAlgorithms.contains(idTokenEncryptionAlgorithm)) {
            String msg = String.format("'%s' IdToken Encryption Method is not allowed.", idTokenEncryptionAlgorithm);
            throw handleClientError(INVALID_REQUEST, msg);
        }
        return idTokenEncryptionAlgorithm;
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

    AuthenticatedUser getAppOwner(OAuthConsumerAppDTO application,
                                  AuthenticatedUser defaultAppOwner) throws IdentityOAuthAdminException {

        // We first set the logged in user as the owner.
        AuthenticatedUser appOwner = defaultAppOwner;
        String applicationOwnerInRequest = application.getUsername();
        if (StringUtils.isNotBlank(applicationOwnerInRequest)) {
            String tenantAwareAppOwnerInRequest = MultitenantUtils.getTenantAwareUsername(applicationOwnerInRequest);
            try {
                if (CarbonContext.getThreadLocalCarbonContext().getUserRealm().
                        getUserStoreManager().isExistingUser(tenantAwareAppOwnerInRequest)) {
                    // Since the app owner sent in OAuthConsumerAppDTO is a valid one we set the appOwner to be
                    // the one sent in the OAuthConsumerAppDTO.
                    String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                    appOwner = buildAuthenticatedUser(tenantAwareAppOwnerInRequest, tenantDomain);
                } else {
                    LOG.warn("OAuth application owner user name " + applicationOwnerInRequest +
                            " does not exist in the user store. Using user: " +
                            defaultAppOwner.toFullQualifiedUsername() + " as app owner.");
                }
            } catch (UserStoreException e) {
                throw handleError("Error while retrieving the user store manager for user: " +
                        applicationOwnerInRequest, e);
            }

        }
        return appOwner;
    }

    OAuth2Service getOAuth2Service() {

        return OAuthComponentServiceHolder.getInstance().getOauth2Service();
    }

    OAuthAppDO getOAuthApp(String consumerKey) throws InvalidOAuthClientException, IdentityOAuth2Exception {

        OAuthAppDO oauthApp = AppInfoCache.getInstance().getValueFromCache(consumerKey);
        if (oauthApp != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth app with consumerKey: " + consumerKey + " retrieved from AppInfoCache.");
            }
            return oauthApp;
        }

        OAuthAppDAO dao = new OAuthAppDAO();
        oauthApp = dao.getAppInformation(consumerKey);
        if (oauthApp != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth app with consumerKey: " + consumerKey + " retrieved from database.");
            }
            AppInfoCache.getInstance().addToCache(consumerKey, oauthApp);
        }

        return oauthApp;
    }

    /**
     * Scope validation before adding the scope.
     *
     * @param scope Scope.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void addScopePreValidation(ScopeDTO scope) throws IdentityOAuthClientException {

        validateScopeName(scope.getName());
        validateRegex(scope.getName());
        validateDisplayName(scope.getDisplayName());
    }

    /**
     * Do the validation before updating the scope.
     *
     * @param updatedScope Updated scope.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void updateScopePreValidation(ScopeDTO updatedScope) throws IdentityOAuthClientException {

        validateScopeName(updatedScope.getName());
        validateDisplayName(updatedScope.getDisplayName());
    }

    /**
     * Check whether scope name is provided or not.
     *
     * @param scopeName Scope name.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateScopeName(String scopeName) throws IdentityOAuthClientException {

        // Check whether the scope name is provided.
        if (StringUtils.isBlank(scopeName)) {
            throw handleClientError(INVALID_REQUEST, Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED.getMessage());
        }
        validateWhiteSpaces(scopeName);
    }

    private void validateRegex(String scopeName) throws IdentityOAuthClientException {

        Pattern regexPattern = Pattern.compile(SCOPE_VALIDATION_REGEX);
        if (!regexPattern.matcher(scopeName).matches()) {
            String message = "Invalid scope name. Scope name : " + scopeName + " cannot contain special characters " +
                    "?,#,/,( or )";
            throw handleClientError(INVALID_REQUEST, message);
        }
    }

    /**
     * Check whether scope name contains any white spaces.
     *
     * @param scopeName Scope name.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateWhiteSpaces(String scopeName) throws IdentityOAuthClientException {

        // Check whether the scope name contains any white spaces.
        Pattern pattern = Pattern.compile("\\s");
        Matcher matcher = pattern.matcher(scopeName);
        boolean foundWhiteSpace = matcher.find();

        if (foundWhiteSpace) {
            throw handleClientError(INVALID_REQUEST, String.format(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_CONTAINS_WHITESPACES.getMessage(), scopeName));
        }
    }

    /**
     * Check whether display name is provided or empty.
     *
     * @param displayName Display name.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateDisplayName(String displayName) throws IdentityOAuthClientException {

        // Check whether the scope display name is provided.
        if (StringUtils.isBlank(displayName)) {
            throw handleClientError(INVALID_REQUEST,
                    Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_NOT_SPECIFIED
                            .getMessage());
        }
    }

    /**
     * Check whether scope exist or not, if scope does not exist trow not found error.
     *
     * @param scopeName Scope name.
     * @throws IdentityOAuth2ScopeException
     */
    private void validateScopeExistence(String scopeName) throws IdentityOAuthAdminException {

        boolean isScopeExists = isScopeExist(scopeName);
        if (!isScopeExists) {
            throw handleClientError(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE,
                    String.format(Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_NOT_FOUND_SCOPE.getMessage(),
                            scopeName));
        }
    }
}
