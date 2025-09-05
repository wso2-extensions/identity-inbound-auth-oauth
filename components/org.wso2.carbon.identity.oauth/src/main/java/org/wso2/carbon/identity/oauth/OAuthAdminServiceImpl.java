/*
 * Copyright (c) 2019-2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.httpclient.HttpsURL;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
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
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuditLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.LogConstants.TARGET_APPLICATION;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.LogConstants.USER;
import static org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils.triggerAuditLogEvent;
import static org.wso2.carbon.identity.oauth.Error.AUTHENTICATED_USER_NOT_FOUND;
import static org.wso2.carbon.identity.oauth.Error.INVALID_OAUTH_CLIENT;
import static org.wso2.carbon.identity.oauth.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.oauth.Error.INVALID_SUBJECT_TYPE_UPDATE;
import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;
import static org.wso2.carbon.identity.oauth.OAuthUtil.handleErrorWithExceptionType;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ENABLE_CLAIMS_SEPARATION_FOR_ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDC_DIALECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_DELETED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.PRIVATE_KEY_JWT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildScopeString;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getTenantId;

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
    private static final String BASE_URL_PLACEHOLDER = "<PROTOCOL>://<HOSTNAME>:<PORT>";

    /**
     * Registers an consumer secret against the logged in user. A given user can only have a single
     * consumer secret at a time. Calling this method again and again will update the existing
     * consumer secret key.
     *
     * @return An array containing the consumer key and the consumer secret correspondingly.
     * @throws IdentityOAuthAdminException Error when persisting the data in the persistence store.
     */
    public String[] registerOAuthConsumer() throws IdentityOAuthAdminException {

        String loggedInUser;
        try {
            loggedInUser =
                    OAuthUtil.getUsername(CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            String msg = "Error while retrieving the username of the logged user.";
            throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, msg, e);
        }
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

        String userName;
        OAuthConsumerAppDTO[] dtos = new OAuthConsumerAppDTO[0];
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            userName = OAuthUtil.getUsername(tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            String msg = "User not logged in to get all registered OAuth Applications.";
            if (LOG.isDebugEnabled()) {
                LOG.debug(msg);
            }
            throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, msg, e);
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
     * @deprecated use {@link #getOAuthApplicationData(String, String)} instead.
     */
    @Deprecated
    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException {

        String tenantDomain = getTenantDomain();
        return getOAuthApplicationData(consumerKey, tenantDomain);
    }

    /**
     * Get OAuth application data by the consumer key and tenant domain.
     *
     * @param consumerKey Consumer Key
     * @param tenantDomain Tenant domain
     * @return <code>OAuthConsumerAppDTO</code> with application information
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerKey, String tenantDomain)
            throws IdentityOAuthAdminException {

        OAuthConsumerAppDTO dto;
        try {
            OAuthAppDO app = getOAuthApp(consumerKey, tenantDomain);
            if (app != null) {
                if (isAccessTokenClaimsSeparationFeatureEnabled() &&
                        !isAccessTokenClaimsSeparationEnabledForApp(consumerKey, tenantDomain)) {
                    // Add requested claims as access token claims if the app is not in the new access token
                    // claims feature.
                    addAccessTokenClaims(app, tenantDomain);
                }
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
     * @param appName OAuth application name.
     * @return <code>OAuthConsumerAppDTO</code> with application information.
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName) throws IdentityOAuthAdminException {

        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return getOAuthApplicationDataByAppName(appName, tenantID);
    }

    /**
     * Get OAuth application data by the application name and tenant ID.
     *
     * @param appName  OAuth application name.
     * @param tenantID Tenant ID associated with the OAuth application.
     * @return <code>OAuthConsumerAppDTO</code> with application information.
     * @throws IdentityOAuthAdminException Error when reading application information from persistence store.
     */
    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName, int tenantID)
            throws IdentityOAuthAdminException {

        OAuthConsumerAppDTO dto;
        OAuthAppDAO dao = new OAuthAppDAO();
        try {
            OAuthAppDO app = dao.getAppInformationByAppName(appName, tenantID);
            if (app != null) {
                dto = OAuthUtil.buildConsumerAppDTO(app);
            } else {
                dto = new OAuthConsumerAppDTO();
            }
            return dto;
        } catch (InvalidOAuthClientException e) {
            String msg = "Cannot find a valid OAuth client with application name: " + appName
                    + " in tenant: " + tenantID;
            throw handleClientError(INVALID_OAUTH_CLIENT, msg);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while retrieving the app information by app name: " + appName
                    + " in tenant: " + tenantID, e);
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

        // When external service call this method, it will always audit the action.
        return registerAndRetrieveOAuthApplicationData(application, true);
    }

    /**
     * Same as {@link #registerAndRetrieveOAuthApplicationData(OAuthConsumerAppDTO)} but with an option to disable
     * the audit logs. This is to avoid logging duplicate logs.
     *
     * @param application    <code>OAuthConsumerAppDTO</code> with application information.
     * @param enableAuditing Enable auditing or not.
     * @return OAuthConsumerAppDTO Created OAuth application details.
     * @throws IdentityOAuthAdminException Error when persisting the application information to the persistence store.
     */
    OAuthConsumerAppDTO registerAndRetrieveOAuthApplicationData(OAuthConsumerAppDTO application, boolean enableAuditing)
            throws IdentityOAuthAdminException {

        String tenantAwareLoggedInUsername = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        OAuthAppDO app = new OAuthAppDO();
        AuthenticatedUser defaultAppOwner = null;
        Map<String, Object> oidcDataMap;
        try {
            if (StringUtils.isNotEmpty(tenantAwareLoggedInUsername)) {
                defaultAppOwner = buildAuthenticatedUser(tenantAwareLoggedInUsername, tenantDomain);
            } else {
                Optional<User> tenantAwareLoggedInUser = OAuthUtil.getUser(tenantDomain, application.getUsername());
                if (tenantAwareLoggedInUser.isPresent()) {
                    defaultAppOwner = new AuthenticatedUser(tenantAwareLoggedInUser.get());
                }
            }

            /*
             * If there is no authenticated user, it is due to the DCR endpoint api authentication being turned off and
             * hence we are setting the tenant admin as authenticated the app owner.
             * If DCR endpoint api authentication is enabled there should be an authenticated user at this point,
             * since if not, there will be an error from Authentication valve above this level.
             */
            if (defaultAppOwner == null) {
                if (LOG.isDebugEnabled()) {
                        LOG.debug("No authenticated user found. Setting tenant admin as the owner for app : " +
                                application.getApplicationName());
                }
                String adminUsername = application.getUsername();
                defaultAppOwner = buildAuthenticatedUser(adminUsername, tenantDomain);
            }

            if (defaultAppOwner != null) {
                OAuthAppDAO dao = new OAuthAppDAO();
                if (application != null) {
                    app.setApplicationName(application.getApplicationName());

                    validateCallbackURI(application);
                    app.setCallbackUrl(application.getCallbackUrl());

                    app.setState(APP_STATE_ACTIVE);
                    boolean isFAPIConformanceEnabled = application.isFapiConformanceEnabled();
                    if (StringUtils.isEmpty(application.getOauthConsumerKey())) {
                        app.setOauthConsumerKey(OAuthUtil.getRandomNumber());
                        app.setOauthConsumerSecret(OAuthUtil.getRandomNumberSecure());
                    } else {
                        app.setOauthConsumerKey(application.getOauthConsumerKey());
                        if (StringUtils.isEmpty(application.getOauthConsumerSecret())) {
                            app.setOauthConsumerSecret(OAuthUtil.getRandomNumberSecure());
                        } else {
                            app.setOauthConsumerSecret(application.getOauthConsumerSecret());
                        }
                    }

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
                        app.setHybridFlowEnabled(application.isHybridFlowEnabled());
                        app.setHybridFlowResponseType(application.getHybridFlowResponseType());
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
                            if (isFAPIConformanceEnabled) {
                                validateFAPIEncryptionAlgorithms(application.getIdTokenEncryptionAlgorithm());
                            }
                            app.setIdTokenEncryptionAlgorithm(
                                    filterEncryptionAlgorithms(application.getIdTokenEncryptionAlgorithm(),
                                            OAuthConstants.ID_TOKEN_ENCRYPTION_ALGORITHM));
                            app.setIdTokenEncryptionMethod(
                                    filterEncryptionMethod(application.getIdTokenEncryptionMethod(),
                                            OAuthConstants.ID_TOKEN_ENCRYPTION_METHOD));
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
                        if (isFAPIConformanceEnabled) {
                            validateFAPIBindingType(application.getTokenBindingType());
                        } else {
                            validateBindingType(application.getTokenBindingType());
                        }
                        app.setTokenBindingType(application.getTokenBindingType());
                        app.setTokenBindingValidationEnabled(application.isTokenBindingValidationEnabled());
                        app.setTokenRevocationWithIDPSessionTerminationEnabled(
                                application.isTokenRevocationWithIDPSessionTerminationEnabled());
                        String tokenEndpointAuthMethod = application.getTokenEndpointAuthMethod();
                        if (StringUtils.isNotEmpty(tokenEndpointAuthMethod)) {
                            if (isFAPIConformanceEnabled) {
                                validateFAPITokenAuthMethods(tokenEndpointAuthMethod);
                            } else {
                                filterTokenEndpointAuthMethods(tokenEndpointAuthMethod);
                            }
                            app.setTokenEndpointAuthMethod(tokenEndpointAuthMethod);
                        }
                        Boolean tokenEndpointAllowReusePvtKeyJwt = application.isTokenEndpointAllowReusePvtKeyJwt();
                        if (isInvalidTokenEPReusePvtKeyJwtRequest(tokenEndpointAuthMethod,
                                tokenEndpointAllowReusePvtKeyJwt)) {
                            throw handleClientError(INVALID_REQUEST, "Requested client authentication method " +
                                    "incompatible with the Private Key JWT Reuse config value.");
                        }
                        app.setTokenEndpointAllowReusePvtKeyJwt(tokenEndpointAllowReusePvtKeyJwt);
                        String tokenEndpointAuthSigningAlgorithm = application.getTokenEndpointAuthSignatureAlgorithm();
                        if (StringUtils.isNotEmpty(tokenEndpointAuthSigningAlgorithm)) {
                            if (isFAPIConformanceEnabled) {
                                validateFAPISignatureAlgorithms(tokenEndpointAuthSigningAlgorithm);
                            } else {
                                filterSignatureAlgorithms(tokenEndpointAuthSigningAlgorithm,
                                      OAuthConstants.TOKEN_EP_SIGNATURE_ALG_CONFIGURATION);
                            }
                            app.setTokenEndpointAuthSignatureAlgorithm(tokenEndpointAuthSigningAlgorithm);
                        }
                        if (StringUtils.isEmpty(application.getSubjectType())) {
                            // Set default subject type.
                            application.setSubjectType(OIDCClaimUtil.getDefaultSubjectType().toString());
                        }
                        OAuthConstants.SubjectType subjectType = OAuthConstants.SubjectType.fromValue(
                                application.getSubjectType());
                        if (subjectType == null) {
                            application.setSubjectType(OIDCClaimUtil.getDefaultSubjectType().toString());
                        }
                        if (OAuthConstants.SubjectType.PAIRWISE.getValue().equals(application.getSubjectType())) {
                            if (StringUtils.isNotEmpty(application.getCallbackUrl())) {
                                List<String> callBackURIList = new ArrayList<>();
                                // Need to split the redirect uris for validating the host names since it is combined
                                // into one regular expression.
                                if (application.getCallbackUrl().startsWith(
                                        OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
                                    callBackURIList = getRedirectURIList(application);
                                } else {
                                    callBackURIList.add(application.getCallbackUrl());
                                }
                                if (StringUtils.isNotEmpty(application.getSectorIdentifierURI())) {
                                    validateSectorIdentifierURI(application.getSectorIdentifierURI(), callBackURIList);
                                    app.setSectorIdentifierURI(application.getSectorIdentifierURI());
                                } else {
                                    validateRedirectURIForPPID(callBackURIList);
                                }
                            }
                        }
                        app.setSubjectType(application.getSubjectType());

                        String idTokenSignatureAlgorithm = application.getIdTokenSignatureAlgorithm();
                        if (StringUtils.isNotEmpty(idTokenSignatureAlgorithm)) {
                            if (isFAPIConformanceEnabled) {
                                validateFAPISignatureAlgorithms(idTokenSignatureAlgorithm);
                            } else {
                                filterSignatureAlgorithms(idTokenSignatureAlgorithm,
                                       OAuthConstants.ID_TOKEN_SIGNATURE_ALG_CONFIGURATION);
                            }
                            app.setIdTokenSignatureAlgorithm(idTokenSignatureAlgorithm);
                        }
                        String requestObjectSignatureAlgorithm = application.getRequestObjectSignatureAlgorithm();
                        if (StringUtils.isNotEmpty(requestObjectSignatureAlgorithm)) {
                            if (isFAPIConformanceEnabled) {
                                validateFAPISignatureAlgorithms(requestObjectSignatureAlgorithm);
                            } else {
                                filterSignatureAlgorithms(requestObjectSignatureAlgorithm,
                                        OAuthConstants.REQUEST_OBJECT_SIGNATURE_ALG_CONFIGURATION);
                            }
                            app.setRequestObjectSignatureValidationEnabled(
                                    application.isRequestObjectSignatureValidationEnabled());
                            app.setRequestObjectSignatureAlgorithm(requestObjectSignatureAlgorithm);
                        }
                        app.setTlsClientAuthSubjectDN(application.getTlsClientAuthSubjectDN());

                        String requestObjectEncryptionAlgorithm = application.getRequestObjectEncryptionAlgorithm();
                        if (StringUtils.isNotEmpty(application.getRequestObjectEncryptionAlgorithm())) {
                            if (isFAPIConformanceEnabled) {
                                validateFAPIEncryptionAlgorithms(
                                        application.getRequestObjectEncryptionAlgorithm());
                            } else {
                                filterEncryptionAlgorithms(application.getRequestObjectEncryptionAlgorithm(),
                                        OAuthConstants.REQUEST_OBJECT_ENCRYPTION_ALGORITHM);
                            }
                            app.setRequestObjectEncryptionAlgorithm(requestObjectEncryptionAlgorithm);
                        }
                        if (StringUtils.isNotEmpty(application.getRequestObjectEncryptionMethod())) {
                            app.setRequestObjectEncryptionMethod(filterEncryptionMethod(
                                    application.getRequestObjectEncryptionMethod(),
                                    OAuthConstants.REQUEST_OBJECT_ENCRYPTION_METHOD));
                        }
                        app.setRequirePushedAuthorizationRequests(application.getRequirePushedAuthorizationRequests());
                        app.setFapiConformanceEnabled(application.isFapiConformanceEnabled());
                        app.setSubjectTokenEnabled(application.isSubjectTokenEnabled());
                        app.setSubjectTokenExpiryTime(application.getSubjectTokenExpiryTime());
                        if (isAccessTokenClaimsSeparationFeatureEnabled()) {
                            validateAccessTokenClaims(application, tenantDomain);
                            app.setAccessTokenClaims(application.getAccessTokenClaims());
                        }
                    }
                    dao.addOAuthApplication(app);
                    if (ApplicationConstants.CONSOLE_APPLICATION_NAME.equals(app.getApplicationName())) {
                        String consoleCallBackURL = OAuth2Util.getConsoleCallbackFromServerConfig(tenantDomain);
                        if (StringUtils.isNotEmpty(consoleCallBackURL)) {
                            app.setCallbackUrl(consoleCallBackURL);
                        }
                    }
                    if (StringUtils.isNotBlank(app.getCallbackUrl()) &&
                            !app.getCallbackUrl().contains(BASE_URL_PLACEHOLDER)) {
                        AppInfoCache.getInstance().addToCache(app.getOauthConsumerKey(), app, tenantDomain);
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Oauth Application registration success : " + application.getApplicationName() +
                                " in tenant domain: " + tenantDomain);
                    }
                    oidcDataMap = buildSPData(app);
                    oidcDataMap.put("allowedOrigins", application.getAllowedOrigins());
                    if (enableAuditing) {
                        Optional<String> initiatorId = getInitiatorId();
                        if (initiatorId.isPresent()) {
                            AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                                    initiatorId.get(), LoggerUtils.Initiator.User.name(),
                                    app.getOauthConsumerKey(), LoggerUtils.Target.Application.name(),
                                    LogConstants.ApplicationManagement.CREATE_OAUTH_APPLICATION_ACTION)
                                    .data(oidcDataMap);
                            triggerAuditLogEvent(auditLogBuilder, true);
                        } else {
                            LOG.error("Error getting the logged in userId");
                        }
                    }
                } else {
                    String message = "No application details in the request. Failed to register OAuth App.";
                    LOG.debug(message);

                    throw handleClientError(INVALID_REQUEST, message);
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    if (application != null) {
                        LOG.debug("No authenticated user found. Failed to register OAuth App: " +
                                application.getApplicationName());
                    } else {
                        LOG.debug("No authenticated user found. Failed to register OAuth App.");
                    }
                }
                String message = "No authenticated user found. Failed to register OAuth App.";
                throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, message);
            }
        } catch (IdentityApplicationManagementException e) {
            throw handleClientError(AUTHENTICATED_USER_NOT_FOUND,
                    "Error resolving user. Failed to register OAuth App", e);
        }
        OAuthConsumerAppDTO oAuthConsumerAppDTO = OAuthUtil.buildConsumerAppDTO(app);
        oAuthConsumerAppDTO.setAuditLogData(oidcDataMap);
        return oAuthConsumerAppDTO;
    }


    private Optional<AuthenticatedUser> getLoggedInUser(String tenantDomain) {

        String tenantAwareLoggedInUsername = CarbonContext.getThreadLocalCarbonContext().getUsername();
        return Optional.ofNullable(tenantAwareLoggedInUsername)
                .filter(StringUtils::isNotEmpty)
                .map(username -> buildAuthenticatedUser(username, tenantDomain));

    }

    private static Map<String, Object> buildSPData(OAuthAppDO app) {

        if (app == null) {
            return new HashMap<>();
        }
        Gson gson = new Gson();
        String oauthApp = maskSPData(app);
        return gson.fromJson(oauthApp, new TypeToken<Map<String, Object>>() {
        }.getType());
    }

    private static String maskSPData(OAuthAppDO oAuthAppDO) {

        if (oAuthAppDO == null) {
            return StringUtils.EMPTY;
        }
        try {
            JSONObject oauthAppJSONObject =
                    new JSONObject(new ObjectMapper().writeValueAsString(oAuthAppDO));
            maskClientSecret(oauthAppJSONObject);
            maskAppOwnerUsername(oauthAppJSONObject);
            return oauthAppJSONObject.toString();
        } catch (JsonProcessingException | IdentityException e) {
            LOG.error("Error while converting service provider object to json.");
        }
        return StringUtils.EMPTY;
    }

    private static void maskAppOwnerUsername(JSONObject oauthAppJSONObject) throws IdentityException {

        JSONObject appOwner = oauthAppJSONObject.optJSONObject("appOwner");
        if (!LoggerUtils.isLogMaskingEnable || appOwner == null) {
            return;
        }
        String username = (String) appOwner.get("userName");
        if (StringUtils.isNotBlank(username)) {
            appOwner.put("userName", LoggerUtils.getMaskedContent(username));
        }
    }

    private static void maskClientSecret(JSONObject oauthApp) {

        if (oauthApp.get("oauthConsumerSecret") == null) {
            return;
        }
        String secret = oauthApp.get("oauthConsumerSecret").toString();
        oauthApp.put("oauthConsumerSecret", LoggerUtils.getMaskedContent(secret));
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

    /**
     * FAPI validation to restrict the token binding type to ensure MTLS sender constrained access tokens.
     * Link - https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server
     * @param bindingType Token binding type.
     * @throws IdentityOAuthClientException if binding type is not 'certificate'.
     */
    private void validateFAPIBindingType(String bindingType)
            throws IdentityOAuthClientException {

        if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType) || bindingType == null) {
            return;
        } else {
            String msg = String.format("Certificate bound access tokens is required. '%s' binding type is found.",
                    bindingType);
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

        updateConsumerApplication(consumerAppDTO, true);
    }

    /**
     * Same as {@link #updateConsumerApplication(OAuthConsumerAppDTO)} but with an option to enable/disable audit logs.
     *
     * @param consumerAppDTO <code>OAuthConsumerAppDTO</code> with updated application information
     * @throws IdentityOAuthAdminException Error when updating the underlying identity persistence store.
     */
    void updateConsumerApplication(OAuthConsumerAppDTO consumerAppDTO, boolean enableAuditing)
            throws IdentityOAuthAdminException {

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

        String tenantDomain = getAppTenantDomain();

        OAuthAppDAO dao = new OAuthAppDAO();
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = getOAuthApp(oauthConsumerKey, tenantDomain);
            if (oAuthAppDO == null) {
                String msg = "OAuth application cannot be found for consumerKey: " + oauthConsumerKey;
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msg);
                }
                throw handleClientError(INVALID_OAUTH_CLIENT, msg);
            }
            if (!StringUtils.equals(consumerAppDTO.getOauthConsumerSecret(), oAuthAppDO.getOauthConsumerSecret())) {
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

        AuthenticatedUser defaultAppOwner = oAuthAppDO.getAppOwner();
        AuthenticatedUser appOwner = getAppOwner(consumerAppDTO, defaultAppOwner);
        oAuthAppDO.setAppOwner(appOwner);

        oAuthAppDO.setOauthConsumerKey(oauthConsumerKey);
        oAuthAppDO.setOauthConsumerSecret(consumerAppDTO.getOauthConsumerSecret());

        validateCallbackURI(consumerAppDTO);
        oAuthAppDO.setCallbackUrl(consumerAppDTO.getCallbackUrl());

        oAuthAppDO.setApplicationName(consumerAppDTO.getApplicationName());
        oAuthAppDO.setPkceMandatory(consumerAppDTO.getPkceMandatory());
        oAuthAppDO.setPkceSupportPlain(consumerAppDTO.getPkceSupportPlain());
        oAuthAppDO.setHybridFlowEnabled(consumerAppDTO.isHybridFlowEnabled());
        oAuthAppDO.setHybridFlowResponseType(consumerAppDTO.getHybridFlowResponseType());

        // Validate access token expiry configurations.
        validateTokenExpiryConfigurations(consumerAppDTO);
        oAuthAppDO.setUserAccessTokenExpiryTime(consumerAppDTO.getUserAccessTokenExpiryTime());
        oAuthAppDO.setApplicationAccessTokenExpiryTime(consumerAppDTO.getApplicationAccessTokenExpiryTime());
        oAuthAppDO.setRefreshTokenExpiryTime(consumerAppDTO.getRefreshTokenExpiryTime());
        oAuthAppDO.setIdTokenExpiryTime(consumerAppDTO.getIdTokenExpiryTime());
        oAuthAppDO.setTokenType(consumerAppDTO.getTokenType());
        oAuthAppDO.setBypassClientCredentials(consumerAppDTO.isBypassClientCredentials());
        if (OAuthConstants.OAuthVersions.VERSION_2.equals(consumerAppDTO.getOAuthVersion())) {
            validateGrantTypes(consumerAppDTO);
            oAuthAppDO.setGrantTypes(consumerAppDTO.getGrantTypes());

            validateAudiences(consumerAppDTO);
            oAuthAppDO.setAudiences(consumerAppDTO.getAudiences());
            oAuthAppDO.setScopeValidators(filterScopeValidators(consumerAppDTO));
            oAuthAppDO.setRequestObjectSignatureValidationEnabled(consumerAppDTO
                    .isRequestObjectSignatureValidationEnabled());

            // Validate IdToken Encryption configurations.
            oAuthAppDO.setIdTokenEncryptionEnabled(consumerAppDTO.isIdTokenEncryptionEnabled());
            boolean isFAPIConformanceEnabled = consumerAppDTO.isFapiConformanceEnabled();
            if (consumerAppDTO.isIdTokenEncryptionEnabled()) {
                if (isFAPIConformanceEnabled) {
                    validateFAPIEncryptionAlgorithms(consumerAppDTO.getIdTokenEncryptionAlgorithm());
                }
                oAuthAppDO.setIdTokenEncryptionAlgorithm(filterEncryptionAlgorithms(
                        consumerAppDTO.getIdTokenEncryptionAlgorithm(), OAuthConstants.ID_TOKEN_ENCRYPTION_ALGORITHM));
                oAuthAppDO.setIdTokenEncryptionMethod(filterEncryptionMethod(
                        consumerAppDTO.getIdTokenEncryptionMethod(), OAuthConstants.ID_TOKEN_ENCRYPTION_METHOD));
            }

            oAuthAppDO.setBackChannelLogoutUrl(consumerAppDTO.getBackChannelLogoutUrl());
            oAuthAppDO.setFrontchannelLogoutUrl(consumerAppDTO.getFrontchannelLogoutUrl());
            oAuthAppDO.setRenewRefreshTokenEnabled(consumerAppDTO.getRenewRefreshTokenEnabled());
            if (isFAPIConformanceEnabled) {
                validateFAPIBindingType(consumerAppDTO.getTokenBindingType());
            } else {
                validateBindingType(consumerAppDTO.getTokenBindingType());
            }
            oAuthAppDO.setTokenBindingType(consumerAppDTO.getTokenBindingType());
            oAuthAppDO.setTokenRevocationWithIDPSessionTerminationEnabled(consumerAppDTO
                    .isTokenRevocationWithIDPSessionTerminationEnabled());
            oAuthAppDO.setTokenBindingValidationEnabled(consumerAppDTO.isTokenBindingValidationEnabled());

            String tokenEndpointAuthMethod = consumerAppDTO.getTokenEndpointAuthMethod();
            if (StringUtils.isNotEmpty(tokenEndpointAuthMethod)) {
                if (isFAPIConformanceEnabled) {
                    validateFAPITokenAuthMethods(tokenEndpointAuthMethod);
                } else {
                    filterTokenEndpointAuthMethods(tokenEndpointAuthMethod);
                }
            }
            oAuthAppDO.setTokenEndpointAuthMethod(tokenEndpointAuthMethod);

            Boolean tokenEndpointAllowReusePvtKeyJwt = consumerAppDTO.isTokenEndpointAllowReusePvtKeyJwt();
            if (isInvalidTokenEPReusePvtKeyJwtRequest(tokenEndpointAuthMethod, tokenEndpointAllowReusePvtKeyJwt)) {
                throw handleClientError(INVALID_REQUEST, "Requested client authentication method " +
                        "incompatible with the Private Key JWT Reuse config value.");
            }
            oAuthAppDO.setTokenEndpointAllowReusePvtKeyJwt(tokenEndpointAllowReusePvtKeyJwt);

            String tokenEndpointAuthSignatureAlgorithm = consumerAppDTO.getTokenEndpointAuthSignatureAlgorithm();
            if (StringUtils.isNotEmpty(tokenEndpointAuthSignatureAlgorithm)) {
                if (isFAPIConformanceEnabled) {
                    validateFAPISignatureAlgorithms(tokenEndpointAuthSignatureAlgorithm);
                } else {
                    filterSignatureAlgorithms(tokenEndpointAuthSignatureAlgorithm,
                            OAuthConstants.TOKEN_EP_SIGNATURE_ALG_CONFIGURATION);
                }
            }
            oAuthAppDO.setTokenEndpointAuthSignatureAlgorithm(tokenEndpointAuthSignatureAlgorithm);

            if (StringUtils.isEmpty(consumerAppDTO.getSubjectType())) {
                // Set default subject type if not set.
                oAuthAppDO.setSubjectType(OIDCClaimUtil.getDefaultSubjectType().toString());
            }
            OAuthConstants.SubjectType subjectType = OAuthConstants.SubjectType.fromValue(
                    consumerAppDTO.getSubjectType());
            if (subjectType == null) {
                consumerAppDTO.setSubjectType(OIDCClaimUtil.getDefaultSubjectType().toString());
            }
            if (OAuthConstants.SubjectType.PAIRWISE.getValue().equals(consumerAppDTO.getSubjectType())) {
                if (StringUtils.isNotEmpty(consumerAppDTO.getCallbackUrl())) {
                    List<String> callBackURIList = new ArrayList<>();
                    // Need to split the redirect uris for validating the host names since it is combined
                    // into one regular expression.
                    if (consumerAppDTO.getCallbackUrl().startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
                        callBackURIList = getRedirectURIList(consumerAppDTO);
                    } else {
                        callBackURIList.add(consumerAppDTO.getCallbackUrl());
                    }
                    if (StringUtils.isNotEmpty(consumerAppDTO.getSectorIdentifierURI())) {
                        validateSectorIdentifierURI(consumerAppDTO.getSectorIdentifierURI(), callBackURIList);
                        oAuthAppDO.setSectorIdentifierURI(consumerAppDTO.getSectorIdentifierURI());
                    } else {
                        validateRedirectURIForPPID(callBackURIList);
                    }
                }
            }
            oAuthAppDO.setSectorIdentifierURI(consumerAppDTO.getSectorIdentifierURI());
            oAuthAppDO.setSubjectType(consumerAppDTO.getSubjectType());

            String idTokenSignatureAlgorithm = consumerAppDTO.getIdTokenSignatureAlgorithm();
            if (StringUtils.isNotEmpty(idTokenSignatureAlgorithm)) {
                if (isFAPIConformanceEnabled) {
                    validateFAPISignatureAlgorithms(idTokenSignatureAlgorithm);
                } else {
                    filterSignatureAlgorithms(idTokenSignatureAlgorithm,
                            OAuthConstants.ID_TOKEN_SIGNATURE_ALG_CONFIGURATION);
                }
            }
            oAuthAppDO.setIdTokenSignatureAlgorithm(idTokenSignatureAlgorithm);

            String requestObjectSignatureAlgorithm = consumerAppDTO.getRequestObjectSignatureAlgorithm();
            if (StringUtils.isNotEmpty(requestObjectSignatureAlgorithm)) {
                if (isFAPIConformanceEnabled) {
                    validateFAPISignatureAlgorithms(requestObjectSignatureAlgorithm);
                } else {
                    filterSignatureAlgorithms(requestObjectSignatureAlgorithm,
                            OAuthConstants.REQUEST_OBJECT_SIGNATURE_ALG_CONFIGURATION);
                }
            }
            oAuthAppDO.setRequestObjectSignatureAlgorithm(requestObjectSignatureAlgorithm);
            oAuthAppDO.setRequestObjectSignatureValidationEnabled(consumerAppDTO
                    .isRequestObjectSignatureValidationEnabled());

            oAuthAppDO.setTlsClientAuthSubjectDN(consumerAppDTO.getTlsClientAuthSubjectDN());

            String requestObjectEncryptionAlgorithm = consumerAppDTO.getRequestObjectEncryptionAlgorithm();
            if (StringUtils.isNotEmpty(requestObjectEncryptionAlgorithm)) {
                if (isFAPIConformanceEnabled) {
                    validateFAPIEncryptionAlgorithms(requestObjectEncryptionAlgorithm);
                } else {
                    filterEncryptionAlgorithms(
                            requestObjectEncryptionAlgorithm, OAuthConstants.REQUEST_OBJECT_ENCRYPTION_ALGORITHM);
                }
            }
            oAuthAppDO.setRequestObjectEncryptionAlgorithm(requestObjectEncryptionAlgorithm);
            String requestObjectEncryptionMethod = consumerAppDTO.getRequestObjectEncryptionMethod();
            if (StringUtils.isNotEmpty(requestObjectEncryptionMethod)) {
                filterEncryptionMethod(requestObjectEncryptionMethod, OAuthConstants.REQUEST_OBJECT_ENCRYPTION_METHOD);

            }
            oAuthAppDO.setRequestObjectEncryptionMethod(requestObjectEncryptionMethod);
            oAuthAppDO.setRequirePushedAuthorizationRequests(consumerAppDTO.getRequirePushedAuthorizationRequests());
            oAuthAppDO.setSubjectTokenEnabled(consumerAppDTO.isSubjectTokenEnabled());
            oAuthAppDO.setSubjectTokenExpiryTime(consumerAppDTO.getSubjectTokenExpiryTime());

            if (isAccessTokenClaimsSeparationFeatureEnabled()) {
                // We check if the AT claims separation enabled at server level and
                // the app level. If both are enabled, we validate the claims and update the app.
                try {
                    if (isAccessTokenClaimsSeparationEnabledForApp(oAuthAppDO.getOauthConsumerKey(), tenantDomain)) {
                        validateAccessTokenClaims(consumerAppDTO, tenantDomain);
                        oAuthAppDO.setAccessTokenClaims(consumerAppDTO.getAccessTokenClaims());
                    }
                } catch (IdentityOAuth2Exception e) {
                    throw new IdentityOAuthAdminException("Error while updating existing OAuth application to " +
                            "the new JWT access token OIDC claims separation model. Application : " +
                            oAuthAppDO.getApplicationName() + " Tenant : " + tenantDomain, e);
                }
                // We only trigger the access token claims migration if the following conditions are met.
                // 1. The AT claims separation is enabled at server level.
                // 2. The AT claims separation is not enabled at app level.
                try {
                    if (!isAccessTokenClaimsSeparationEnabledForApp(oAuthAppDO.getOauthConsumerKey(), tenantDomain)) {
                        // Add requested claims as access token claims.
                        addAccessTokenClaims(oAuthAppDO, tenantDomain);
                    }

                } catch (IdentityOAuth2Exception e) {
                    throw new IdentityOAuthAdminException("Error while updating existing OAuth application to " +
                            "the new JWT access token OIDC claims separation model. Application : " +
                            oAuthAppDO.getApplicationName() + " Tenant : " + tenantDomain, e);
                }
            }
        }
        dao.updateConsumerApplication(oAuthAppDO);
        AppInfoCache.getInstance().addToCache(oAuthAppDO.getOauthConsumerKey(), oAuthAppDO, tenantDomain);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Oauth Application update success : " + consumerAppDTO.getApplicationName() + " in " +
                    "tenant domain: " + tenantDomain);
        }
        Map<String, Object> oidcDataMap = buildSPData(oAuthAppDO);
        oidcDataMap.put("allowedOrigins", consumerAppDTO.getAllowedOrigins());
        consumerAppDTO.setAuditLogData(oidcDataMap);
        if (enableAuditing) {
            Optional<String> initiatorId = getInitiatorId();
            if (initiatorId.isPresent()) {
                AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                        initiatorId.get(), LoggerUtils.Initiator.User.name(), oauthConsumerKey,
                        LoggerUtils.Target.Application.name(),
                        LogConstants.ApplicationManagement.UPDATE_OAUTH_APPLICATION_ACTION).data(oidcDataMap);
                triggerAuditLogEvent(auditLogBuilder, true);
            } else {
                LOG.error("Error getting the logged in userId");
            }
        }
    }

    private Optional<String> getInitiatorId() {

        String loggedInUserId = CarbonContext.getThreadLocalCarbonContext().getUserId();
        if (StringUtils.isNotBlank(loggedInUserId)) {
            return Optional.of(loggedInUserId);
        } else {
            String tenantDomain = getLoggedInTenant();
            Optional<AuthenticatedUser> loggedInUser = getLoggedInUser(tenantDomain);
            if (loggedInUser.isPresent()) {
                return Optional.ofNullable(IdentityUtil.getInitiatorId(loggedInUser.get().getUserName(), tenantDomain));
            }
        }
        return Optional.empty();
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
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        ClaimMetadataManagementService claimService = OAuth2ServiceComponentHolder.getInstance()
                .getClaimMetadataManagementService();
        try {
            List<ExternalClaim> oidcDialectClaims =  claimService.getExternalClaims(OAuthConstants.OIDC_DIALECT,
                    tenantDomain);
            List<String> oidcClaimsMappedToScopes = Arrays.asList(scope.getClaim());
            for (ExternalClaim oidcClaim : oidcDialectClaims) {
                if (oidcClaimsMappedToScopes.contains(oidcClaim.getClaimURI())) {
                    claimService.updateExternalClaim(oidcClaim, tenantDomain);
                }
            }
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().addScope(scope, tenantId);
        } catch (ClaimMetadataException e) {
            IdentityOAuth2Exception identityOAuth2Exception = new IdentityOAuth2Exception(String.format(
                    "Error while inserting OIDC scope: %s in tenant: %s", scope.getName(), tenantDomain), e);
            throw handleErrorWithExceptionType(identityOAuth2Exception.getMessage(), identityOAuth2Exception);
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
        // Check whether a scope exists with the provided scope name which to be updated.
        validateScopeExistence(updatedScope.getName());

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        ClaimMetadataManagementService claimService = OAuth2ServiceComponentHolder.getInstance()
                .getClaimMetadataManagementService();
        try {
            List<ExternalClaim> oidcDialectClaims =  claimService.getExternalClaims(OAuthConstants.OIDC_DIALECT,
                    tenantDomain);
            List<String> oidcClaimsMappedToScopes = Arrays.asList(updatedScope.getClaim());
            for (ExternalClaim oidcClaim : oidcDialectClaims) {
                if (oidcClaimsMappedToScopes.contains(oidcClaim.getClaimURI())) {
                    claimService.updateExternalClaim(oidcClaim, tenantDomain);
                }
            }
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().updateScope(updatedScope, tenantId);
        } catch (ClaimMetadataException e) {
            IdentityOAuth2Exception identityOAuth2Exception = new IdentityOAuth2Exception(String.format(
                    "Error while updating the scope: %s in tenant: %s", updatedScope.getName(), tenantId), e);
            throw handleErrorWithExceptionType(identityOAuth2Exception.getMessage(), identityOAuth2Exception);
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
            OAuthAppDO oAuthAppDO = getOAuthApp(consumerKey, getTenantDomain());
            // change the state
            oAuthAppDO.setState(newState);

            Properties properties = new Properties();
            properties.setProperty(OAuthConstants.OAUTH_APP_NEW_STATE, newState);
            properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REVOKE);

            AppInfoCache.getInstance().clearCacheEntry(consumerKey);
            updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);
            handleInternalTokenRevocation(consumerKey, properties);

            if (LOG.isDebugEnabled()) {
                LOG.debug("App state is updated to:" + newState + " in the AppInfoCache for OAuth App with " +
                        "consumerKey: " + consumerKey);
            }

            Optional<String> initiatorId = getInitiatorId();
            if (initiatorId.isPresent()) {
                AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                        initiatorId.get(), USER, consumerKey, TARGET_APPLICATION,
                        OAuthConstants.LogConstants.UPDATE_APP_STATE);

                triggerAuditLogEvent(auditLogBuilder, true);
            } else {
                LOG.error("Error getting the logged in userId");
            }

        } catch (InvalidOAuthClientException e) {
            String msg = "Error while updating state of OAuth app with consumerKey: " + consumerKey;
            throw handleClientError(INVALID_OAUTH_CLIENT, msg, e);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while updating state of OAuth app with consumerKey: " + consumerKey, e);
        }
    }

    private String getTenantDomain() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = IdentityTenantUtil.getTenantDomainFromContext();
        }
        return tenantDomain;
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

    private String getLoggedInTenant() {

        return Optional.ofNullable(IdentityTenantUtil.getTenantDomainFromContext())
                .filter(StringUtils::isNotBlank)
                .orElseGet(() -> PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
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
        String newSecret = OAuthUtil.getRandomNumberSecure();
        OAuthConsumerAppDTO oldAppDTO = null;

        oldAppDTO = getOAuthApplicationData(consumerKey);
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY, newSecret);
        properties.setProperty(OAuthConstants.ACTION_PROPERTY_KEY, OAuthConstants.ACTION_REGENERATE);
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_STATE, APP_STATE_ACTIVE);

        AppInfoCache.getInstance().clearCacheEntry(consumerKey);
        updateAppAndRevokeTokensAndAuthzCodes(consumerKey, properties);
        handleInternalTokenRevocation(consumerKey, properties);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client Secret for OAuth app with consumerKey: " + consumerKey + " updated in OAuthCache.");
        }

        OAuthConsumerAppDTO updatedApplication = getOAuthApplicationData(consumerKey);
        updatedApplication.setOauthConsumerSecret(newSecret);
        // This API is invoked when regenerating client secret and when activating the app.
        Optional<String> initiatorId = getInitiatorId();
        if (initiatorId.isPresent()) {
            if (!StringUtils.equalsIgnoreCase(oldAppDTO.getState(), APP_STATE_ACTIVE)) {
                AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                        initiatorId.get(), USER, consumerKey, TARGET_APPLICATION,
                        OAuthConstants.LogConstants.UPDATE_APP_STATE)
                        .data(Map.of("state", APP_STATE_ACTIVE));
                triggerAuditLogEvent(auditLogBuilder, true);
            }
            AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                    initiatorId.get(), USER, consumerKey, TARGET_APPLICATION,
                    OAuthConstants.LogConstants.REGENERATE_CLIENT_SECRET);
            triggerAuditLogEvent(auditLogBuilder, true);
        } else {
            LOG.error("Error getting the logged in userId");
        }
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
            }
            clearTokenCacheEntry(consumerKey, activeDetailedTokens);

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

        removeOAuthApplicationData(consumerKey, true);
    }

    /**
     * Removes an OAuth consumer application. Also this will allow to enable or disable audit logs.
     *
     * @param consumerKey Consumer Key.
     * @throws IdentityOAuthAdminException Error when removing the consumer information from the database.
     */
    void removeOAuthApplicationData(String consumerKey, boolean enableAuditing) throws IdentityOAuthAdminException {

        for (OAuthApplicationMgtListener oAuthApplicationMgtListener : OAuthComponentServiceHolder.getInstance()
                .getOAuthApplicationMgtListeners()) {
            oAuthApplicationMgtListener.doPreRemoveOAuthApplicationData(consumerKey);
        }
        Properties properties = new Properties();
        properties.setProperty(OAuthConstants.OAUTH_APP_NEW_STATE, APP_STATE_DELETED);


        Set<AccessTokenDO> activeDetailedTokens;
        try {
            activeDetailedTokens = OAuthTokenPersistenceFactory
                    .getInstance().getAccessTokenDAO().getActiveAcessTokenDataByConsumerKey(consumerKey);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error in updating oauth app & revoking access tokens and authz " +
                    "codes for OAuth App with consumerKey: " + consumerKey, e);
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

        // Remove all active tokens and authorization codes from the cache.
        clearTokenCacheEntry(consumerKey, activeDetailedTokens);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client credentials are removed from the cache for OAuth App with consumerKey: "
                    + consumerKey);
        }
        handleInternalTokenRevocation(consumerKey, properties);
        if (enableAuditing) {
            Optional<String> initiatorId = getInitiatorId();
            if (initiatorId.isPresent()) {
                AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                        initiatorId.get(), LoggerUtils.Initiator.User.name(), consumerKey,
                        LoggerUtils.Target.Application.name(),
                        LogConstants.ApplicationManagement.DELETE_OAUTH_APPLICATION_ACTION);
                triggerAuditLogEvent(auditLogBuilder, true);
            } else {
                LOG.error("Error getting the logged in userId");
            }
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
        AuthenticatedUser loggedInUser = null;
        try {
            if (tenantAwareLoggedInUserName != null) {
                loggedInUser = buildAuthenticatedUser(tenantAwareLoggedInUserName, tenantDomain);
            } else {
                Optional<User> tenantAwareLoggedInUser = OAuthUtil.getUser(tenantDomain, null);
                if (tenantAwareLoggedInUser.isPresent()) {
                    loggedInUser = new AuthenticatedUser(tenantAwareLoggedInUser.get());
                }
            }
        } catch (IdentityApplicationManagementException e) {
            throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, "Error resolving user.", e);
        }

        String username = loggedInUser.getUsernameAsSubjectIdentifier(true, true);
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
                            OAuthAppDO appDO = getOAuthAppDO(scopedToken.getConsumerKey(), tenantDomain);
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

    private OAuthAppDO getOAuthAppDO(String consumerKey, String tenantDomain) throws IdentityOAuthAdminException {

        OAuthAppDO appDO;
        try {
            appDO = getOAuthApp(consumerKey, tenantDomain);
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
            AuthenticatedUser user = null;
            try {
                if (tenantAwareLoggedInUserName != null) {
                    user = buildAuthenticatedUser(tenantAwareLoggedInUserName, tenantDomain);
                } else {
                    Optional<User> tenantAwareLoggedInUser = OAuthUtil.getUser(tenantDomain, null);
                    if (tenantAwareLoggedInUser.isPresent()) {
                        user = new AuthenticatedUser(tenantAwareLoggedInUser.get());
                    }
                }
            } catch (IdentityApplicationManagementException e) {
                throw handleClientError(AUTHENTICATED_USER_NOT_FOUND, "Error resolving user.", e);
            }
            String userName = user.getUsernameAsSubjectIdentifier(true, true);
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

        String tenantDomain = getLoggedInTenant(consumerKey);
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
        AccessTokenEventUtil.publishTokenRevokeEvent(application.getApplicationResourceId(), applicationName,
                consumerKey, tenantDomain);
        triggerPostApplicationTokenRevokeListeners(application, revokeRespDTO, accessTokenDOs);
        return revokeRespDTO;
    }

    /**
     * Revoke issued tokens for the application for the given authorized organization.
     *
     * @param application    {@link OAuthAppRevocationRequestDTO}.
     * @param organizationId ID of the organization for which the tokens should be revoked.
     * @return revokeRespDTO {@link OAuthAppRevocationRequestDTO}.
     * @throws IdentityOAuthAdminException Error while revoking the issued tokens.
     */
    public OAuthRevocationResponseDTO revokeIssuedTokensForOrganizationByApplication
    (OAuthAppRevocationRequestDTO application, String organizationId) throws IdentityOAuthAdminException {

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

        List<AccessTokenDO> accessTokenDOs = getActiveAccessTokensByConsumerKey(consumerKey);
        accessTokenDOs.removeIf(token -> OAuthConstants.AuthorizedOrganization.NONE.equals(
                token.getAuthorizedOrganizationId()));

        if (!accessTokenDOs.isEmpty()) {
            List<String> accessTokens = new ArrayList<>();
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                String authorizedOrganizationId = accessTokenDO.getAuthorizedOrganizationId();
                if (StringUtils.equals(organizationId, authorizedOrganizationId)) {
                    accessTokens.add(accessTokenDO.getAccessToken());
                    clearCacheByAccessTokenAndConsumerKey(accessTokenDO, consumerKey);
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Access tokens are removed from the cache for OAuth application with " +
                        "consumer key: %s in organization with ID: %s", consumerKey, organizationId));
            }

            String tenantDomain = getTenantDomain(organizationId);
            revokeAccessTokens(accessTokens.toArray(new String[0]), consumerKey, tenantDomain);
            revokeOAuthConsentsForApplication(getApplicationName(consumerKey, tenantDomain), tenantDomain);
        }
        triggerPostApplicationTokenRevokeListeners(application, revokeRespDTO, accessTokenDOs);
        return revokeRespDTO;
    }

    /**
     * Get tenant domain corresponding to the provided organization ID.
     *
     * @param organizationId The organization ID.
     * @return The tenant domain.
     * @throws IdentityOAuthAdminException if an error occurs while retrieving the tenant domain.
     */
    private static String getTenantDomain(String organizationId) throws IdentityOAuthAdminException {

        try {
            return OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(organizationId);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuthAdminException("Error while resolving tenant domain of organization with ID : " +
                    organizationId, e);
        }
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
        String tenantAwareUserName = null;
        try {
            tenantAwareUserName = OAuthUtil.getUsername(tenantDomain);
            OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                    .updateApproveAlwaysForAppConsentByResourceOwner(tenantAwareUserName,
                            tenantDomain, appName, state);
        } catch (IdentityOAuth2Exception | IdentityApplicationManagementException e) {
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

    private String getLoggedInTenant(String consumerKey) throws IdentityOAuthAdminException {

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

    /**
     * Get the list of grant types that supports public clients.
     *
     * @return Array of grant types that supports public clients.
     */
    public String[] getPublicClientSupportedGrantTypes() {

        return PublicClientSupportedGrantTypeHolder.PUBLIC_CLIENT_SUPPORTED_GRANTS;
    }

    private static class PublicClientSupportedGrantTypeHolder {

        static final String[] PUBLIC_CLIENT_SUPPORTED_GRANTS;
        static {
            List<String> publicClientSupportedGrantTypes =
                    OAuthServerConfiguration.getInstance().getPublicClientSupportedGrantTypesList();
            if (publicClientSupportedGrantTypes == null || publicClientSupportedGrantTypes.isEmpty()) {
                PUBLIC_CLIENT_SUPPORTED_GRANTS = new String[0];
            } else {
                PUBLIC_CLIENT_SUPPORTED_GRANTS = publicClientSupportedGrantTypes.toArray(new String[0]);
            }
        }
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
     * @param encryptionMethod Encryption method sent in the registration request.
     * @return idTokenEncryptionMethod
     * @throws IdentityOAuthAdminException Identity OAuthAdmin exception.
     */
    private String filterEncryptionMethod(String encryptionMethod, String configName)
            throws IdentityOAuthAdminException {

        List<String> supportedEncryptionMethods = IdentityUtil.getPropertyAsList(configName);
        if (!supportedEncryptionMethods.contains(encryptionMethod)) {
            String msg = String.format("'%s' Encryption Method is not allowed.", encryptionMethod);
            throw handleClientError(INVALID_REQUEST, msg);
        }
        return encryptionMethod;
    }

    /**
     * Get the IdToken Encryption Algorithm registered by the user and filter the allowed one.
     *
     * @param algorithm algorithm sent in the registration request.
     * @return idTokenEncryptionAlgorithm
     * @throws IdentityOAuthAdminException Identity OAuthAdmin exception.
     */
    private String filterEncryptionAlgorithms(String algorithm, String configName)
            throws IdentityOAuthAdminException {

        List<String> supportedEncryptionAlgorithms = IdentityUtil.getPropertyAsList(configName);
        if (!supportedEncryptionAlgorithms.contains(algorithm)) {
            String msg = String.format("'%s' Encryption Algorithm is not allowed.", algorithm);
            throw handleClientError(INVALID_REQUEST, msg);
        }
        return algorithm;
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
                // Since the app owner sent in OAuthConsumerAppDTO is a valid one we set the appOwner to be
                // the one sent in the OAuthConsumerAppDTO.
                String tenantDomain = getAppTenantDomain();
                Optional<User> maybeAppOwner = OAuthUtil.getUser(tenantDomain, tenantAwareAppOwnerInRequest);
                if (maybeAppOwner.isPresent()) {
                    appOwner = new AuthenticatedUser(maybeAppOwner.get());
                } else {
                    LOG.warn("OAuth application owner user name " + applicationOwnerInRequest +
                            " does not exist in the user store. Using user: " +
                            defaultAppOwner.toFullQualifiedUsername() + " as app owner.");
                }
            } catch (IdentityApplicationManagementException e) {
                throw handleError("Error resolving the user requested as application owner: " +
                        applicationOwnerInRequest, e);
            }

        }
        return appOwner;
    }

    OAuth2Service getOAuth2Service() {

        return OAuthComponentServiceHolder.getInstance().getOauth2Service();
    }

    OAuthAppDO getOAuthApp(String consumerKey, String tenantDomain) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO oauthApp = AppInfoCache.getInstance().getValueFromCache(consumerKey, tenantDomain);
        if (oauthApp != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth app with consumerKey: " + consumerKey + " retrieved from AppInfoCache of tenant " +
                        "domain: " + tenantDomain);
            }
            return oauthApp;
        }

        OAuthAppDAO dao = new OAuthAppDAO();
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        oauthApp = dao.getAppInformation(consumerKey, tenantID);
        if (oauthApp != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth app with consumerKey: " + consumerKey + " retrieved from database.");
            }
            AppInfoCache.getInstance().addToCache(consumerKey, oauthApp, tenantDomain);
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
        validateDescription(scope.getDescription());
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
     * Check whether scope name is empty, contains white spaces and whether the scope name is too long.
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
        if (scopeName.length() > Oauth2ScopeConstants.MAX_LENGTH_OF_SCOPE_NAME) {
            throw handleClientError(INVALID_REQUEST, String.format(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_TOO_LONG.getMessage(), scopeName));
        }
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
     * Check whether the display name is provided or empty and whether the display name is too long.
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
        if (displayName.length() > Oauth2ScopeConstants.MAX_LENGTH_OF_SCOPE_DISPLAY_NAME) {
            throw handleClientError(INVALID_REQUEST, String.format(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_TOO_LONG.getMessage(), displayName));
        }
    }

    /**
     * Check whether the description is too long.
     *
     * @param description Description.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateDescription(String description) throws IdentityOAuthClientException {

        if (StringUtils.isNotBlank(description) &&
                description.length() > Oauth2ScopeConstants.MAX_LENGTH_OF_SCOPE_DESCRIPTION) {
            throw handleClientError(INVALID_REQUEST, String.format(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_DESCRIPTION_TOO_LONG.getMessage(), description));
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

    /**
     * Returns OIDC scopes registered in the tenant.
     *
     * @param tenantDomain tenant domain
     * @return List of OIDC scopes registered in tenant.
     * @throws IdentityOAuthAdminException exception if OIDC scope retrieval fails.
     */
    public List<String> getRegisteredOIDCScope(String tenantDomain) throws IdentityOAuthAdminException {

        try {
            int tenantId = getTenantId(tenantDomain);
            return OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().getScopeNames(tenantId);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error while loading OIDC scopes of tenant: " + tenantDomain, e);
        }
    }

    /**
     * Notify OAuthApplicationMgtListeners on post consumer app change events which have impact on token revocation.
     *
     * @param consumerKey consumer key of the application
     * @param properties  properties
     * @throws IdentityOAuthAdminException if an error occurs while handling the internal token revocation
     */
    private void handleInternalTokenRevocation(String consumerKey, Properties properties)
            throws IdentityOAuthAdminException {

        for (OAuthApplicationMgtListener oAuthApplicationMgtListener : OAuthComponentServiceHolder.getInstance()
                .getOAuthApplicationMgtListeners()) {
            oAuthApplicationMgtListener.doPostTokenRevocationOnClientAppEvent(consumerKey, properties);
            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuthApplicationMgtListener is triggered after revoking the OAuth secret.");
            }
        }
    }

    /**
     * Return whether the request of updating the tokenEndpointAllowReusePvtKeyJwt is valid.
     *
     * @param tokenEndpointAuthMethod     token endpoint client authentication method.
     * @param tokenEndpointAllowReusePvtKeyJwt During client authentication whether to reuse private key JWT.
     * @return True if tokenEndpointAuthMethod and tokenEndpointAllowReusePvtKeyJwt is NOT in the correct format.
     */
    private boolean isInvalidTokenEPReusePvtKeyJwtRequest(String tokenEndpointAuthMethod,
                                                          Boolean tokenEndpointAllowReusePvtKeyJwt) {

        if (StringUtils.isNotBlank(tokenEndpointAuthMethod)) {
            if (tokenEndpointAuthMethod.equals(PRIVATE_KEY_JWT)) {
                return tokenEndpointAllowReusePvtKeyJwt == null;
            }
        }
        return tokenEndpointAllowReusePvtKeyJwt != null;
    }

    /**
     * FAPI validation to restrict the token endpoint authentication methods.
     * Link - https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server (5.2.2 - 14)
     * @param authenticationMethod authentication methid used to authenticate to the token endpoint
     * @throws IdentityOAuthClientException
     */
    private void validateFAPITokenAuthMethods(String authenticationMethod) throws IdentityOAuthClientException {

        List<String> allowedAuthMethods = IdentityUtil.getPropertyAsList(
                OAuthConstants.FAPI_CLIENT_AUTH_METHOD_CONFIGURATION);
        if (authenticationMethod != null && !allowedAuthMethods.contains(authenticationMethod)) {
            throw handleClientError(INVALID_REQUEST, "Invalid token endpoint authentication method requested.");
        }
    }

    /**
     * FAPI validation to restrict the signature algorithms.
     * Link - https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations
     * @param signatureAlgorithm signature algorithm used to sign the assertions.
     * @throws IdentityOAuthClientException
     */
    private void validateFAPISignatureAlgorithms(String signatureAlgorithm)
            throws IdentityOAuthClientException {

        List<String> allowedSignatureAlgorithms = IdentityUtil
                .getPropertyAsList(OAuthConstants.FAPI_SIGNATURE_ALGORITHM_CONFIGURATION);
        if (signatureAlgorithm != null && !allowedSignatureAlgorithms.contains(signatureAlgorithm)) {
            throw handleClientError(INVALID_REQUEST, "Invalid signature algorithm requested");
        }
    }

    /**
     * FAPI validation to restrict the encryption algorithms.
     * Link - https://openid.net/specs/openid-financial-api-part-2-1_0.html#encryption-algorithm-considerations
     * @param encryptionAlgorithm
     * @throws IdentityOAuthClientException
     */
    private void validateFAPIEncryptionAlgorithms(String encryptionAlgorithm)
            throws IdentityOAuthClientException {

        if (encryptionAlgorithm.equals(OAuthConstants.RESTRICTED_ENCRYPTION_ALGORITHM)) {
            throw handleClientError(INVALID_REQUEST, "Invalid encryption algorithm requested");
        }
    }


    /**
     * If there are multiple hostnames in the registered redirect_uris,
     * the Client MUST register a sector_identifier_uri.
     * https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
     * @param redirectURIs list of callback urls sent in the request
     * @throws IdentityOAuthClientException
     */
    private void validateRedirectURIForPPID(List<String> redirectURIs)
            throws IdentityOAuthClientException {

        if (redirectURIs.size() > 1) {
            String hostname = URI.create(redirectURIs.get(0)).getHost();
            for (String redirectURI : redirectURIs) {
                URI uri = URI.create(redirectURI);
                if (!uri.getHost().equals(hostname)) {
                    throw handleClientError(INVALID_SUBJECT_TYPE_UPDATE,
                            "Sector Identifier URI is mandatory if multiple redirect URIs with different" +
                                    "hostnames are configured.");
                }
            }
        }
    }

    /**
     * The value of the sector_identifier_uri MUST be a URL using the https scheme
     * The values of the registered redirect_uris MUST be included in the elements of the array.
     * https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
     *
     * @param sectorIdentifierURI sector identifier URI
     * @param redirectURIs        callBack URLs
     * @throws IdentityOAuthClientException
     */
    private void validateSectorIdentifierURI(String sectorIdentifierURI, List<String> redirectURIs) throws
            IdentityOAuthClientException {

        URI uri = URI.create(sectorIdentifierURI);
        String scheme = uri.getScheme();
        if (!StringUtils.equals(scheme, String.valueOf(HttpsURL.DEFAULT_SCHEME))) {
            throw handleClientError(INVALID_REQUEST, "Invalid scheme for sector identifier URI");
        }
        // Validate whether sectorIdentifierURI points to JSON file containing an array of redirect_uri values.
        if (Boolean.parseBoolean(IdentityUtil.getProperty(OAuthConstants.VALIDATE_SECTOR_IDENTIFIER))) {
            try {
                List<String> fetchedRedirectURI = new ArrayList<>();
                ObjectMapper mapper = new ObjectMapper();
                JsonNode redirectURIArray = mapper.readTree(uri.toURL());
                if (redirectURIArray.isArray()) {
                    Iterator<JsonNode> itr = redirectURIArray.iterator();
                    while (itr.hasNext()) {
                        JsonNode item = itr.next();
                        fetchedRedirectURI.add(item.asText());
                    }
                }
                if (!fetchedRedirectURI.containsAll(redirectURIs)) {
                    throw handleClientError(INVALID_REQUEST, "Redirect URI missing in sector " +
                            "identifier URI set");
                }
            } catch (IOException e) {
                throw handleClientError(INVALID_REQUEST, "Invalid sector identifier URI");
            }
        }
    }

    /**
     * Get call back URIs as a list
     * @param application  OAuthConsumerAppDTO
     * @return list of callback urls
     */
    private List<String> getRedirectURIList(OAuthConsumerAppDTO application) {

        List<String> callBackURIList = new ArrayList<>();
        // Need to split the redirect uris for validating the host names since it is combined
        // into one regular expression.
        if (application.getCallbackUrl().startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            String redirectURI = application.getCallbackUrl();
            redirectURI = redirectURI.substring(redirectURI.indexOf("(") + 1,
                    redirectURI.indexOf(")"));
            callBackURIList = Arrays.asList(redirectURI.split("\\|"));
        }
        return callBackURIList;
    }

    /**
     * filter allowed signature algorithms
     *
     * @param algorithm  algorithm to be validated
     * @param configName configuration to read allowed algorithms
     * @throws IdentityOAuthClientException if the algorithm is not allowed
     */
    public void filterSignatureAlgorithms(String algorithm, String configName) throws IdentityOAuthClientException {

        List<String> allowedSignatureAlgorithms = IdentityUtil.getPropertyAsList(configName);
        if (!allowedSignatureAlgorithms.contains(algorithm)) {
            String msg = String.format("'%s' Signing Algorithm is not allowed.", algorithm);
            throw handleClientError(INVALID_REQUEST, msg);
        }
    }

    /**
     * filter allowed token endpoint authentication methods
     *
     * @param authMethod authentication method to be validated
     * @throws IdentityOAuthClientException if the token endpoint authentication method is not allowed
     */
    public void filterTokenEndpointAuthMethods(String authMethod) throws IdentityOAuthClientException {

        List<String> authMethods = Arrays.asList(OAuth2Util.getSupportedClientAuthMethods());
        if (!authMethods.contains(authMethod)) {
            String msg = String.format("'%s' Token endpoint authentication method is not allowed.", authMethod);
            throw handleClientError(INVALID_REQUEST, msg);
        }
    }

    private static void clearTokensFromCache(String consumerKey, AccessTokenDO detailToken, String token)
            throws IdentityOAuthAdminException {

        OAuthCacheKey cacheKeyToken = new OAuthCacheKey(token);
        OAuthCache.getInstance().clearCacheEntry(cacheKeyToken);

        String scope = buildScopeString(detailToken.getScope());
        String authorizedUser;
        try {
            authorizedUser = detailToken.getAuthzUser().getUserId();
        } catch (UserIdNotFoundException e) {
            /*
            * This fall back mechanism is added to support the token deletion process of the token exchange grant type.
            * When a token is issued from the token exchange grant type, the username for the token is set from the
            * `sub` property of the JWT token. This `sub` property of the JWT claim can be any value. When deleting
            * those access tokens while deleting the applications, it tried to resolve the user to remove the cache.
            * In that case, the user id extraction is failing because the user is searched from the username claim
            * by adding the `sub` value of the user. To prevent that, the authorized user will be extracted from the
            * subject identifier of the issued token.
            */
            if (detailToken.getAuthzUser().getAuthenticatedSubjectIdentifier() != null) {
                authorizedUser = detailToken.getAuthzUser().getAuthenticatedSubjectIdentifier();
            } else {
                throw handleError("Error when obtaining the user ID.", e);
            }
        }
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

    private static void clearTokenCacheEntry(String consumerKey, Set<AccessTokenDO> activeDetailedTokens)
            throws IdentityOAuthAdminException {

        for (AccessTokenDO detailToken : activeDetailedTokens) {
            String accessToken = detailToken.getAccessToken();
            try {
                accessToken = OAuth2Util.getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(accessToken);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Failed to retrieve the pre-processed access token for consumer key: "
                        + consumerKey, e);
            }
            clearTokensFromCache(consumerKey, detailToken, accessToken);
        }
    }

    /**
     * validate access token claims.
     *
     * @param consumerAppDTO OAuthConsumerAppDTO
     * @param tenantDomain   tenant domain
     * @throws IdentityOAuthAdminException if the claim is invalid
     */
    private void validateAccessTokenClaims(OAuthConsumerAppDTO consumerAppDTO, String tenantDomain)
            throws IdentityOAuthAdminException {

        if (consumerAppDTO.getAccessTokenClaims() != null) {
            Map<String, String> oidcToLocalClaimMappings;
            try {
                oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(tenantDomain);
                for (String claimURI : consumerAppDTO.getAccessTokenClaims()) {
                    if (!oidcToLocalClaimMappings.containsKey(claimURI)) {
                        throw handleClientError(INVALID_REQUEST, "Invalid access token claim URI: "
                                + claimURI);
                    }
                }
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error while retrieving OIDC to Local claim mappings for " +
                        "access token claims validation.", e);
            }
        }
    }

    /**
     * Adding requested claims in service provider as access token claims to the OAuthAppDO.
     *
     * @param oauthApp     OAuthAppDO
     * @param tenantDomain tenant domain
     * @throws IdentityOAuth2Exception if an error occurs while adding access token claims
     */
    private void addAccessTokenClaims(OAuthAppDO oauthApp, String tenantDomain) throws
            IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder
                .getApplicationMgtService();
        try {
            List<String> jwtAccessTokenClaims = new ArrayList<>();
            ServiceProvider serviceProvider = applicationMgtService.getServiceProvider(oauthApp.getApplicationName(),
                    tenantDomain);
            if (serviceProvider != null) {
                ClaimMapping[] claimMappings = serviceProvider.getClaimConfig().getClaimMappings();
                if (claimMappings != null && claimMappings.length > 0) {
                    Map<String, String> oidcToLocalClaimMappings = getOIDCToLocalClaimMappings(tenantDomain);
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (claimMapping.isRequested()) {
                            for (Map.Entry<String, String> entry : oidcToLocalClaimMappings.entrySet()) {
                                if (entry.getValue().equals(claimMapping.getLocalClaim().getClaimUri())) {
                                    jwtAccessTokenClaims.add(entry.getKey());
                                }
                            }
                        }
                    }
                }
            }
            oauthApp.setAccessTokenClaims(jwtAccessTokenClaims.toArray(new String[0]));
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while updating existing OAuth application to the new" +
                    "JWT access token OIDC claims separation model. Application : " + oauthApp.getApplicationName()
                    + " Tenant : " + tenantDomain, e);
        }
    }

    /**
     * Get OIDC to Local claim mappings.
     *
     * @param tenantDomain tenant domain
     * @return OIDC to Local claim mappings
     * @throws IdentityOAuth2Exception if an error occurs while retrieving OIDC to Local claim mappings
     */
    private Map<String, String> getOIDCToLocalClaimMappings(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, tenantDomain, false);
        } catch (ClaimMetadataException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OIDC to Local claim mappings.", e);
        }
    }

    private boolean isAccessTokenClaimsSeparationFeatureEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_CLAIMS_SEPARATION_FOR_ACCESS_TOKEN));
    }

    private boolean isAccessTokenClaimsSeparationEnabledForApp(String consumerKey, String tenantDomain)
            throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(consumerKey, tenantDomain);
        return OAuth2Util.isAppVersionAllowed(serviceProvider.getApplicationVersion(),
                ApplicationConstants.ApplicationVersion.APP_VERSION_V2);
    }

    private static String getAppTenantDomain() throws IdentityOAuthAdminException {

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
            try {
                tenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(applicationResidentOrgId);
            } catch (OrganizationManagementException e) {
                throw handleError("Error while resolving tenant domain from the organization id: "
                        + applicationResidentOrgId, e);
            }
        }
        return tenantDomain;
    }
}
