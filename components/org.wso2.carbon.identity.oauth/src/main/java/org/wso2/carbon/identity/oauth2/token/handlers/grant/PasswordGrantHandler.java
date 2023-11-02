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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.config.UserStorePreferenceOrderSupplier;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.model.UserMgtContext;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ALLOW_SESSION_CREATION;


/**
 * Handles the Password Grant Type of the OAuth 2.0 specification. Resource owner sends his
 * credentials in the token request which is validated against the corresponding user store.
 * Grant Type : password
 */
public class PasswordGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(PasswordGrantHandler.class);
    private static final String OAUTH2 = "oauth2";
    private static final String IS_INITIAL_LOGIN = "isInitialLogin";
    private static final String PASSWORD_GRANT_AUTHENTICATOR_NAME = "BASIC";
    private static final String PUBLISH_PASSWORD_GRANT_LOGIN = "OAuth.PublishPasswordGrantLogin";
    private static final String REMOTE_IP_ADDRESS = "remote-ip-address";
    private static final String PASSWORD_GRANT_POST_AUTHENTICATION_EVENT = "PASSWORD_GRANT_POST_AUTHENTICATION";
    private static final String OIDC = "oidc";
    private static final String CLIENT_ID = "client_id";
    private static final String SP = "sp";
    private static final String RELYING_PARTY = "relyingParty";
    private static final String TENANT_DOMAIN = "tenantDomain";
    private static final String COMMON_AUTH_CALLER_PATH = "commonAuthCallerPath";
    private static final String AUTH_REQUEST = "authRequest";
    private static final String SESSION_DATA_KEY = "sessionDataKey";
    private static final String TYPE = "type";
    private static final String AUTHENTICATED_USER = "authenticatedUser";
    private static final String ENABLE_PASSWORD_FLOW_ENHANCEMENTS = "enablePasswordFlowEnhancements";


    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.GrantTypes.PASSWORD);
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        ServiceProvider serviceProvider = getServiceProvider(tokenReq);

        // Update resource owner username when tenant qualified URLs enabled.
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            String userNameWithTenant = getFullQualifiedUsername(tokenReq, serviceProvider);
            tokenReq.setResourceOwnerUsername(userNameWithTenant);
        }

        AuthenticatedUser authenticatedUser = validateUserCredentials(tokenReq, serviceProvider);
        setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq, authenticatedUser);
        return true;
    }

    private Optional<AuthenticatedUser>  authenticateUserAtUserStore(OAuth2AccessTokenReqDTO tokenReq, String userId,
                                                                     AbstractUserStoreManager userStoreManager,
                                                                     String tenantAwareUserName,
                                                                     boolean isPublishPasswordGrantLoginEnabled,
                                                                     String userTenantDomain,
                                                                     ServiceProvider serviceProvider)
            throws org.wso2.carbon.user.core.UserStoreException, IdentityOAuth2Exception {

        AuthenticationResult authenticationResult;

        if (userId != null) {
            authenticationResult = userStoreManager.authenticateWithID(userId, tokenReq.getResourceOwnerPassword());
        } else {
            authenticationResult = userStoreManager.authenticateWithID(
                    UserCoreClaimConstants.USERNAME_CLAIM_URI, tenantAwareUserName,
                    tokenReq.getResourceOwnerPassword(), UserCoreConstants.DEFAULT_PROFILE);
        }
        boolean authenticated = AuthenticationResult.AuthenticationStatus.SUCCESS
                == authenticationResult.getAuthenticationStatus()
                && authenticationResult.getAuthenticatedUser().isPresent();
        if (log.isDebugEnabled()) {
            log.debug("user " + tokenReq.getResourceOwnerUsername() + " authenticated: " + authenticated);
        }
        if (authenticated) {
            AuthenticatedUser authenticatedUser =
                    new AuthenticatedUser(authenticationResult.getAuthenticatedUser().get());
            if (isPublishPasswordGrantLoginEnabled) {
                publishAuthenticationData(tokenReq, true, serviceProvider, authenticatedUser);
            }
            return Optional.of(authenticatedUser);
        }

        triggerPasswordExpiryValidationEvent(PASSWORD_GRANT_POST_AUTHENTICATION_EVENT, tenantAwareUserName,
                userTenantDomain, userStoreManager, true);
        if (log.isDebugEnabled()) {
            log.debug(PASSWORD_GRANT_POST_AUTHENTICATION_EVENT + " event is triggered");
        }
        return Optional.empty();
    }

    private Optional<AuthenticatedUser> authenticateUserAtFramework(OAuth2AccessTokenReqDTO tokenReq,
                                                                    ServiceProvider serviceProvider)
            throws IdentityOAuth2Exception {

        HttpServletRequest request = tokenReq.getHttpServletRequestWrapper();
        HttpServletResponse response = tokenReq.getHttpServletResponseWrapper();
        try {
            CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(request);
            requestWrapper.setParameter(TYPE, OIDC);
            String tenantDomain = serviceProvider.getTenantDomain();
            String clientId = null;
            if (serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() != null) {
                for (InboundAuthenticationRequestConfig oauth2config :
                        serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                    if (oauth2config.getInboundAuthType().equals(OAUTH2)) {
                        clientId = oauth2config.getInboundAuthKey();
                        break;
                    }
                }
            }
            if (clientId == null) {
                log.error(String.format("Invalid client of application : %s , " +
                                "trying to authenticate for the user: %s ", serviceProvider.getApplicationName(),
                        tokenReq.getResourceOwnerUsername()));
                throw new IdentityOAuth2Exception("Authentication failed for " + tokenReq.getResourceOwnerUsername());
            }

            AuthenticationRequest authenticationRequest = new AuthenticationRequest();
            authenticationRequest.setRelyingParty(clientId);
            // To ensure the authentication result is added to the cache
            authenticationRequest.setType(OIDC);
            // To nullify the effect of commonAuthId cookie that will be returned in responses
            authenticationRequest.setForceAuth(true);
            authenticationRequest.setCommonAuthCallerPath(request.getRequestURI());
            authenticationRequest.setTenantDomain(tenantDomain);
            AuthenticationRequestCacheEntry authenticationRequestCacheEntry =
                    new AuthenticationRequestCacheEntry(authenticationRequest);
            requestWrapper.setParameter(RELYING_PARTY, clientId);
            requestWrapper.setAttribute(SP, serviceProvider.getApplicationName());
            requestWrapper.setAttribute(AUTH_REQUEST, authenticationRequestCacheEntry);
            requestWrapper.setParameter(COMMON_AUTH_CALLER_PATH, request.getRequestURI());
            requestWrapper.setParameter(CLIENT_ID, clientId);
            requestWrapper.setParameter(TENANT_DOMAIN, tenantDomain);
            requestWrapper.setParameter(SESSION_DATA_KEY, UUID.randomUUID().toString());
            requestWrapper.setAttribute(ALLOW_SESSION_CREATION, Boolean.FALSE.toString());
            CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(response);

            AuthenticationService authenticationService = new AuthenticationService();
            AuthServiceResponse authServiceResponse = authenticationService.
                    handleAuthentication(new AuthServiceRequest(requestWrapper, responseWrapper));

            if (authServiceResponse.getSessionDataKey() != null && AuthenticatorFlowStatus.SUCCESS_COMPLETED.toString().
                    equals(authServiceResponse.getFlowStatus().toString())) {
                String sessionDataKey = authServiceResponse.getSessionDataKey();
                org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult
                        authResult = null;
                AuthenticationResultCacheEntry authResultCacheEntry = FrameworkUtils
                        .getAuthenticationResultFromCache(sessionDataKey);
                if (authResultCacheEntry != null) {
                    authResult = authResultCacheEntry.getResult();
                    if (authResult.isAuthenticated()) {
                        if (log.isDebugEnabled()) {
                            log.debug("user " + tokenReq.getResourceOwnerUsername() + " authenticated: true");
                        }
                        request.setAttribute(AUTHENTICATED_USER, authResult.getSubject());
                        return Optional.of(authResult.getSubject());
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("user " + tokenReq.getResourceOwnerUsername() + " authenticated: false");
            }
        } catch (AuthServiceException e) {
            log.error("Error occurred while authenticating user: " + tokenReq.getResourceOwnerUsername());
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        return Optional.empty();
    }

    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq,
                                                 AuthenticatedUser authenticatedUser) {

        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
        tokReqMsgCtx.setScope(tokenReq.getScope());
    }

    private String getFullQualifiedUsername(OAuth2AccessTokenReqDTO tokenReq, ServiceProvider serviceProvider) {

        boolean isEmailUserNameEnabled = MultitenantUtils.isEmailUserName();
        boolean isSaasApp = serviceProvider.isSaasApp();
        boolean isLegacySaaSAuthenticationEnabled = IdentityTenantUtil.isLegacySaaSAuthenticationEnabled();
        String usernameFromRequest = tokenReq.getResourceOwnerUsername();
        String tenantDomainFromContext = IdentityTenantUtil.resolveTenantDomain();

        if (!isSaasApp) {
            /*
            For non-Saas app tenant domain from context is appended to the username from request.
            When using tenant qualified URLs, providing tenant-aware username is expected.
             */
            return UserCoreUtil.addTenantDomainToEntry(usernameFromRequest, tenantDomainFromContext);
        } else if (isLegacySaaSAuthenticationEnabled) { // isSaasApp && isLegacySaaSAuthenticationEnabled.
            return usernameFromRequest;
        } else { // isSaasApp && !isLegacySaaSAuthenticationEnabled.

            /*
            If !isEmailUserNameEnabled, then username containing '@' symbol and a username containing
            a tenant domain can't be distinguished.
            Hence, tenant-qualified username is expected.
             */
            String tenantDomainFromUser = MultitenantUtils.getTenantDomain(usernameFromRequest);
            if (isEmailUserNameEnabled && StringUtils.equalsIgnoreCase(tenantDomainFromUser,
                    MultitenantConstants.SUPER_TENANT_DOMAIN_NAME) &&
                    !usernameFromRequest.endsWith(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                return UserCoreUtil.addTenantDomainToEntry(usernameFromRequest, tenantDomainFromContext);
            }
            return usernameFromRequest;
        }
    }

    private ServiceProvider getServiceProvider(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {
        ServiceProvider serviceProvider;
        try {
            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(
                    tokenReq.getClientId(), OAuthConstants.Scope.OAUTH2, tokenReq.getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id " +
                    tokenReq.getClientId(), e);
        }
        if (serviceProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find an application for client id: " + tokenReq.getClientId()
                        + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " + tokenReq.getTenantDomain());
            }
            throw new IdentityOAuth2Exception("Service Provider not found");
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved service provider: " + serviceProvider.getApplicationName() + " for client: " +
                    tokenReq.getClientId() + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " +
                    tokenReq.getTenantDomain());
        }

        return serviceProvider;
    }

    private AuthenticatedUser validateUserCredentials(OAuth2AccessTokenReqDTO tokenReq, ServiceProvider serviceProvider)
            throws IdentityOAuth2Exception {

        boolean isPublishPasswordGrantLoginEnabled = Boolean.parseBoolean(
                IdentityUtil.getProperty(PUBLISH_PASSWORD_GRANT_LOGIN));
        try {
            // Get the user store preference order supplier.
            UserStorePreferenceOrderSupplier<List<String>> userStorePreferenceOrderSupplier =
                    FrameworkUtils.getUserStorePreferenceOrderSupplier(null, serviceProvider);
            UserMgtContext userMgtContext = new UserMgtContext();
            userMgtContext.setUserStorePreferenceOrderSupplier(userStorePreferenceOrderSupplier);
            if (userStorePreferenceOrderSupplier != null) {
                UserCoreUtil.setUserMgtContextInThreadLocal(userMgtContext);
                if (log.isDebugEnabled()) {
                    log.debug("UserMgtContext had been set as the thread local.");
                }
            }

            String username = tokenReq.getResourceOwnerUsername();
            if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
                FrameworkUtils.validateUsername(username);
                username = FrameworkUtils.preprocessUsername(username, serviceProvider);
            }

            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
            String userTenantDomain = MultitenantUtils.getTenantDomain(username);
            ResolvedUserResult resolvedUserResult =
                    FrameworkUtils.processMultiAttributeLoginIdentification(tenantAwareUserName, userTenantDomain);
            String userId = null;
            if (resolvedUserResult != null &&
                    ResolvedUserResult.UserResolvedStatus.SUCCESS.equals(resolvedUserResult.getResolvedStatus())) {
                tenantAwareUserName = resolvedUserResult.getUser().getUsername();
                userId = resolvedUserResult.getUser().getUserID();
                tokenReq.setResourceOwnerUsername(tenantAwareUserName + "@" + userTenantDomain);
            }

            AbstractUserStoreManager userStoreManager = getUserStoreManager(userTenantDomain);
            Optional<AuthenticatedUser> authenticatedUser;
            ServiceProviderProperty[] spProps = serviceProvider.getSpProperties();
            if (spProps != null && Arrays.stream(spProps)
                    .anyMatch(property -> ENABLE_PASSWORD_FLOW_ENHANCEMENTS.equals(property.getName())
                            && Boolean.parseBoolean(property.getValue()))) {
                authenticatedUser = authenticateUserAtFramework(tokenReq, serviceProvider);
            } else {
                authenticatedUser = authenticateUserAtUserStore(tokenReq, userId, userStoreManager,
                        tenantAwareUserName, isPublishPasswordGrantLoginEnabled, userTenantDomain, serviceProvider);
            }
            if (authenticatedUser.isPresent()) {
                return authenticatedUser.get();
            }
            triggerPasswordExpiryValidationEvent(PASSWORD_GRANT_POST_AUTHENTICATION_EVENT, tenantAwareUserName,
                    userTenantDomain, userStoreManager, false);
            if (log.isDebugEnabled()) {
                log.debug(PASSWORD_GRANT_POST_AUTHENTICATION_EVENT + " event is triggered");
            }
            if (isPublishPasswordGrantLoginEnabled) {
                publishAuthenticationData(tokenReq, false, serviceProvider);
            }
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(MultitenantUtils.getTenantDomain
                    (tokenReq.getResourceOwnerUsername()))) {
                throw new IdentityOAuth2Exception("Authentication failed for " + tenantAwareUserName);
            }
            username = tokenReq.getResourceOwnerUsername();
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                // For tenant qualified urls, no need to send fully qualified username in response.
                username = tenantAwareUserName;
            }
            throw new IdentityOAuth2Exception("Authentication failed for " + username);
        } catch (UserStoreClientException e) {
            if (isPublishPasswordGrantLoginEnabled) {
                publishAuthenticationData(tokenReq, false, serviceProvider);
            }
            String message = e.getMessage();
            if (StringUtils.isNotBlank(e.getErrorCode())) {
                message = e.getErrorCode() + " " + e.getMessage();
            }
            throw new IdentityOAuth2Exception(message, e);
        } catch (UserStoreException e) {
            if (isPublishPasswordGrantLoginEnabled) {
                publishAuthenticationData(tokenReq, false, serviceProvider);
            }
            String message = e.getMessage();
            // Sometimes client exceptions are wrapped in the super class.
            // Therefore, checking for possible client exception.
            Throwable rootCause = ExceptionUtils.getRootCause(e);
            if (rootCause instanceof UserStoreClientException) {
                message = rootCause.getMessage();
                String errorCode = ((UserStoreClientException) rootCause).getErrorCode();
                if (StringUtils.isNotBlank(errorCode)) {
                    message = errorCode + " " + message;
                }
            }
            if (e.getCause() instanceof IdentityException) {
                IdentityException identityException = (IdentityException) (e.getCause());
                // Set error code to message if available.
                if (StringUtils.isNotBlank(identityException.getErrorCode())) {
                    message = identityException.getErrorCode() + " " + e.getMessage();
                }
            }
            throw new IdentityOAuth2Exception(message, e);
        } catch (AuthenticationFailedException e) {
            String message = "Authentication failed for the user: " + tokenReq.getResourceOwnerUsername();
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new IdentityOAuth2Exception(message);
        } finally {
            UserCoreUtil.removeUserMgtContextInThreadLocal();
            if (log.isDebugEnabled()) {
                log.debug("UserMgtContext had been remove from the thread local.");
            }
        }
    }

    /**
     * This method will publish the Password Grant Authentication data.
     *
     * @param tokenReq        Token request which contains all the details of the request.
     * @param authenticated   Boolean value which determines whether the user is authenticated or not.
     * @param serviceProvider Service provider which contains the details of the application.
     */
    protected void publishAuthenticationData(OAuth2AccessTokenReqDTO tokenReq, boolean authenticated,
                                             ServiceProvider serviceProvider) {

        //Since the user id/user object is not already resolved when the user id not authenticated, we have to
        // resolve it from here.
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tokenReq, serviceProvider);
        publishAuthenticationData(tokenReq, authenticated, serviceProvider, authenticatedUser);
    }

    /**
     * This method will publish the Password Grant Authentication data.
     *
     * @param tokenReq          Token request which contains all the details of the request.
     * @param authenticated     Boolean value which determines whether the user is authenticated or not.
     * @param serviceProvider   Service provider which contains the details of the application.
     * @param authenticatedUser authenticated user.
     */
    protected void publishAuthenticationData(OAuth2AccessTokenReqDTO tokenReq, boolean authenticated,
                                             ServiceProvider serviceProvider, AuthenticatedUser authenticatedUser) {

        AuthenticationContext authenticationContext = initializeAuthContext(authenticatedUser, serviceProvider);
        AuthenticationDataPublisher authnDataPublisherProxy =
                OAuth2ServiceComponentHolder.getAuthenticationDataPublisherProxy();
        if (authnDataPublisherProxy != null && authnDataPublisherProxy.isEnabled(authenticationContext)) {
            Map<String, Object> paramMap = new HashMap<>();
            paramMap.put(FrameworkConstants.AnalyticsAttributes.USER, authenticatedUser);
            paramMap.put(REMOTE_IP_ADDRESS, IdentityUtil.getClientIpAddress(tokenReq.getHttpServletRequestWrapper()));
            Map<String, Object> unmodifiableParamMap = Collections.unmodifiableMap(paramMap);
            if (authenticated) {
                authnDataPublisherProxy
                        .publishAuthenticationStepSuccess(null, authenticationContext, unmodifiableParamMap);
                authnDataPublisherProxy.publishAuthenticationSuccess(null, authenticationContext, unmodifiableParamMap);
            } else {
                authnDataPublisherProxy.
                        publishAuthenticationStepFailure(null, authenticationContext, unmodifiableParamMap);
                authnDataPublisherProxy.publishAuthenticationFailure(null, authenticationContext,
                        unmodifiableParamMap);
            }
        }
    }

    /**
     * This method will create an AuthenticationContext object which needs to be passed to the publish methods.
     *
     * @param authenticatedUser User which tries to be authenticated.
     * @param serviceProvider Service provider which contains the details of the application.
     * @return An AuthenticationContest object with relevant details.
     */
    private AuthenticationContext initializeAuthContext(AuthenticatedUser authenticatedUser,
                                                        ServiceProvider serviceProvider) {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        String contextId = UUID.randomUUID().toString();
        authenticationContext.setContextIdentifier(contextId);
        authenticationContext.setTenantDomain(authenticatedUser.getTenantDomain());
        authenticationContext.setRequestType(OAUTH2);
        authenticationContext.setRememberMe(false);
        authenticationContext.setForceAuthenticate(true);
        authenticationContext.setPassiveAuthenticate(false);
        authenticationContext.setProperty(IS_INITIAL_LOGIN, true);

        // Setting sequenceConfig with authenticatedUser, serviceProvider.
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setAuthenticatedUser(authenticatedUser);

        // Setting applicationConfig with serviceProvider.
        ApplicationConfig applicationConfig = new ApplicationConfig(serviceProvider);
        sequenceConfig.setApplicationConfig(applicationConfig);

        sequenceConfig.setAuthenticatedIdPs(FrameworkConstants.LOCAL_IDP_NAME);
        authenticationContext.setSequenceConfig(sequenceConfig);

         /* Setting the authenticated IDP for currentAuthenticatedIDPs to get
         the tenant domain and other parameters when the login is a success. */
        AuthenticatedIdPData authenticatedIdPData = new AuthenticatedIdPData();
        authenticatedIdPData.setUser(authenticatedUser);
        authenticatedIdPData.setIdpName(FrameworkConstants.LOCAL_IDP_NAME);

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setName(PASSWORD_GRANT_AUTHENTICATOR_NAME);
        authenticatedIdPData.addAuthenticator(authenticatorConfig);
        authenticationContext.getCurrentAuthenticatedIdPs().put(FrameworkConstants.LOCAL_IDP_NAME,
                authenticatedIdPData);

        // Setting serviceProviderName from applicationConfig.
        authenticationContext.setServiceProviderName(sequenceConfig.getApplicationConfig().getApplicationName());

        return authenticationContext;
    }

    private AbstractUserStoreManager getUserStoreManager(String tenantDomain)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(tenantDomain);
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        AbstractUserStoreManager userStoreManager;
        try {
            userStoreManager
                    = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved user store manager for tenant id: " + tenantId);
        }
        return userStoreManager;
    }

    private int getTenantId(String tenantDomain) throws IdentityOAuth2Exception {

        int tenantId;
        try {
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            log.error("Token request with Password Grant Type for an invalid tenant : " + tenantDomain);
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved tenant id: " + tenantId + " for tenant domain: " + tenantDomain);
        }
        return tenantId;
    }

    private AuthenticatedUser getAuthenticatedUser(OAuth2AccessTokenReqDTO tokenReq, ServiceProvider serviceProvider) {
        String username = getFullQualifiedUsername(tokenReq);
        AuthenticatedUser user = OAuth2Util.getUserFromUserName(username);
        user.setAuthenticatedSubjectIdentifier(user.getUserName(), serviceProvider);
        if (log.isDebugEnabled()) {
            log.debug("Token request with password grant type from user: " + user);
        }
        return user;
    }

    private String getFullQualifiedUsername(OAuth2AccessTokenReqDTO tokenReq) {
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(tokenReq.getResourceOwnerUsername());
        String userTenantDomain = MultitenantUtils.getTenantDomain(tokenReq.getResourceOwnerUsername());
        String userNameWithTenant = tenantAwareUsername + UserCoreConstants.TENANT_DOMAIN_COMBINER + userTenantDomain;
        if (!userNameWithTenant.contains(CarbonConstants.DOMAIN_SEPARATOR) &&
                StringUtils.isNotBlank(UserCoreUtil.getDomainFromThreadLocal())) {
            if (log.isDebugEnabled()) {
                log.debug("User store domain is not found in username. Adding domain: " +
                        UserCoreUtil.getDomainFromThreadLocal());
            }
            return UserCoreUtil.getDomainFromThreadLocal() + CarbonConstants.DOMAIN_SEPARATOR +
                    userNameWithTenant;
        }
        return userNameWithTenant;

    }

    /**
     * This method will trigger an event to check whether the password is expired.
     * @param eventName name of the event
     * @param username authenticated user
     * @param tenantDomain tenant domain of the user
     * @param userStoreManager
     * @throws IdentityOAuth2Exception if password is expired or any other exceptions
     */
    private void triggerPasswordExpiryValidationEvent(String eventName, String username, String tenantDomain,
                                                      org.wso2.carbon.user.core.UserStoreManager userStoreManager,
                                                      boolean authenticated) throws IdentityOAuth2Exception {

        IdentityEventService eventService = OAuth2ServiceComponentHolder.getIdentityEventService();
        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, username);
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        eventProperties.put(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS, authenticated);

        Event event = new Event(eventName, eventProperties);
        try {
            if (eventService != null) {
                eventService.handleEvent(event);
            }
        } catch (IdentityEventException e) {
            throw new IdentityOAuth2Exception("Authentication Failed! " + e.getMessage(), e); // Password has expired
        }
    }
}
