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
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.config.UserStorePreferenceOrderSupplier;
import org.wso2.carbon.user.core.model.UserMgtContext;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

        validateUserTenant(tokenReq, serviceProvider);
        validateUserCredentials(tokenReq, serviceProvider);
        setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq, serviceProvider);
        return true;
    }

    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, ServiceProvider serviceProvider) {
        AuthenticatedUser user = getAuthenticatedUser(tokenReq, serviceProvider);
        tokReqMsgCtx.setAuthorizedUser(user);
        tokReqMsgCtx.setScope(tokenReq.getScope());
    }

    private boolean validateUserTenant(OAuth2AccessTokenReqDTO tokenReq, ServiceProvider serviceProvider)
            throws IdentityOAuth2Exception {

        String userTenantDomain = null;

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            String userNameWithTenant = getFullQualifiedUsernameWhenTenantQualifiedUrlEnabled(tokenReq,
                    serviceProvider);
            userTenantDomain = MultitenantUtils.getTenantDomain(userNameWithTenant);
            tokenReq.setResourceOwnerUsername(userNameWithTenant);
        }

        if (StringUtils.isBlank(userTenantDomain)) {
            userTenantDomain = MultitenantUtils.getTenantDomain(tokenReq.getResourceOwnerUsername());
        }

        if (!serviceProvider.isSaasApp() && !userTenantDomain.equals(tokenReq.getTenantDomain())) {
            if (log.isDebugEnabled()) {
                log.debug("Non-SaaS service provider. Application tenantDomain(" + tokenReq.getTenantDomain() + ") "
                        + "!= User tenant domain(" + userTenantDomain + ")");
            }
            throw new IdentityOAuth2Exception("Users in the tenant domain : " + userTenantDomain + " do not have" +
                    " access to application " + serviceProvider.getApplicationName());
        }
        return true;
    }

    private String getFullQualifiedUsernameWhenTenantQualifiedUrlEnabled(OAuth2AccessTokenReqDTO tokenReq,
                                                                         ServiceProvider serviceProvider) {

        boolean isEmailUserNameEnabled = MultitenantUtils.isEmailUserName();
        boolean isSaasApp = serviceProvider.isSaasApp();
        boolean isLegacySaaSAuthenticationEnabled = IdentityTenantUtil.isLegacySaaSAuthenticationEnabled();
        String usernameFromRequest = tokenReq.getResourceOwnerUsername();
        String tenantDomainFromContext = IdentityTenantUtil.getTenantDomainFromContext();

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

    private boolean validateUserCredentials(OAuth2AccessTokenReqDTO tokenReq, ServiceProvider serviceProvider) throws
            IdentityOAuth2Exception {

        boolean authenticated;
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
            UserStoreManager userStoreManager = getUserStoreManager(tokenReq);
            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(tokenReq.getResourceOwnerUsername());
            String userTenantDomain = MultitenantUtils.getTenantDomain(tokenReq.getResourceOwnerUsername());
            ResolvedUserResult resolvedUserResult =
                    FrameworkUtils.processMultiAttributeLoginIdentification(tenantAwareUserName, userTenantDomain);
            if (resolvedUserResult != null &&
                    ResolvedUserResult.UserResolvedStatus.SUCCESS.equals(resolvedUserResult.getResolvedStatus())) {
                tenantAwareUserName = resolvedUserResult.getUser().getUsername();
                tokenReq.setResourceOwnerUsername(tenantAwareUserName + "@" + userTenantDomain);
            }
            authenticated = userStoreManager.authenticate(tenantAwareUserName, tokenReq.getResourceOwnerPassword());
            if (log.isDebugEnabled()) {
                log.debug("user " + tokenReq.getResourceOwnerUsername() + " authenticated: " + authenticated);
            }
            if (!authenticated) {
                if (isPublishPasswordGrantLoginEnabled) {
                    publishAuthenticationData(tokenReq, false, serviceProvider);
                }
                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(MultitenantUtils.getTenantDomain
                        (tokenReq.getResourceOwnerUsername()))) {
                    throw new IdentityOAuth2Exception("Authentication failed for " + tenantAwareUserName);
                }
                String username = tokenReq.getResourceOwnerUsername();
                if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                    // For tenant qualified urls, no need to send fully qualified username in response.
                    username = tenantAwareUserName;
                }
                throw new IdentityOAuth2Exception("Authentication failed for " + username);
            } else if (isPublishPasswordGrantLoginEnabled) {
                publishAuthenticationData(tokenReq, true, serviceProvider);
            }
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
            // Therefore checking for possible client exception.
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
        }  finally {
            UserCoreUtil.removeUserMgtContextInThreadLocal();
            if (log.isDebugEnabled()) {
                log.debug("UserMgtContext had been remove from the thread local.");
            }
        }
        return true;
    }

    /**
     * This method will publish the Password Grant Authentication data.
     *
     * @param tokenReq Token request which contains all the details of the request.
     * @param authenticated Boolean value which determines whether the user is authenticated or not.
     * @param serviceProvider Service provider which contains the details of the application.
     */
    protected void publishAuthenticationData(OAuth2AccessTokenReqDTO tokenReq, boolean authenticated,
                                           ServiceProvider serviceProvider) {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tokenReq, serviceProvider);
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
     * @param authenticatedUser User which tries to be authenticate.
     * @param serviceProvider Service provider which contains the details of the application.
     * @return An AuthenticationContest object with relevant details.
     */
    private AuthenticationContext initializeAuthContext(AuthenticatedUser authenticatedUser,
                                                        ServiceProvider serviceProvider) {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        String contextId = UUIDGenerator.generateUUID();
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

    private UserStoreManager getUserStoreManager(OAuth2AccessTokenReqDTO tokenReq)
            throws IdentityOAuth2Exception {
        int tenantId = getTenantId(tokenReq);
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        UserStoreManager userStoreManager;
        try {
            userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved user store manager for tenant id: " + tenantId);
        }
        return userStoreManager;
    }

    private int getTenantId(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {
        String username = tokenReq.getResourceOwnerUsername();
        String userTenantDomain = MultitenantUtils.getTenantDomain(username);

        int tenantId;
        try {
            tenantId = IdentityTenantUtil.getTenantId(userTenantDomain);
        } catch (IdentityRuntimeException e) {
            log.error("Token request with Password Grant Type for an invalid tenant : " + userTenantDomain);
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved tenant id: " + tenantId + " for tenant domain: " + userTenantDomain);
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
}
