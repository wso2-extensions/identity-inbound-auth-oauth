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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * Handles the Password Grant Type of the OAuth 2.0 specification. Resource owner sends his
 * credentials in the token request which is validated against the corresponding user store.
 * Grant Type : password
 */
public class PasswordGrantHandler extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(PasswordGrantHandler.class);

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
        validateUserCredentials(tokenReq);
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
        String userTenantDomain = MultitenantUtils.getTenantDomain(tokenReq.getResourceOwnerUsername());
        if (!serviceProvider.isSaasApp() && !userTenantDomain.equals(tokenReq.getTenantDomain())) {
            if (log.isDebugEnabled()) {
                log.debug("Non-SaaS service provider. Application tenantDomain(" + tokenReq.getTenantDomain() + ") " +
                        "!= User tenant domain(" + userTenantDomain + ")");
            }
            throw new IdentityOAuth2Exception("Users in the tenant domain : " + userTenantDomain + " do not have" +
                    " access to application " + serviceProvider.getApplicationName());

        }
        return true;
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

    private boolean validateUserCredentials(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {
        boolean authenticated;
        try {
            UserStoreManager userStoreManager = getUserStoreManager(tokenReq);
            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(tokenReq.getResourceOwnerUsername());
            authenticated = userStoreManager.authenticate(tenantAwareUserName, tokenReq.getResourceOwnerPassword());
            if (log.isDebugEnabled()) {
                log.debug("user " + tokenReq.getResourceOwnerUsername() + " authenticated: " + authenticated);
            }
            if (!authenticated) {
                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(MultitenantUtils.getTenantDomain
                        (tokenReq.getResourceOwnerUsername()))) {
                    throw new IdentityOAuth2Exception("Authentication failed for " + tenantAwareUserName);
                }
                throw new IdentityOAuth2Exception("Authentication failed for " + tokenReq.getResourceOwnerUsername());
            }
        } catch (UserStoreException e) {
            String message = e.getMessage();
            if (!(e.getCause() instanceof IdentityException)) {
                throw new IdentityOAuth2Exception(message, e);
            }
            IdentityException identityException = (IdentityException) (e.getCause());
            // Set error code to message if available.
            if (StringUtils.isNotBlank(identityException.getErrorCode())) {
                message = identityException.getErrorCode() + " " + e.getMessage();
            }
            throw new IdentityOAuth2Exception(message, e);
        }
        return true;
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
