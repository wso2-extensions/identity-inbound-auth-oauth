/*
 * Copyright (c) 2013-2026, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants.StandardInboundProtocols;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.SharedAppResolveDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.CURRENT_SESSION_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.CURRENT_TOKEN_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.OAUTH2;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ORGANIZATION_LOGIN_HOME_REALM_IDENTIFIER;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.DEFAULT_VALUE_FOR_PREVENT_TOKEN_REUSE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.ENABLE_TOKEN_REUSE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.JWT_CONFIGURATION_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.JWT_CONFIGURATION_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.PREVENT_TOKEN_REUSE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.PVT_KEY_JWT_CLIENT_AUTHENTICATOR_CLASS_NAME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX;

/**
 * OAuth utility functionality.
 */
public final class OAuthUtil {

    public static final Log LOG = LogFactory.getLog(OAuthUtil.class);
    private static final String ALGORITHM_SHA1 = "HmacSHA1";
    private static final String ALGORITHM_SHA256 = "HmacSHA256";
    private static final String managedOrgClaim = "http://wso2.org/claims/identity/managedOrg";

    private OAuthUtil() {

    }

    /**
     * Generates a random number using two UUIDs and HMAC-SHA1
     *
     * @return generated secure random number
     * @throws IdentityOAuthAdminException Invalid Algorithm or Invalid Key
     */
    public static String getRandomNumber() throws IdentityOAuthAdminException {
        try {
            String secretKey = UUID.randomUUID().toString();
            String baseString = UUID.randomUUID().toString();
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(Charsets.UTF_8), ALGORITHM_SHA1);
            Mac mac = Mac.getInstance(ALGORITHM_SHA1);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(baseString.getBytes(Charsets.UTF_8));
            String random = Base64.encode(rawHmac);
            // Registry doesn't have support for these character.
            random = random.replace("/", "_");
            random = random.replace("=", "a");
            random = random.replace("+", "f");
            return random;
        } catch (Exception e) {
            throw new IdentityOAuthAdminException("Error when generating a random number.", e);
        }
    }

    /**
     * Generates a securer random number using two UUIDs and HMAC-SHA256
     *
     * @return generated secure random number
     * @throws IdentityOAuthAdminException Invalid Algorithm or Invalid Key
     */
    public static String getRandomNumberSecure() throws IdentityOAuthAdminException {
        try {
            String secretKey = UUID.randomUUID().toString();
            String baseString = UUID.randomUUID().toString();

            String hmacAlgorithm;
            if (Boolean.parseBoolean(IdentityUtil.getProperty(IdentityConstants.OAuth.ENABLE_SHA256_PARAMS))) {
                hmacAlgorithm = ALGORITHM_SHA256;
            } else {
                hmacAlgorithm = ALGORITHM_SHA1;
            }
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(Charsets.UTF_8), hmacAlgorithm);
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(baseString.getBytes(Charsets.UTF_8));
            String random = Base64.encode(rawHmac);
            // Registry doesn't have support for these character.
            random = random.replace("/", "_");
            random = random.replace("=", "a");
            random = random.replace("+", "f");
            return random;
        } catch (Exception e) {
            throw new IdentityOAuthAdminException("Error when generating a random number.", e);
        }
    }

    /**
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser)} instead.
     * @param consumerKey
     * @param authorizedUser
     */
    @Deprecated
    public static void clearOAuthCache(String consumerKey, User authorizedUser) {

        if (authorizedUser instanceof AuthenticatedUser) {
            clearOAuthCache(consumerKey, (AuthenticatedUser) authorizedUser);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User object is not an instance of AuthenticatedUser therefore cannot resolve " +
                        "authenticatedIDP name.");
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
            String userId;
            try {
                userId = authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                // Masking getLoggableUserId as it will return the username because the user id is not available.
                LOG.error("User id cannot be found for user: " + (LoggerUtils.isLogMaskingEnable ?
                        LoggerUtils.getMaskedContent(authenticatedUser.getLoggableUserId()) :
                        authenticatedUser.getLoggableUserId()));
                return;
            }
            clearOAuthCache(consumerKey, userId);
            clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, null);
        }
    }

    /**
     * Clear OAuth cache based on the application and authorized user.
     *
     * @param consumerKey       Client id of the application the token issued to.
     * @param authorizedUser    authorized user.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser) {

        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authorizedUser);
        String userId;
        try {
            userId = authorizedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableUserId());
            return;
        }
        clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, authenticatedIDP);
    }

    /**
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser, String)} instead.
     * @param consumerKey
     * @param authorizedUser
     * @param scope
     */
    @Deprecated
    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope) {

        String authenticatedIDP;
        if (authorizedUser instanceof AuthenticatedUser) {
            clearOAuthCache(consumerKey, (AuthenticatedUser) authorizedUser, scope);
        } else {
            authenticatedIDP = null;
            if (LOG.isDebugEnabled()) {
                LOG.debug("User object is not an instance of AuthenticatedUser therefore cannot resolve " +
                        "authenticatedIDP name.");
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
            String userId;
            try {
                userId = authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                // Masking getLoggableUserId as it will return the username because the user id is not available.
                LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableMaskedUserId());
                return;
            }
            clearOAuthCache(consumerKey, userId, scope);
            clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, scope, authenticatedIDP,
                    authenticatedUser.getTenantDomain());
        }
    }

    /**
     * Clear OAuth cache based on the application, authorized user and scope list.
     *
     * @param consumerKey       Client id of the application the token issued to.
     * @param authorizedUser    authorized user.
     * @param scope             scope string.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser, String scope) {

        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authorizedUser);

        String userId;
        try {
            userId = authorizedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableUserId());
            return;
        }
        clearOAuthCacheWithAuthenticatedIDP(consumerKey, userId, scope, authenticatedIDP,
                authorizedUser.getTenantDomain());
    }

    /**
     * Clear OAuth cache.
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser, String, String)} instead.
     *
     * @param consumerKey consumer key.
     * @param authorizedUser authorized user.
     * @param scope scope.
     * @param tokenBindingReference token binding reference.
     */
    @Deprecated
    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope,
            String tokenBindingReference) {

        if (authorizedUser instanceof AuthenticatedUser) {
            clearOAuthCache(consumerKey, (AuthenticatedUser) authorizedUser, scope, tokenBindingReference);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User is not an instance of AuthenticatedUser therefore cannot resolve authenticatedIDP "
                        + "name");
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
            String userId;
            try {
                userId = authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                // Masking getLoggableUserId as it will return the username because the user id is not available.
                LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableMaskedUserId());
                return;
            }
            clearOAuthCache(consumerKey, userId, scope);
            clearOAuthCache(buildCacheKeyStringForToken(consumerKey, scope, userId, null,
                    tokenBindingReference));
        }
    }

    /**
     * Clear OAuth cache based on the application, authorized user, scope list and token binding reference.
     *
     * @param consumerKey           Client id of the application the token issued to.
     * @param authorizedUser        Authorized user.
     * @param scope                 Scope list.
     * @param tokenBindingReference Token binding reference.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser, String scope,
                                       String tokenBindingReference) {

        clearOAuthCache(consumerKey, authorizedUser, scope, tokenBindingReference,
                OAuthConstants.AuthorizedOrganization.NONE);
    }


    /**
     * Clear OAuth cache based on the application, authorized user, scope list and token binding reference.
     *
     * @param consumerKey            Client id of the application the token issued to.
     * @param authorizedUser         Authorized user.
     * @param scope                  Scope list.
     * @param tokenBindingReference  Token binding reference.
     * @param authorizedOrganization Authorized organization.
     */
    public static void clearOAuthCache(String consumerKey, AuthenticatedUser authorizedUser, String scope,
                                       String tokenBindingReference, String authorizedOrganization) {

        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authorizedUser);

        String userId;
        String tenantDomain;
        try {
            userId = authorizedUser.getUserId();
            tenantDomain = authorizedUser.getTenantDomain();

        } catch (UserIdNotFoundException e) {
            LOG.error("User id cannot be found for user: " + authorizedUser.getLoggableMaskedUserId());
            return;
        }
        if (authorizedUser.getAccessingOrganization() != null) {
            authorizedOrganization = authorizedUser.getAccessingOrganization();
        }
        clearOAuthCacheByTenant(OAuth2Util.buildCacheKeyStringForTokenWithUserIdOrgId(consumerKey, scope, userId,
                authenticatedIDP, tokenBindingReference, authorizedOrganization), tenantDomain);
    }


    private static void clearOAuthCache(String consumerKey, String authorizedUserId) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey      Consumer key.
     * @param authorizedUserId   Authorized user.
     * @param authenticatedIDP Authenticated IdP.
     */
    private static void clearOAuthCacheWithAuthenticatedIDP(String consumerKey, String authorizedUserId,
                                                            String authenticatedIDP) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId + ":" + authenticatedIDP);
    }

    private static void clearOAuthCache(String consumerKey, String authorizedUserId, String scope) {

        clearOAuthCache(consumerKey + ":" + authorizedUserId + ":" + scope);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey      Consumer key.
     * @param authorizedUserId   Authorized user.
     * @param scope            Scopes.
     * @param authenticatedIDP Authenticated IdP.
     */
    private static void clearOAuthCacheWithAuthenticatedIDP(String consumerKey, String authorizedUserId, String scope
            , String authenticatedIDP, String tenantDomain) {

        clearOAuthCacheByTenant(consumerKey + ":" + authorizedUserId + ":" + scope + ":" + authenticatedIDP,
                tenantDomain);
    }

    /**
     * Build the cache key string when storing token info in cache.
     * @deprecated use {@link #clearOAuthCache(String, AuthenticatedUser, String, String)} instead.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUserId   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @param tokenBindingReference Token binding reference.
     * @return Cache key string combining the input parameters.
     */
    @Deprecated
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUserId,
            String authenticatedIDP, String tokenBindingReference) {

        return OAuth2Util.buildCacheKeyStringForTokenWithUserId(clientId, scope, authorizedUserId,
                authenticatedIDP, tokenBindingReference);
    }

    public static void clearOAuthCache(String oauthCacheKey) {

        OAuthCacheKey cacheKey = new OAuthCacheKey(oauthCacheKey);
        OAuthCache.getInstance().clearCacheEntry(cacheKey);
    }

    public static void clearOAuthCacheByTenant(String oauthCacheKey, String tenantDomain) {

        OAuthCacheKey cacheKey = new OAuthCacheKey(oauthCacheKey);
        OAuthCache.getInstance().clearCacheEntry(cacheKey, tenantDomain);
    }

    public static void clearOAuthCache(AccessTokenDO accessTokenDO) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Clearing cache for access token as cache key of user: " +
                    accessTokenDO.getAuthzUser().getLoggableUserId());
        }
        OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenDO.getAccessToken());
        String tenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();
        OAuthCache.getInstance().clearCacheEntry(cacheKey,  tenantDomain);
    }

    public static AuthenticatedUser getAuthenticatedUser(String fullyQualifiedUserName) {

        if (StringUtils.isBlank(fullyQualifiedUserName)) {
            throw new RuntimeException("Invalid username.");
        }

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(IdentityUtil.extractDomainFromName(fullyQualifiedUserName));
        authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(fullyQualifiedUserName));

        String username = fullyQualifiedUserName;
        if (fullyQualifiedUserName.startsWith(authenticatedUser.getUserStoreDomain())) {
            username = UserCoreUtil.removeDomainFromName(fullyQualifiedUserName);
        }
        authenticatedUser.setUserName(MultitenantUtils.getTenantAwareUsername(username));

        return authenticatedUser;
    }

    /**
     * This is used to handle the OAuthAdminService exceptions. This will log the error message and return an
     * IdentityOAuthAdminException exception
     * @param message error message
     * @param exception Exception.
     * @return
     */
    public static IdentityOAuthAdminException handleError(String message, Exception exception) {

        if (exception == null) {
            return new IdentityOAuthAdminException(message);
        } else {
            String errorCode = Error.UNEXPECTED_SERVER_ERROR.getErrorCode();
            return new IdentityOAuthAdminException(errorCode, message, exception);
        }
    }

    /**
     * This is used to handle the OAuthAdminService exceptions depends on the exception type, there can be client
     * exception and server exception.This will log the error message and
     * return an IdentityOAuthClientException/IdentityOAuthServerException/IdentityOAuthAdminException exception
     * depends on the IdentityOAuth2Exception exception type.
     *
     * @param message   Error message.
     * @param exception Exception.
     * @return
     */
    public static IdentityOAuthAdminException handleErrorWithExceptionType(String message,
                                                                           IdentityOAuth2Exception exception) {

        if (exception == null) {
            return new IdentityOAuthAdminException(message);
        }
        if (StringUtils.isBlank(exception.getErrorCode())) {
            handleError(message, exception);
        }
        if (exception instanceof IdentityOAuth2ClientException) {
            return new IdentityOAuthClientException(exception.getErrorCode(), message);
        } else if (exception instanceof IdentityOAuth2ServerException) {
            return new IdentityOAuthServerException(exception.getErrorCode(), message, exception);
        } else {
            return new IdentityOAuthAdminException(exception.getErrorCode(), message, exception);
        }
    }

    /**
     * Get created oauth application details.
     *
     * @param appDO <code>OAuthAppDO</code> with created application information.
     * @return OAuthConsumerAppDTO Created OAuth application details.
     */
    public static OAuthConsumerAppDTO buildConsumerAppDTO(OAuthAppDO appDO) {

        OAuthConsumerAppDTO dto = new OAuthConsumerAppDTO();
        dto.setApplicationName(appDO.getApplicationName());
        dto.setCallbackUrl(appDO.getCallbackUrl());
        dto.setOauthConsumerKey(appDO.getOauthConsumerKey());
        dto.setOauthConsumerSecret(appDO.getOauthConsumerSecret());
        dto.setOAuthVersion(appDO.getOauthVersion());
        dto.setGrantTypes(appDO.getGrantTypes());
        dto.setScopeValidators(appDO.getScopeValidators());
        dto.setUsername(appDO.getUser().toFullQualifiedUsername());
        dto.setState(appDO.getState());
        dto.setPkceMandatory(appDO.isPkceMandatory());
        dto.setPkceSupportPlain(appDO.isPkceSupportPlain());
        dto.setHybridFlowEnabled(appDO.isHybridFlowEnabled());
        dto.setHybridFlowResponseType(appDO.getHybridFlowResponseType());
        dto.setUserAccessTokenExpiryTime(appDO.getUserAccessTokenExpiryTime());
        dto.setApplicationAccessTokenExpiryTime(appDO.getApplicationAccessTokenExpiryTime());
        dto.setRefreshTokenExpiryTime(appDO.getRefreshTokenExpiryTime());
        dto.setIdTokenExpiryTime(appDO.getIdTokenExpiryTime());
        dto.setAudiences(appDO.getAudiences());
        dto.setRequestObjectSignatureValidationEnabled(appDO.isRequestObjectSignatureValidationEnabled());
        dto.setIdTokenEncryptionEnabled(appDO.isIdTokenEncryptionEnabled());
        dto.setIdTokenEncryptionAlgorithm(appDO.getIdTokenEncryptionAlgorithm());
        dto.setIdTokenEncryptionMethod(appDO.getIdTokenEncryptionMethod());
        dto.setBackChannelLogoutUrl(appDO.getBackChannelLogoutUrl());
        dto.setFrontchannelLogoutUrl(appDO.getFrontchannelLogoutUrl());
        dto.setTokenType(appDO.getTokenType());
        dto.setBypassClientCredentials(appDO.isBypassClientCredentials());
        dto.setRenewRefreshTokenEnabled(appDO.getRenewRefreshTokenEnabled());
        dto.setExtendRenewedRefreshTokenExpiryTime(appDO.isExtendRenewedRefreshTokenExpiryTime());
        dto.setTokenBindingType(appDO.getTokenBindingType());
        dto.setTokenRevocationWithIDPSessionTerminationEnabled(appDO
                .isTokenRevocationWithIDPSessionTerminationEnabled());
        dto.setTokenBindingValidationEnabled(appDO.isTokenBindingValidationEnabled());
        dto.setTokenEndpointAuthMethod(appDO.getTokenEndpointAuthMethod());
        dto.setTokenEndpointAllowReusePvtKeyJwt(appDO.isTokenEndpointAllowReusePvtKeyJwt());
        dto.setTokenEndpointAuthSignatureAlgorithm(appDO.getTokenEndpointAuthSignatureAlgorithm());
        dto.setSectorIdentifierURI(appDO.getSectorIdentifierURI());
        dto.setIdTokenSignatureAlgorithm(appDO.getIdTokenSignatureAlgorithm());
        dto.setRequestObjectSignatureAlgorithm(appDO.getRequestObjectSignatureAlgorithm());
        dto.setTlsClientAuthSubjectDN(appDO.getTlsClientAuthSubjectDN());
        dto.setSubjectType(appDO.getSubjectType());
        dto.setRequestObjectEncryptionAlgorithm(appDO.getRequestObjectEncryptionAlgorithm());
        dto.setRequestObjectEncryptionMethod(appDO.getRequestObjectEncryptionMethod());
        dto.setRequirePushedAuthorizationRequests(appDO.isRequirePushedAuthorizationRequests());
        dto.setFapiConformanceEnabled(appDO.isFapiConformanceEnabled());
        dto.setSubjectTokenEnabled(appDO.isSubjectTokenEnabled());
        dto.setSubjectTokenExpiryTime(appDO.getSubjectTokenExpiryTime());
        dto.setJwtScopeAsArrayEnabled(appDO.isJwtScopeAsArrayEnabled());
        dto.setAccessTokenClaims(appDO.getAccessTokenClaims());
        dto.setCibaNotificationChannels(appDO.getCibaNotificationChannels());
        dto.setCibaAuthReqExpiryTime(appDO.getCibaAuthReqExpiryTime());
        dto.setIssuerDetails(appDO.getIssuerDetails());
        return dto;
    }

    /**
     * This will be called after when Tokens Revoked through Listeners directly.
     *
     * @param accessTokenDO {@link AccessTokenDO}
     */
    public static void invokePostRevocationBySystemListeners(AccessTokenDO accessTokenDO, Map<String, Object> params) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPostTokenRevocationBySystem(accessTokenDO, params);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while triggering listener for post token revocation by system.", e);
            }
        }
    }

    /**
     * This will be called before when Tokens Revoked through Listeners directly.
     *
     * @param accessTokenDO {@link AccessTokenDO}
     */
    public static void invokePreRevocationBySystemListeners(AccessTokenDO accessTokenDO, Map<String, Object> params) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPreTokenRevocationBySystem(accessTokenDO, params);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while triggering listener for pre token revocation by system.", e);
            }
        }
    }

    /**
     * This will be called before when tokens are revoked through Listeners implicitly.
     * The {@link OAuthEventInterceptor} implementations can be invoked pre user events
     * for the user.
     * @param userUUID - UUID of the user.
     * @param params   - Additional parameters.
     */
    public static void invokePreRevocationBySystemListeners(String userUUID, Map<String, Object> params) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPreTokenRevocationBySystem(userUUID, params);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while triggering listener for pre token revocation by system.", e);
            }
        }
    }

    /**
     * This will be called after when tokens are revoked through Listeners implicitly.
     * The {@link OAuthEventInterceptor} implementations can be invoked post user events
     * for the user.
     * @param userUUID - UUID of the user.
     * @param params   - Additional parameters.
     */
    public static void invokePostRevocationBySystemListeners(String userUUID, Map<String, Object> params) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPostTokenRevocationBySystem(userUUID, params);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while triggering listener for post token revocation by system.", e);
            }
        }
    }

    /**
     * Remove user claims from ClaimCache
     *
     * @param userName
     */
    public static boolean removeUserClaimsFromCache(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        ClaimCache claimCache = ClaimCache.getInstance();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(userName);
        authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId()));
        authenticatedUser.setUserStoreDomain(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration()));
        ClaimCacheKey cacheKey = new ClaimCacheKey(authenticatedUser);
        if (cacheKey != null) {
            claimCache.clearCacheEntry(cacheKey, userStoreManager.getTenantId());
        }
        return true;
    }

    /**
     * This method will revoke the authorization codes of user.
     * @param username          username.
     * @param userStoreManager  userStoreManager.
     * @return true if revocation is successfull. Else return false
     * @throws UserStoreException If an error occurred when revoking codes.
     */
    public static boolean revokeAuthzCodes(String username, UserStoreManager userStoreManager)
            throws UserStoreException {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);

        List<AuthzCodeDO> authorizationCodes;
        try {
            authorizationCodes = OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().getAuthorizationCodesDataByUser(authenticatedUser);
            for (AuthzCodeDO authorizationCode : authorizationCodes) {
                OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(
                        OAuth2Util.buildCacheKeyStringForAuthzCode(authorizationCode.getConsumerKey(),
                                authorizationCode.getAuthorizationCode())));
                OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                        .updateAuthorizationCodeState(authorizationCode.getAuthorizationCode(),
                                authorizationCode.getAuthzCodeId(), OAuthConstants.AuthorizationCodeState.REVOKED);
            }
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while revoking authorization codes for user: " + username;
            if (LOG.isDebugEnabled()) {
                LOG.debug(errorMsg);
            }
            throw new UserStoreException(errorMsg, e);
        }

        return true;
    }

    /**
     * This method can be used to build the AuthenticatedUser object.
     * @param userStoreManager  userStoreManager.
     * @param username          username.
     * @param userStoreDomain   userStoreDomain.
     * @return AuthenticatedUser.
     */
    private static AuthenticatedUser buildAuthenticatedUser(UserStoreManager userStoreManager, String username,
                                                            String userStoreDomain, String tenantDomain)
            throws UserStoreException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(UserCoreUtil.removeDomainFromName(username));
        boolean isOrganization;
        try {
            isOrganization = OrganizationManagementUtil.isOrganization(tenantDomain);
        } catch (OrganizationManagementException e) {
            String msg = "Error occurred while check whether organization for the tenant : " + tenantDomain;
            throw new UserStoreException(msg, e);
        }

        if (!isOrganization) {
            return authenticatedUser;
        }

        String userId = ((AbstractUserStoreManager) userStoreManager).getUser(null, username).getUserID();
        Map<String, String> claimsMap = ((AbstractUserStoreManager) userStoreManager)
                .getUserClaimValuesWithID(userId, new String[]{managedOrgClaim}, null);
        String managedOrg = claimsMap.get(managedOrgClaim);
        try {
            String accessingOrg = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            String primaryOrganizationId = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .getPrimaryOrganizationId(accessingOrg);
            tenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(primaryOrganizationId);
            authenticatedUser.setTenantDomain(tenantDomain);

            // Shared user flow.
            if (managedOrg != null) {
                authenticatedUser.setUserResidentOrganization(managedOrg);
                authenticatedUser.setAccessingOrganization(accessingOrg);
                authenticatedUser.setSharedUserId(userId);

                // SSO login user shared flow.
                if (!OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .isPrimaryOrganization(managedOrg)) {
                    userId = OAuthComponentServiceHolder.getInstance().getOrganizationUserSharingService()
                            .getUserAssociation(userId, accessingOrg).getAssociatedUserId();
                    authenticatedUser.setUserName(userId);
                    setOrganizationSSOUserDetails(authenticatedUser);
                } else {
                    UserAssociation userAssociation = OAuthComponentServiceHolder.getInstance()
                            .getOrganizationUserSharingService()
                            .getUserAssociation(userId, accessingOrg);

                    if (userAssociation != null && userAssociation.getAssociatedUserId() != null) {
                        String parentUserStoreDomain = getUserStoreDomainOfParentUser(
                                userAssociation.getAssociatedUserId(), tenantDomain);
                        authenticatedUser.setUserStoreDomain(parentUserStoreDomain);
                    }
                }
                return authenticatedUser;
            }

            /*
             Organization SSO user flow. This user id will be used to get the consumer keys which are associated
             with the user from access tokens.
            */
            authenticatedUser.setUserId(userId);
            setOrganizationSSOUserDetails(authenticatedUser);
            authenticatedUser.setUserResidentOrganization(accessingOrg);
            authenticatedUser.setAccessingOrganization(accessingOrg);
            return authenticatedUser;
        } catch (OrganizationManagementException e) {
            String msg = "Error occurred while resolving organization information for the tenant : " + tenantDomain;
            throw new UserStoreException(msg, e);
        } catch (IdentityProviderManagementException e) {
            String msg = "Error occurred while resolving IDP name of the organization login IDP in : " + tenantDomain;
            throw new UserStoreException(msg, e);
        }
    }

    /**
     * Get clientIds of associated application of an application role.
     *
     * @param role               Role basic info object.
     * @param authenticatedUser  Authenticated user.
     * @return Set of clientIds of associated applications.
     */
    private static Optional<String> getClientIdOfAssociatedApplication(RoleBasicInfo role,
                                                                       AuthenticatedUser authenticatedUser)
            throws UserStoreException {

        ApplicationManagementService applicationManagementService =
                OAuthComponentServiceHolder.getInstance().getApplicationManagementService();
        String associatedApplication = role.getAudienceId();
        String appTenantDomain = authenticatedUser.getTenantDomain();
        try {
            if (authenticatedUser.getUserResidentOrganization() != null) {
                /*
                 Organizations now have both shared apps and main apps. Therefore, we need to resolve the main
                 app only if the application is a fragment app.
                */
                String userResidentTenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(authenticatedUser.getUserResidentOrganization());
                ServiceProvider application = applicationManagementService
                        .getApplicationByResourceId(associatedApplication, userResidentTenantDomain);
                appTenantDomain = userResidentTenantDomain;
                if (StringUtils.isNotEmpty(authenticatedUser.getSharedUserId()) || (application != null &&
                        application.getSpProperties() != null && Arrays.stream(application.getSpProperties()).
                        anyMatch(property -> "isFragmentApp".equals(property.getName())
                                && "true".equals(property.getValue())))) {
                    associatedApplication = SharedAppResolveDAO.getMainApplication(
                            associatedApplication, authenticatedUser.getAccessingOrganization());
                    appTenantDomain = authenticatedUser.getTenantDomain();
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw new UserStoreException("Error occurred while getting the main applications of the shared apps.", e);
        } catch (OrganizationManagementException e) {
            throw new UserStoreException("Error occurred while resolving the tenant domain for the organization : "
                    + authenticatedUser.getUserResidentOrganization(), e);
        } catch (IdentityApplicationManagementException e) {
            throw new UserStoreException("Error while getting the application for app id : " +
                    associatedApplication, e);
        }
        try {
            ServiceProvider application = applicationManagementService
                    .getApplicationByResourceId(associatedApplication, appTenantDomain);
            if (application != null && application.getInboundAuthenticationConfig() != null) {
                InboundAuthenticationRequestConfig[] inboundAuthenticationRequestConfigs =
                        application.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
                return Arrays.stream(inboundAuthenticationRequestConfigs)
                        .filter(config -> StandardInboundProtocols.OAUTH2.equals(config.getInboundAuthType()))
                        .map(InboundAuthenticationRequestConfig::getInboundAuthKey)
                        .findFirst();
            }
        } catch (IdentityApplicationManagementException e) {
            String errorMessage = "Error occurred while retrieving application of id : " +
                    associatedApplication;
            LOG.error(errorMessage);
        }
        return Optional.empty();
    }

    private static Set<String> filterClientIdsWithOrganizationAudience(List<String> clientIds, String tenantDomain) {

        Set<String> clientIdsWithOrganizationAudience = new HashSet<>();
        ApplicationManagementService applicationManagementService =
                OAuthComponentServiceHolder.getInstance().getApplicationManagementService();
        for (String clientId : clientIds) {
            try {
                String applicationId = applicationManagementService.getApplicationResourceIDByInboundKey(clientId,
                        OAUTH2, tenantDomain);
                String audience = applicationManagementService.getAllowedAudienceForRoleAssociation(applicationId,
                        tenantDomain);
                if (RoleConstants.ORGANIZATION.equalsIgnoreCase(audience)) {
                    clientIdsWithOrganizationAudience.add(clientId);
                }
            } catch (IdentityApplicationManagementException e) {
                LOG.error("Error occurred while retrieving application information for client id: " + clientId, e);
            }
        }
        return clientIdsWithOrganizationAudience;
    }

    /**
     * This method will retrieve the role details of the given role id.
     * @param roleId        Role Id.
     * @param tenantDomain  Tenant domain.
     * @return Role.
     */
    private static RoleBasicInfo getRoleBasicInfo(String roleId, String tenantDomain) throws UserStoreException {

        try {
            RoleManagementService roleV2ManagementService =
                    OAuthComponentServiceHolder.getInstance().getRoleV2ManagementService();
            return roleV2ManagementService.getRoleBasicInfoById(roleId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            String errorMessage = "Error occurred while retrieving basic role info of id : " + roleId;
            throw new UserStoreException(errorMessage, e);
        }
    }

    /**
     * Initiate token revocation process for the associated clientIds for the given user.
     * @param clientIds          Set of clientIds
     * @param authenticatedUser  Authenticated User object of the user.
     * @param userStoreDomain    User store domain of the user.
     * @param username           Username.
     * @return True if token revocation is successful. Else return false.
     */
    private static boolean processTokenRevocation(Set<String> clientIds, AuthenticatedUser authenticatedUser,
                                                  String userStoreDomain, String username) {

        boolean isErrorOnRevokingTokens = false;
        boolean isTokenPreservingAtPasswordUpdateEnabled = IdPManagementUtil.
                getPreserveCurrentSessionAtPasswordUpdate(authenticatedUser.getTenantDomain());
        for (String clientId : clientIds) {
            try {
                Set<AccessTokenDO> accessTokenDOs = new HashSet<>();
                try {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Retrieving all ACTIVE or EXPIRED access tokens for the client: " + clientId
                                + " authorized by user: " + username + "/" + userStoreDomain);
                    }
                    // retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                    accessTokenDOs.addAll(OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                            .getAccessTokens(clientId, authenticatedUser, userStoreDomain, true));
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while retrieving access tokens issued for " +
                            "Client ID : " + clientId + ", User ID : " + authenticatedUser;
                    LOG.error(errorMsg, e);
                    throw new UserStoreException(e);
                }

                if (LOG.isDebugEnabled() && CollectionUtils.isNotEmpty(accessTokenDOs)) {
                    LOG.debug("ACTIVE or EXPIRED access tokens found for the client: " + clientId + " for the user: "
                            + username);
                }
                String currentTokenBindingReference = "";
                String currentTokenReference = "";
                if (isTokenPreservingAtPasswordUpdateEnabled) {
                    if (IdentityUtil.threadLocalProperties.get().get(CURRENT_SESSION_IDENTIFIER) != null) {
                        currentTokenBindingReference = (String) IdentityUtil.threadLocalProperties.get()
                                .get(CURRENT_SESSION_IDENTIFIER);
                    }
                    if (IdentityUtil.threadLocalProperties.get().get(CURRENT_TOKEN_IDENTIFIER) != null) {
                        currentTokenReference = (String) IdentityUtil.threadLocalProperties.get()
                                .get(CURRENT_TOKEN_IDENTIFIER);
                    }
                }

                Set<String> scopes = new HashSet<>();
                List<AccessTokenDO> accessTokens = new ArrayList<>();
                boolean tokenBindingEnabled = false;
                boolean isOrganizationUserTokenRevocation = StringUtils.isNotEmpty(
                        authenticatedUser.getAccessingOrganization());
                for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                    if (isOrganizationUserTokenRevocation
                            && accessTokenDO.getAuthzUser().getAccessingOrganization() == null) {
                        continue;
                    }
                    // Clear cache
                    String tokenBindingReference = NONE;
                    if (accessTokenDO.getTokenBinding() != null && StringUtils
                            .isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
                        tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
                        tokenBindingEnabled = true;
                        // Skip current token from being revoked.
                        if (StringUtils.equals(accessTokenDO.getTokenBinding().getBindingValue(),
                                currentTokenBindingReference)) {
                            continue;
                        }
                    }
                    // Skip current token from being revoked. When the token is generated using password grant.
                    if (isTokenPreservingAtPasswordUpdateEnabled && StringUtils.equals(accessTokenDO.getTokenId(),
                            currentTokenReference)) {
                        continue;
                    }
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                    OAuthUtil.clearOAuthCache(accessTokenDO);
                    // Get unique scopes list
                    scopes.add(OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                    accessTokens.add(accessTokenDO);
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Is hash disabled:" + OAuth2Util.isHashDisabled());
                }
                if (!tokenBindingEnabled && OAuth2Util.isHashDisabled()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Revoke latest tokens with scopes for the clientId: " + clientId);
                    }
                    revokeLatestTokensWithScopes(scopes, clientId, authenticatedUser);
                } else {
                    // If the hashed token is enabled, there can be multiple active tokens with a user with same scope.
                    // Also, if token binding is enabled, there can be multiple active tokens for the same user, scope
                    // and client combination.
                    // So need to revoke all the tokens.
                    try {
                        revokeTokens(accessTokens);
                    } catch (IdentityOAuth2Exception e) {
                        String errorMsg = "Error occurred while revoking Access Token";
                        LOG.error(errorMsg, e);
                        throw new UserStoreException(e);
                    }
                }
            } catch (UserStoreException e) {
                // Set a flag to throw an exception after revoking all the possible access tokens.
                // The error details are logged at the same place they are throwing.
                isErrorOnRevokingTokens = true;
            }
        }

        return isErrorOnRevokingTokens;
    }

    /**
     * This method will revoke the access tokens of user.
     * @param username username.
     * @param userStoreManager userStoreManager.
     * @param roleId roleId.
     * @return true if revocation is successful. Else return false.
     */
    public static boolean revokeTokens(String username, UserStoreManager userStoreManager, String roleId)
            throws UserStoreException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Request received for token revocation for the user: " + username + " roleId:" + roleId);
        }
        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        AuthenticatedUser authenticatedUser = buildAuthenticatedUser(userStoreManager, username, userStoreDomain,
                tenantDomain);
        AuthenticatedUser authenticatedOrgUser = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            try {
                String userResidentTenant = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(authenticatedUser.getUserResidentOrganization());
                if (OrganizationManagementUtil.isOrganization(userResidentTenant)) {
                    /*
                     If the authenticated user's resident organization is an organization, then we need to check
                     for the access tokens issued directly for the organization as well. Therefore, we need to
                     construct the authenticated user object with the details of the organization to revoke the
                     tokens.
                    */
                    String authenticatedUserName = authenticatedUser.getUserName();
                    /*
                     Changing this to handle the organization SSO flow since the tokens are stored against the
                     user id of the federated user.
                    */
                    authenticatedUser.setUserName(authenticatedUser.getUserId());

                    Optional<User> user = getUser(userResidentTenant, authenticatedUserName);
                    if (user.isPresent()) {
                        authenticatedOrgUser = new AuthenticatedUser();
                        authenticatedOrgUser.setUserName(authenticatedUserName);
                        authenticatedOrgUser.setUserResidentOrganization(authenticatedUser.
                                getUserResidentOrganization());
                        authenticatedOrgUser.setAccessingOrganization(authenticatedUser.getUserResidentOrganization());
                        authenticatedOrgUser.setFederatedUser(false);
                        authenticatedOrgUser.setUserStoreDomain(user.get().getUserStoreDomain());
                        String userTenantDomain = OAuthComponentServiceHolder.getInstance().
                                getOrganizationManager()
                                .resolveTenantDomain(authenticatedUser.getUserResidentOrganization());
                        authenticatedOrgUser.setTenantDomain(userTenantDomain);
                    }
                }
            } catch (OrganizationManagementException | UserIdNotFoundException e) {
                throw new UserStoreException("Error occurred while constructing the authenticated user.", e);
            } catch (IdentityApplicationManagementException e) {
                throw new UserStoreException("Error occurred while getting the user details for the" +
                        " authenticated user.", e);
            }
        }

        /* This userStoreDomain variable is used for access token table partitioning. So it is set to null when access
        token table partitioning is not enabled.*/
        userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error occurred while getting user store domain for User ID : " + authenticatedUser, e);
                throw new UserStoreException(e);
            }
        }

        // Get details about the role to identify the audience and associated applications.
        Set<String> clientIds = new HashSet<>();
        RoleBasicInfo role = null;
        boolean getClientIdsFromUser = false;
        if (roleId != null) {
            role = getRoleBasicInfo(roleId, tenantDomain);
            if (role != null && RoleConstants.APPLICATION.equals(role.getAudience())) {
                // Get clientIds of associated applications for the specific application role.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Get clientIds of associated applications for the application role: "
                            + role.getName());
                }
                getClientIdOfAssociatedApplication(role, authenticatedUser)
                        .ifPresent(clientIds::add);
            } else {
                // Get all the distinct client Ids authorized by this user since this is an organization role.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Get all the distinct client Ids authorized by user:" + username + " since this is " +
                            "an organization role: " + role.getName());
                }
                getClientIdsFromUser = true;

            }
        } else {
            // Get all the distinct client Ids authorized by this user since no role is specified.
            getClientIdsFromUser = true;
        }

        if (getClientIdsFromUser) {
            // Get all the distinct client Ids authorized by this user
            if (LOG.isDebugEnabled()) {
                LOG.debug("Get all the distinct client Ids authorized by user: " + username);
            }
            try {
                clientIds = OAuthTokenPersistenceFactory.getInstance()
                            .getTokenManagementDAO().getAllTimeAuthorizedClientIds(authenticatedUser);
                if (authenticatedOrgUser != null) {
                    clientIds.addAll(OAuthTokenPersistenceFactory.getInstance()
                            .getTokenManagementDAO().getAllTimeAuthorizedClientIds(authenticatedOrgUser));
                }

                Set<String> filteredClientIds = clientIds;
                if (role != null && RoleConstants.ORGANIZATION.equals(role.getAudience())) {
                    filteredClientIds = filterClientIdsWithOrganizationAudience(new ArrayList<>(clientIds),
                            authenticatedUser.getTenantDomain());
                }

                if (authenticatedUser.getUserResidentOrganization() != null) {
                    Set<String> organizationClientIds = new HashSet<>();
                    String userResidentTenantDomain = OAuth2Util.getUserResidentTenantDomain(authenticatedUser);
                    if (!StringUtils.equals(authenticatedUser.getTenantDomain(), userResidentTenantDomain)) {
                        organizationClientIds = filterClientIdsWithOrganizationAudience(new ArrayList<>(clientIds),
                                userResidentTenantDomain);
                    }
                    filteredClientIds.addAll(organizationClientIds);
                }
                clientIds = filteredClientIds;

            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error occurred while retrieving apps authorized by User ID : " + authenticatedUser, e);
                throw new UserStoreException(e);
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("The number of distinct client IDs for the user: " + username + " is " + clientIds.size());
        }

        boolean isErrorOnRevokingTokens;
        isErrorOnRevokingTokens = processTokenRevocation(clientIds, authenticatedUser, userStoreDomain, username);

        if (!isErrorOnRevokingTokens && CollectionUtils.isNotEmpty(clientIds)) {
            // Considering the root tenant revocation in current scope, will consider the sub organizations later.
            AccessTokenEventUtil.publishTokenRevokeEvent(clientIds, authenticatedUser);
        }

        if (authenticatedOrgUser != null) {
            isErrorOnRevokingTokens = processTokenRevocation(clientIds, authenticatedOrgUser, authenticatedOrgUser.
                    getUserStoreDomain(), username);
        }

        // Throw exception if there was any error found in revoking tokens.
        if (isErrorOnRevokingTokens) {
            throw new UserStoreException("Error occurred while revoking Access Tokens of the user " + username);
        }
        return true;
    }

    /**
     * This method will revoke the access tokens of user.
     * @param username username.
     * @param userStoreManager userStoreManager.
     * @return true if revocation is successful. Else return false
     */
    public static boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

        return revokeTokens(username, userStoreManager, null);
    }


    private static void revokeTokens(List<AccessTokenDO> accessTokens) throws IdentityOAuth2Exception {

        if (!accessTokens.isEmpty()) {
            // Revoking token from database.
            for (AccessTokenDO accessToken : accessTokens) {
                OAuthUtil.invokePreRevocationBySystemListeners(accessToken, Collections.emptyMap());
                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .revokeAccessTokens(new String[]{accessToken.getAccessToken()}, OAuth2Util.isHashEnabled());
                OAuthUtil.invokePostRevocationBySystemListeners(accessToken, Collections.emptyMap());
            }
        }
    }

    private static void revokeLatestTokensWithScopes(Set<String> scopes, String clientId,
                                                        AuthenticatedUser authenticatedUser) throws
            UserStoreException {

        for (String scope : scopes) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Revoking tokens for the scope: " + scope);
            }
            AccessTokenDO scopedToken = null;
            try {
                // Retrieve latest access token for particular client, user and scope combination
                // if its ACTIVE or EXPIRED.
                scopedToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getLatestAccessToken(clientId, authenticatedUser, authenticatedUser.getUserStoreDomain(),
                                scope, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while retrieving latest access token issued for Client ID : " +
                        clientId + ", User ID : " + authenticatedUser + " and Scope : " + scope;
                LOG.error(errorMsg, e);
                throw new UserStoreException(e);
            }
            if (scopedToken != null) {
                try {
                    // Revoking token from database
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Revoking latest scoped token from database");
                    }
                    revokeTokens(Collections.singletonList(scopedToken));
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking " + "Access Token : "
                            + scopedToken.getAccessToken() + " for user " + authenticatedUser;
                    LOG.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
    }

    /**
     * This method will remove the authorization grant caches for the user associated tokens and auth codes.
     *
     * @param userName          Username of the user.
     * @param userStoreManager  UserStoreManager of the user.
     * @throws UserStoreException If an error occurred while removing the caches.
     */
    public static void removeAuthzGrantCacheForUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        Set<AccessTokenDO> accessTokenDOSet;
        List<AuthzCodeDO> authorizationCodeDOSet;
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(userName);
        try {
            /*
             Only the tokens and auth codes issued for openid scope should be removed from the cache, since no
             claims are usually cached against tokens or auth codes, otherwise.
             */

            // Retrieve the tokens and auth codes associated with usernames without domain.
            accessTokenDOSet = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getAccessTokensByUserForOpenidScope(authenticatedUser, true);
            authorizationCodeDOSet = OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().getAuthorizationCodesByUserForOpenidScope(authenticatedUser);
            
            // Retrieve the tokens and auth codes associated with domain-qualified usernames.
            if (!userName.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
                authenticatedUser.setUserName(IdentityUtil.addDomainToName(userName, userStoreDomain));
                accessTokenDOSet.addAll(OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getAccessTokensByUserForOpenidScope(authenticatedUser, true));
                authorizationCodeDOSet.addAll(OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                        .getAuthorizationCodesByUserForOpenidScope(authenticatedUser));
            }
            clearAuthzCodeGrantCachesForTokens(accessTokenDOSet, null);
            clearAuthzCodeGrantCachesForCodes(authorizationCodeDOSet, null);

            // Remove root organization federated user related caches if the user is an organization user.
            if (OrganizationManagementUtil.isOrganization(tenantDomain)) {
                /*
                In organization SSO flow, the tokens are stored against the user id of the federated user.
                Therefore, we need to get the user id and set it in authenticated user to remove the caches.
                 */
                String userId = ((AbstractUserStoreManager) userStoreManager).getUser(null, userName).getUserID();
                authenticatedUser.setUserName(userId);
                // Use federated domain to fetch tokens for the root org user.
                authenticatedUser.setUserStoreDomain(FEDERATED_USER_DOMAIN_PREFIX);
                Set<AccessTokenDO> federatedAccessTokenDOSet = OAuthTokenPersistenceFactory.getInstance()
                        .getAccessTokenDAO().getAccessTokensByUserForOpenidScope(authenticatedUser, true);
                List<AuthzCodeDO> federatedAuthorizationCodeDOSet = OAuthTokenPersistenceFactory.getInstance()
                        .getAuthorizationCodeDAO()
                        .getAuthorizationCodesByUserForOpenidScope(authenticatedUser);

                // Switch authorization grant cache from sub org to root org cache.
                String accessingOrg = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveOrganizationId(tenantDomain);
                String primaryOrganizationId = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .getPrimaryOrganizationId(accessingOrg);
                String rootTenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(primaryOrganizationId);
                clearAuthzCodeGrantCachesForTokens(federatedAccessTokenDOSet, rootTenantDomain);
                clearAuthzCodeGrantCachesForCodes(federatedAuthorizationCodeDOSet, rootTenantDomain);
            }
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Error occurred while retrieving access tokens issued for user : " +
                    LoggerUtils.getMaskedContent(userName);
            LOG.error(errorMsg, e);
        } catch (OrganizationManagementException e) {
            String errorMsg = "Error occurred while retrieving access tokens for user: " +
                    LoggerUtils.getMaskedContent(userName) + " due to a failure in resolving the organization ID.";
            LOG.error(errorMsg, e);
        }
    }

    private static void clearAuthzCodeGrantCachesForCodes(List<AuthzCodeDO> authorizationCodeDOSet,
                                                          String tenantDomain) {

        if (CollectionUtils.isNotEmpty(authorizationCodeDOSet)) {
            for (AuthzCodeDO authorizationCodeDO : authorizationCodeDOSet) {
                String authorizationCode = authorizationCodeDO.getAuthorizationCode();
                String authzCodeId = authorizationCodeDO.getAuthzCodeId();
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
                AuthorizationGrantCache.getInstance().clearCacheEntryByCodeId(cacheKey, authzCodeId, tenantDomain);
            }
        }
    }

    private static void clearAuthzCodeGrantCachesForTokens(Set<AccessTokenDO> accessTokenDOSet, String tenantDomain) {

        if (CollectionUtils.isNotEmpty(accessTokenDOSet)) {
            for (AccessTokenDO accessTokenDO : accessTokenDOSet) {
                if (StringUtils.equalsIgnoreCase(OAuthConstants.GrantTypes.PASSWORD,
                        accessTokenDO.getGrantType())) {
                    continue;
                }
                String accessToken = accessTokenDO.getAccessToken();
                String tokenId = accessTokenDO.getTokenId();
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
                AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(cacheKey, tokenId, tenantDomain);
            }
        }
    }

    /**
     * Resolve user.
     *
     * @param tenantDomain The tenant domain which user is trying to access.
     * @param username     The username of resolving user.
     * @return User object.
     * @throws IdentityApplicationManagementException Error when user cannot be resolved.
     */
    public static Optional<User> getUser(String tenantDomain, String username)
            throws IdentityApplicationManagementException {

        User user = null;
        try {
            int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
            String userId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId();

            if (tenantID == MultitenantConstants.SUPER_TENANT_ID) {
                user = getUserFromTenant(username, userId, tenantID);
            } else {
                Tenant tenant = OAuthComponentServiceHolder.getInstance().getRealmService()
                        .getTenantManager().getTenant(tenantID);
                String accessedOrganizationId = tenant.getAssociatedOrganizationUUID();
                if (StringUtils.isEmpty(accessedOrganizationId)) {
                    user = getUserFromTenant(username, userId, tenantID);
                } else {
                    Optional<org.wso2.carbon.user.core.common.User> resolvedUser =
                            OAuthComponentServiceHolder.getInstance()
                                    .getOrganizationUserResidentResolverService()
                                    .resolveUserFromResidentOrganization(username, userId, accessedOrganizationId);
                    if (resolvedUser.isPresent()) {
                        user = getApplicationUser(resolvedUser.get());
                    }
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException | OrganizationManagementException e) {
            throw new IdentityApplicationManagementException("Error resolving user.", e);
        }
        return Optional.ofNullable(user);
    }

    /**
     * Get user from tenant by username or user id.
     *
     * @param username The username.
     * @param userId   The user id.
     * @param tenantId The tenant id where user resides.
     * @return User object from tenant userStoreManager.
     * @throws IdentityApplicationManagementException Error when user cannot be resolved.
     */
    private static User getUserFromTenant(String username, String userId, int tenantId)
            throws IdentityApplicationManagementException {

        User user = null;
        try {
            AbstractUserStoreManager userStoreManager =
                    (AbstractUserStoreManager) OAuthComponentServiceHolder.getInstance()
                            .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            if (StringUtils.isNotEmpty(username) && userStoreManager.isExistingUser(username)) {
                user = getApplicationUser(userStoreManager.getUser(null, username));
            } else if (StringUtils.isNotEmpty(userId) && userStoreManager.isExistingUserWithID(userId)) {
                user = getApplicationUser(userStoreManager.getUser(userId, null));
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new IdentityApplicationManagementException("Error finding user in tenant.", e);
        }
        return user;
    }

    /**
     * Get user from tenant by user id.
     *
     * @param userId   The user id.
     * @param tenantId The tenant id where user resides.
     * @return User object from tenant userStoreManager.
     * @throws IdentityOAuth2Exception Error when user cannot be resolved.
     */
    public static User getUserFromTenant(String userId, int tenantId)
            throws IdentityOAuth2Exception {

        User user = null;
        try {
            AbstractUserStoreManager userStoreManager =
                    (AbstractUserStoreManager) OAuthComponentServiceHolder.getInstance()
                            .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            if (StringUtils.isNotEmpty(userId) && userStoreManager.isExistingUserWithID(userId)) {
                user = getApplicationUser(userStoreManager.getUser(userId, null));
            }
            return user;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new IdentityOAuth2Exception("Error finding user in tenant.", e);
        }
    }

    private static User getApplicationUser(org.wso2.carbon.user.core.common.User coreUser) {

        User user = new User();
        user.setUserName(coreUser.getUsername());
        user.setUserStoreDomain(coreUser.getUserStoreDomain());
        user.setTenantDomain(coreUser.getTenantDomain());
        return user;
    }

    /**
     * Get user's username.
     *
     * @param tenantDomain The tenant domain which user is trying to access.
     * @return username  The username.
     * @throws IdentityApplicationManagementException Error when user cannot be resolved.
     */
    public static String getUsername(String tenantDomain) throws IdentityApplicationManagementException {

        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (StringUtils.isBlank(username)) {
            Optional<User> maybeUser = getUser(tenantDomain, null);
            User user = maybeUser
                    .orElseThrow(() -> new IdentityApplicationManagementException("Error resolving user."));
            username = IdentityUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain());
        }
        return username;
    }

    private static void setOrganizationSSOUserDetails(AuthenticatedUser authenticatedUser)
            throws IdentityProviderManagementException {

        authenticatedUser.setFederatedUser(true);
        authenticatedUser.setUserStoreDomain(FEDERATED_USER_DOMAIN_PREFIX);
        IdentityProvider orgSsoIdp = OAuthComponentServiceHolder.getInstance().getIdpManager()
                .getIdPByRealmId(ORGANIZATION_LOGIN_HOME_REALM_IDENTIFIER, authenticatedUser.getTenantDomain());
        if (orgSsoIdp != null) {
            authenticatedUser.setFederatedIdPName(orgSsoIdp.getIdentityProviderName());
        }
    }

    /**
     * Get the value of the Tenant configuration of Reuse Private key JWT from the tenant configuration.
     *
     * @param tokenEPAllowReusePvtKeyJwtValue   Value of the tokenEPAllowReusePvtKeyJwt configuration.
     * @param tokenAuthMethod                   Token authentication method.
     * @return Value of the tokenEPAllowReusePvtKeyJwt configuration.
     * @throws IdentityOAuth2ServerException IdentityOAuth2ServerException exception.
     */
    public static String getValueOfTokenEPAllowReusePvtKeyJwt(String tokenEPAllowReusePvtKeyJwtValue,
                                                              String tokenAuthMethod)
            throws IdentityOAuth2ServerException {

        if ((tokenEPAllowReusePvtKeyJwtValue == null ||
                tokenEPAllowReusePvtKeyJwtValue.equals("null")) && StringUtils.isNotBlank(tokenAuthMethod)
                && OAuthConstants.PRIVATE_KEY_JWT.equals(tokenAuthMethod)) {
            try {
                tokenEPAllowReusePvtKeyJwtValue = readTenantConfigurationPvtKeyJWTReuse();
            } catch (ConfigurationManagementException e) {
                throw new IdentityOAuth2ServerException("Unable to retrieve JWT Authenticator tenant configuration.",
                        e);
            }
            if (tokenEPAllowReusePvtKeyJwtValue == null) {
                tokenEPAllowReusePvtKeyJwtValue = readServerConfigurationPvtKeyJWTReuse();
                if (tokenEPAllowReusePvtKeyJwtValue == null) {
                    tokenEPAllowReusePvtKeyJwtValue = String.valueOf(DEFAULT_VALUE_FOR_PREVENT_TOKEN_REUSE);
                }
            }
        }
        return tokenEPAllowReusePvtKeyJwtValue;
    }

    private static String readTenantConfigurationPvtKeyJWTReuse() throws ConfigurationManagementException {

        String tokenEPAllowReusePvtKeyJwtTenantConfig = null;
        Resource resource = OAuthComponentServiceHolder.getInstance().getConfigurationManager()
                .getResource(JWT_CONFIGURATION_RESOURCE_TYPE_NAME, JWT_CONFIGURATION_RESOURCE_NAME);

        if (resource != null) {
            tokenEPAllowReusePvtKeyJwtTenantConfig = resource.getAttributes().stream()
                    .filter(attribute -> ENABLE_TOKEN_REUSE.equals(attribute.getKey()))
                    .map(Attribute::getValue)
                    .findFirst()
                    .orElse(null);
        }
        return tokenEPAllowReusePvtKeyJwtTenantConfig;
    }

    private static String readServerConfigurationPvtKeyJWTReuse() {

        String tokenEPAllowReusePvtKeyJwtTenantConfig = null;
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty(
                AbstractIdentityHandler.class.getName(), PVT_KEY_JWT_CLIENT_AUTHENTICATOR_CLASS_NAME);

        if (identityEventListenerConfig != null
                && Boolean.parseBoolean(identityEventListenerConfig.getEnable())) {
            if (identityEventListenerConfig.getProperties() != null) {
                for (Map.Entry<Object, Object> property : identityEventListenerConfig.getProperties().entrySet()) {
                    String key = (String) property.getKey();
                    String value = (String) property.getValue();
                    if (Objects.equals(key, PREVENT_TOKEN_REUSE)) {
                        boolean preventTokenReuse = Boolean.parseBoolean(value);
                        tokenEPAllowReusePvtKeyJwtTenantConfig = String.valueOf(!preventTokenReuse);
                        break;
                    }
                }
            }
        }
        return tokenEPAllowReusePvtKeyJwtTenantConfig;
    }

    /**
     * Retrieves the user store domain of the parent user for a shared user in a specific organization.
     *
     * @param tenantDomain   Tenant domain of the shared user.
     * @return The parent user's user store domain.
     * @throws OrganizationManagementException If an error occurs retrieving user association.
     * @throws UserStoreException              If an error occurs retrieving the user store domain.
     */
    private static String getUserStoreDomainOfParentUser(String parentUserId, String tenantDomain)
            throws OrganizationManagementException, UserStoreException {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserRealm userRealm = OAuthComponentServiceHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);
            UserStoreManager userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();

            return ((AbstractUserStoreManager) userStoreManager).getUser(parentUserId, null).getUserStoreDomain();
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Failed to retrieve the user store domain for the parent user with ID: "
                    + parentUserId + " in tenant domain: " + tenantDomain, e);
        }
    }

    /**
     * Triggers a cache clearance for the original scopes associated with a token.
     * This is necessary because the scopes in the provided {@code accessTokenDO} might have been
     * filtered or mutated during the request lifecycle. Fetch the original scopes from the
     * database to ensure the cache is cleared using the correct keys.
     *
     * @param tokenBindingReference The token binding identifier.
     * @param accessTokenDO        The current (potentially mutated) access token object.
     * @param revokeRequestDTO     The revocation request details containing the consumer key.
     */
    public static void clearOAuthCacheUsingPersistedScopes(String tokenBindingReference, AccessTokenDO accessTokenDO,
                                                           OAuthRevocationRequestDTO revokeRequestDTO) {

        if (OAuthServerConfiguration.getInstance().getAllowedScopes().isEmpty()) {
            return;
        }

        String accessToken = accessTokenDO.getAccessToken();
        if (StringUtils.isBlank(accessToken)) {
            return;
        }

        try {
            // The in-memory scopes may be mutated during validation. To avoid cache-key
            // mismatches, retrieve the original scopes from the database before clearing
            // the OAuth cache.
            AccessTokenDO dbTokenDO = OAuthTokenPersistenceFactory.getInstance()
                    .getAccessTokenDAO()
                    .getAccessToken(accessToken, true);
            if (dbTokenDO == null || dbTokenDO.getScope() == null || dbTokenDO.getScope().length == 0) {
                return;
            }

            String dbTokenScopeString = OAuth2Util.buildScopeString(dbTokenDO.getScope());
            OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(),
                    accessTokenDO.getAuthzUser(), dbTokenScopeString, tokenBindingReference);
            OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(),
                    accessTokenDO.getAuthzUser(), dbTokenScopeString);

        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while clearing cache entries for extended scopes. Consumer key: "
                    + revokeRequestDTO.getConsumerKey(), e);
        }
    }
}
