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

import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class OAuthUtil {

    public static final Log log = LogFactory.getLog(OAuthUtil.class);
    private static final String ALGORITHM = "HmacSHA1";

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
            String secretKey = UUIDGenerator.generateUUID();
            String baseString = UUIDGenerator.generateUUID();

            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(Charsets.UTF_8), ALGORITHM);
            Mac mac = Mac.getInstance(ALGORITHM);
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

    public static void clearOAuthCache(String consumerKey, User authorizedUser) {

        String user = UserCoreUtil.addDomainToName(authorizedUser.getUserName(), authorizedUser.getUserStoreDomain());
        user = UserCoreUtil.addTenantDomainToEntry(user, authorizedUser.getTenantDomain());
        String authenticatedIDP;
        if (authorizedUser instanceof AuthenticatedUser) {
            authenticatedIDP = ((AuthenticatedUser) authorizedUser).getFederatedIdPName();
        } else {
            authenticatedIDP = null;
            if (log.isDebugEnabled()) {
                log.debug("User object is not an instance of AuthenticatedUser therefore cannot resolve " +
                        "authenticatedIDP name.");
            }
            clearOAuthCache(consumerKey, user);
        }

        clearOAuthCacheWithAuthenticatedIDP(consumerKey, user, authenticatedIDP);
    }

    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope) {

        String user = UserCoreUtil.addDomainToName(authorizedUser.getUserName(), authorizedUser.getUserStoreDomain());
        user = UserCoreUtil.addTenantDomainToEntry(user, authorizedUser.getTenantDomain());
        String authenticatedIDP;
        if (authorizedUser instanceof AuthenticatedUser) {
            authenticatedIDP = ((AuthenticatedUser) authorizedUser).getFederatedIdPName();
        } else {
            authenticatedIDP = null;
            if (log.isDebugEnabled()) {
                log.debug("User object is not an instance of AuthenticatedUser therefore cannot resolve " +
                        "authenticatedIDP name.");
            }
            clearOAuthCache(consumerKey, user, scope);
        }

        clearOAuthCacheWithAuthenticatedIDP(consumerKey, user, scope, authenticatedIDP);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey consumer key.
     * @param authorizedUser authorized user.
     * @param scope scope.
     * @param tokenBindingReference token binding reference.
     */
    public static void clearOAuthCache(String consumerKey, User authorizedUser, String scope,
            String tokenBindingReference) {

        String user = UserCoreUtil.addDomainToName(authorizedUser.getUserName(), authorizedUser.getUserStoreDomain());
        user = UserCoreUtil.addTenantDomainToEntry(user, authorizedUser.getTenantDomain());
        String authenticatedIDP;
        if (authorizedUser instanceof AuthenticatedUser) {
            authenticatedIDP = ((AuthenticatedUser) authorizedUser).getFederatedIdPName();
        } else {
            authenticatedIDP = null;
            if (log.isDebugEnabled()) {
                log.debug("User is not an instance of AuthenticatedUser therefore cannot resolve authenticatedIDP "
                        + "name");
            }
            clearOAuthCache(consumerKey, user, scope);
        }

        clearOAuthCache(buildCacheKeyStringForToken(consumerKey, scope, user, authenticatedIDP, tokenBindingReference));
    }

    @Deprecated
    public static void clearOAuthCache(String consumerKey, String authorizedUser) {
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }
        clearOAuthCache(consumerKey + ":" + authorizedUser);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey      Consumer key.
     * @param authorizedUser   Authorized user.
     * @param authenticatedIDP Authenticated IdP.
     */
    private static void clearOAuthCacheWithAuthenticatedIDP(String consumerKey, String authorizedUser,
                                                            String authenticatedIDP) {

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }
        clearOAuthCache(consumerKey + ":" + authorizedUser + ":" + authenticatedIDP);
    }

    @Deprecated
    public static void clearOAuthCache(String consumerKey, String authorizedUser, String scope) {
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }
        clearOAuthCache(consumerKey + ":" + authorizedUser + ":" + scope);
    }

    /**
     * Clear OAuth cache.
     *
     * @param consumerKey      Consumer key.
     * @param authorizedUser   Authorized user.
     * @param scope            Scopes.
     * @param authenticatedIDP Authenticated IdP.
     */
    private static void clearOAuthCacheWithAuthenticatedIDP(String consumerKey, String authorizedUser, String scope,
                                                           String authenticatedIDP) {

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (!isUsernameCaseSensitive) {
            authorizedUser = authorizedUser.toLowerCase();
        }
        clearOAuthCache(consumerKey + ":" + authorizedUser + ":" + scope + ":" + authenticatedIDP);
    }

    /**
     * Build the cache key string when storing token info in cache.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUser   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @param tokenBindingReference Token binding reference.
     * @return Cache key string combining the input parameters.
     */
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUser,
            String authenticatedIDP, String tokenBindingReference) {

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (isUsernameCaseSensitive) {
            return clientId + ":" + authorizedUser + ":" + scope + ":" + authenticatedIDP + ":" + tokenBindingReference;
        } else {
            return clientId + ":" + authorizedUser.toLowerCase() + ":" + scope + ":" + authenticatedIDP + ":"
                    + tokenBindingReference;
        }
    }

    public static void clearOAuthCache(String oauthCacheKey) {

        OAuthCacheKey cacheKey = new OAuthCacheKey(oauthCacheKey);
        OAuthCache.getInstance().clearCacheEntry(cacheKey);
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
        dto.setTokenBindingType(appDO.getTokenBindingType());
        return dto;
    }
}
