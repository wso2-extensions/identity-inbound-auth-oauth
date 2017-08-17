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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JWSAlgorithm;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.config.SpOAuth2ExpiryTimeConfiguration;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Utility methods for OAuth 2.0 implementation
 */
public class OAuth2Util {

    public static final String REMOTE_ACCESS_TOKEN = "REMOTE_ACCESS_TOKEN";
    public static final String JWT_ACCESS_TOKEN = "JWT_ACCESS_TOKEN";
    public static final String ACCESS_TOKEN_DO = "AccessTokenDo";
    public static final String OAUTH2_VALIDATION_MESSAGE_CONTEXT = "OAuth2TokenValidationMessageContext";

    private static final String ALGORITHM_NONE = "NONE";
    /*
     * OPTIONAL. A JSON string containing a space-separated list of scopes associated with this token, in the format
     * described in Section 3.3 of OAuth 2.0
     */
    public static final String SCOPE = "scope";

    /*
     * OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
     */
    public static final String CLIENT_ID = "client_id";

    /*
     * OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
     */
    public static final String USERNAME = "username";

    /*
     * OPTIONAL. Type of the token as defined in Section 5.1 of OAuth 2.0
     */
    public static final String TOKEN_TYPE = "token_type";

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token is not to be used before, as defined in JWT
     */
    public static final String NBF = "nbf";

    /*
     * OPTIONAL. Service-specific string identifier or list of string identifiers representing the intended audience for
     * this token, as defined in JWT
     */
    public static final String AUD = "aud";

    /*
     * OPTIONAL. String representing the issuer of this token, as defined in JWT
     */
    public static final String ISS = "iss";

    /*
     * OPTIONAL. String identifier for the token, as defined in JWT
     */
    public static final String JTI = "jti";

    /*
     * OPTIONAL. Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the
     * resource owner who authorized this token.
     */
    public static final String SUB = "sub";

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token will expire, as defined in JWT
     */
    public static final String EXP = "exp";

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token was originally issued, as defined in JWT
     */
    public static final String IAT = "iat";

    /***
     * Constant for user access token expiry time.
     */
    public static final String USER_ACCESS_TOKEN_TIME_IN_MILLISECONDS = "userAccessTokenExpireTime";

    /***
     * Constant for refresh token expiry time.
     */
    public static final String REFRESH_TOKEN_TIME_IN_MILLISECONDS = "refreshTokenExpireTime";

    /***
     * Constant for application access token expiry time.
     */
    public static final String APPLICATION_ACCESS_TOKEN_TIME_IN_MILLISECONDS = "applicationAccessTokenExpireTime";

    private static Log log = LogFactory.getLog(OAuth2Util.class);
    private static boolean cacheEnabled = OAuthServerConfiguration.getInstance().isCacheEnabled();
    private static OAuthCache cache = OAuthCache.getInstance();
    private static long timestampSkew = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
    private static ThreadLocal<Integer> clientTenatId = new ThreadLocal<>();
    private static ThreadLocal<OAuthTokenReqMessageContext> tokenRequestContext = new ThreadLocal<OAuthTokenReqMessageContext>();
    private static ThreadLocal<OAuthAuthzReqMessageContext> authzRequestContext = new ThreadLocal<OAuthAuthzReqMessageContext>();
    //Precompile PKCE Regex pattern for performance improvement
    private static Pattern pkceCodeVerifierPattern = Pattern.compile("[\\w\\-\\._~]+");

    private OAuth2Util(){

    }

    /**
     *
     * @return
     */
    public static OAuthAuthzReqMessageContext getAuthzRequestContext() {
	if (log.isDebugEnabled()) {
	    log.debug("Retreived OAuthAuthzReqMessageContext from threadlocal");
	}
	return authzRequestContext.get();
    }

    /**
     *
     * @param context
     */
    public static void setAuthzRequestContext(OAuthAuthzReqMessageContext context) {
	authzRequestContext.set(context);
	if (log.isDebugEnabled()) {
	    log.debug("Added OAuthAuthzReqMessageContext to threadlocal");
	}
    }

    /**
     *
     */
    public static void clearAuthzRequestContext() {
	authzRequestContext.remove();
	if (log.isDebugEnabled()) {
	    log.debug("Cleared OAuthAuthzReqMessageContext");
	}
    }

    /**
     *
     * @return
     */
    public static OAuthTokenReqMessageContext getTokenRequestContext() {
	if (log.isDebugEnabled()) {
	    log.debug("Retreived OAuthTokenReqMessageContext from threadlocal");
	}
	return tokenRequestContext.get();
    }

    /**
     *
     * @param context
     */
    public static void setTokenRequestContext(OAuthTokenReqMessageContext context) {
	tokenRequestContext.set(context);
	if (log.isDebugEnabled()) {
	    log.debug("Added OAuthTokenReqMessageContext to threadlocal");
	}
    }

    /**
     *
     */
    public static void clearTokenRequestContext() {
	tokenRequestContext.remove();
	if (log.isDebugEnabled()) {
	    log.debug("Cleared OAuthTokenReqMessageContext");
	}
    }

    /**
     * @return
     */
    public static int getClientTenatId() {
        if (clientTenatId.get() == null) {
            return -1;
        }
        return clientTenatId.get().intValue();
    }

    /**
     * @param tenantId
     */
    public static void setClientTenatId(int tenantId) {
        Integer id = Integer.valueOf(tenantId);
        clientTenatId.set(id);
    }

    /**
     *
     */
    public static void clearClientTenantId() {
        clientTenatId.remove();
    }

    /**
     * Build a comma separated list of scopes passed as a String set by OLTU.
     *
     * @param scopes set of scopes
     * @return Comma separated list of scopes
     */
    public static String buildScopeString(String[] scopes) {
        if (scopes != null) {
            StringBuilder scopeString = new StringBuilder("");
            Arrays.sort(scopes);
            for (int i = 0; i < scopes.length; i++) {
                scopeString.append(scopes[i].trim());
                if (i != scopes.length - 1) {
                    scopeString.append(" ");
                }
            }
            return scopeString.toString();
        }
        return null;
    }

    /**
     * @param scopeStr
     * @return
     */
    public static String[] buildScopeArray(String scopeStr) {
        if (StringUtils.isNotBlank(scopeStr)) {
            scopeStr = scopeStr.trim();
            return scopeStr.split("\\s");
        }
        return new String[0];
    }

    /**
     * Authenticate the OAuth Consumer
     *
     * @param clientId             Consumer Key/Id
     * @param clientSecretProvided Consumer Secret issued during the time of registration
     * @return true, if the authentication is successful, false otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     */
    public static boolean authenticateClient(String clientId, String clientSecretProvided)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        boolean cacheHit = false;
        String clientSecret = null;

        // Check the cache first.
        if (cacheEnabled) {
            CacheEntry cacheResult = cache.getValueFromCache(new OAuthCacheKey(clientId));
            if (cacheResult != null && cacheResult instanceof ClientCredentialDO) {
                ClientCredentialDO clientCredentialDO = (ClientCredentialDO) cacheResult;
                clientSecret = clientCredentialDO.getClientSecret();
                cacheHit = true;
                if (log.isDebugEnabled()) {
                    log.debug("Client credentials were available in the cache for client id : " +
                            clientId);
                }
            }
        }

        // Cache miss
        if (clientSecret == null) {
            OAuthConsumerDAO oAuthConsumerDAO = new OAuthConsumerDAO();
            clientSecret = oAuthConsumerDAO.getOAuthConsumerSecret(clientId);
            if (log.isDebugEnabled()) {
                log.debug("Client credentials were fetched from the database.");
            }
        }

        if (clientSecret == null) {
            if (log.isDebugEnabled()) {
                log.debug("Provided Client ID : " + clientId + "is not valid.");
            }
            return false;
        }

        if (!clientSecret.equals(clientSecretProvided)) {

            if (log.isDebugEnabled()) {
                log.debug("Provided the Client ID : " + clientId +
                        " and Client Secret do not match with the issued credentials.");
            }

            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Successfully authenticated the client with client id : " + clientId);
        }

        if (cacheEnabled && !cacheHit) {

            cache.addToCache(new OAuthCacheKey(clientId), new ClientCredentialDO(clientSecret));
            if (log.isDebugEnabled()) {
                log.debug("Client credentials were added to the cache for client id : " + clientId);
            }
        }

        return true;
    }

    /**
     * Authenticate the OAuth consumer and return the username of user which own the provided client id and client
     * secret.
     *
     * @param clientId             Consumer Key/Id
     * @param clientSecretProvided Consumer Secret issued during the time of registration
     * @return Username of the user which own client id and client secret if authentication is
     * successful. Empty string otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     */
    public static String getAuthenticatedUsername(String clientId, String clientSecretProvided)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        boolean cacheHit = false;
        String username = null;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(username);

        if (OAuth2Util.authenticateClient(clientId, clientSecretProvided)) {
            // check cache
            if (cacheEnabled) {
                CacheEntry cacheResult = cache.getValueFromCache(new OAuthCacheKey(clientId + ":" + username));
                if (cacheResult != null && cacheResult instanceof ClientCredentialDO) {
                    // Ugh. This is fugly. Have to have a generic way of caching a key:value pair
                    username = ((ClientCredentialDO) cacheResult).getClientSecret();
                    cacheHit = true;
                    if (log.isDebugEnabled()) {
                        log.debug("Username was available in the cache : " +
                                username);
                    }
                }
            }

            if (username == null) {
                // Cache miss
                OAuthConsumerDAO oAuthConsumerDAO = new OAuthConsumerDAO();
                username = oAuthConsumerDAO.getAuthenticatedUsername(clientId, clientSecretProvided);
                if (log.isDebugEnabled()) {
                    log.debug("Username fetch from the database");
                }
            }

            if (username != null && cacheEnabled && !cacheHit) {
                /**
                 * Using the same ClientCredentialDO to host username. Semantically wrong since ClientCredentialDo
                 * accept a client secret and we're storing a username in the secret variable. Do we have to make our
                 * own cache key and cache entry class every time we need to put something to it? Ideal solution is
                 * to have a generalized way of caching a key:value pair
                 */
                if (isUsernameCaseSensitive) {
                    cache.addToCache(new OAuthCacheKey(clientId + ":" + username), new ClientCredentialDO(username));
                } else {
                    cache.addToCache(new OAuthCacheKey(clientId + ":" + username.toLowerCase()),
                            new ClientCredentialDO(username));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Caching username : " + username);
                }

            }
        }
        return username;
    }

    /**
     * Build the cache key string when storing Authz Code info in cache
     *
     * @param clientId  Client Id representing the client
     * @param authzCode Authorization Code issued to the client
     * @return concatenated <code>String</code> of clientId:authzCode
     */
    public static String buildCacheKeyStringForAuthzCode(String clientId, String authzCode) {
        return clientId + ":" + authzCode;
    }

    public static AccessTokenDO validateAccessTokenDO(AccessTokenDO accessTokenDO) {

        long validityPeriodMillis = accessTokenDO.getValidityPeriodInMillis();
        long issuedTime = accessTokenDO.getIssuedTime().getTime();

        //check the validity of cached OAuth2AccessToken Response
        long accessTokenValidityMillis = calculateValidityInMillis(issuedTime,validityPeriodMillis);

        if (accessTokenValidityMillis > 1000) {
            long refreshValidityPeriodMillis = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * 1000;
            long refreshTokenValidityMillis = calculateValidityInMillis(issuedTime, refreshValidityPeriodMillis);
            if (refreshTokenValidityMillis > 1000) {
                //Set new validity period to response object
                accessTokenDO.setValidityPeriodInMillis(accessTokenValidityMillis);
                accessTokenDO.setRefreshTokenValidityPeriodInMillis(refreshTokenValidityMillis);
                //Set issued time period to response object
                accessTokenDO.setIssuedTime(new Timestamp(issuedTime));
                return accessTokenDO;
            }
        }
        //returns null if cached OAuth2AccessToken response object is expired
        return null;
    }

    public static boolean checkAccessTokenPartitioningEnabled() {
        return OAuthServerConfiguration.getInstance().isAccessTokenPartitioningEnabled();
    }

    public static boolean checkUserNameAssertionEnabled() {
        return OAuthServerConfiguration.getInstance().isUserNameAssertionEnabled();
    }

    public static String getAccessTokenPartitioningDomains() {
        return OAuthServerConfiguration.getInstance().getAccessTokenPartitioningDomains();
    }

    public static Map<String, String> getAvailableUserStoreDomainMappings() throws
            IdentityOAuth2Exception {
        //TreeMap is used to ignore the case sensitivity of key. Because when user logged in, the case of the user name is ignored.
        Map<String, String> userStoreDomainMap = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        String domainsStr = getAccessTokenPartitioningDomains();
        if (domainsStr != null) {
            String[] userStoreDomainsArr = domainsStr.split(",");
            for (String userStoreDomains : userStoreDomainsArr) {
                String[] mapping = userStoreDomains.trim().split(":"); //A:foo.com , B:bar.com
                if (mapping.length < 2) {
                    throw new IdentityOAuth2Exception("Domain mapping has not defined correctly");
                }
                userStoreDomainMap.put(mapping[1].trim(), mapping[0].trim()); //key=domain & value=mapping
            }
        }
        return userStoreDomainMap;
    }

    public static String getUserStoreDomainFromUserId(String userId)
            throws IdentityOAuth2Exception {
        String userStore = null;
        if (userId != null) {
            String[] strArr = userId.split("/");
            if (strArr != null && strArr.length > 1) {
                userStore = strArr[0];
                Map<String, String> availableDomainMappings = getAvailableUserStoreDomainMappings();
                if (availableDomainMappings != null &&
                        availableDomainMappings.containsKey(userStore)) {
                    userStore = getAvailableUserStoreDomainMappings().get(userStore);
                }
            }
        }
        return userStore;
    }

    public static String getUserStoreDomainFromAccessToken(String apiKey)
            throws IdentityOAuth2Exception {
        String userStoreDomain = null;
        String userId;
        String decodedKey = new String(Base64.decodeBase64(apiKey.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
        String[] tmpArr = decodedKey.split(":");
        if (tmpArr != null) {
            userId = tmpArr[1];
            if (userId != null) {
                userStoreDomain = getUserStoreDomainFromUserId(userId);
            }
        }
        return userStoreDomain;
    }

    public static String getAccessTokenStoreTableFromUserId(String userId)
            throws IdentityOAuth2Exception {
        String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
        String userStore;
        if (userId != null) {
            String[] strArr = userId.split("/");
            if (strArr != null && strArr.length > 1) {
                userStore = strArr[0];
                Map<String, String> availableDomainMappings = getAvailableUserStoreDomainMappings();
                if (availableDomainMappings != null &&
                        availableDomainMappings.containsKey(userStore)) {
                    accessTokenStoreTable = accessTokenStoreTable + "_" +
                            availableDomainMappings.get(userStore);
                }
            }
        }
        return accessTokenStoreTable;
    }

    public static String getAccessTokenStoreTableFromAccessToken(String apiKey)
            throws IdentityOAuth2Exception {
        String userId = getUserIdFromAccessToken(apiKey); //i.e: 'foo.com/admin' or 'admin'
        return getAccessTokenStoreTableFromUserId(userId);
    }

    public static String getUserIdFromAccessToken(String apiKey) {
        String userId = null;
        String decodedKey = new String(Base64.decodeBase64(apiKey.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
        String[] tmpArr = decodedKey.split(":");
        if (tmpArr != null) {
            userId = tmpArr[1];
        }
        return userId;
    }

    public static long getTokenExpireTimeMillis(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }

        long accessTokenValidity = getAccessTokenExpireMillis(accessTokenDO);
        long refreshTokenValidity = getRefreshTokenExpireTimeMillis(accessTokenDO);

        if (accessTokenValidity > 1000 && refreshTokenValidity > 1000) {
            return accessTokenValidity;
        }
        return 0;
    }

    public static long getRefreshTokenExpireTimeMillis(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }

        long refreshTokenValidityPeriodMillis = accessTokenDO.getRefreshTokenValidityPeriodInMillis();

        if (refreshTokenValidityPeriodMillis < 0) {
            if (log.isDebugEnabled()) {
                log.debug("Refresh Token has infinite lifetime");
            }
            return -1;
        }

        long refreshTokenIssuedTime = accessTokenDO.getRefreshTokenIssuedTime().getTime();
        long refreshTokenValidity = calculateValidityInMillis(refreshTokenIssuedTime, refreshTokenValidityPeriodMillis);
        if (refreshTokenValidity > 1000) {
            return refreshTokenValidity;
        }
        return 0;
    }

    public static long getAccessTokenExpireMillis(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }
        long validityPeriodMillis = accessTokenDO.getValidityPeriodInMillis();

        if (validityPeriodMillis < 0) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Access Token(hashed) : " + DigestUtils.sha256Hex(accessTokenDO.getAccessToken()) +
                            " has infinite lifetime");
                } else {
                    log.debug("Access Token has infinite lifetime");
                }
            }
            return -1;
        }

        long issuedTime = accessTokenDO.getIssuedTime().getTime();
        long validityMillis = calculateValidityInMillis(issuedTime, validityPeriodMillis);
        if (validityMillis > 1000) {
            return validityMillis;
        } else {
            return 0;
        }
    }

    /**
     * Util method to calculate the validity period after applying skew corrections.
     *
     * @param issuedTimeInMillis
     * @param validityPeriodMillis
     * @return skew corrected validity period in milliseconds
     */
    public static long calculateValidityInMillis(long issuedTimeInMillis, long validityPeriodMillis) {

        return issuedTimeInMillis + validityPeriodMillis - (System.currentTimeMillis() - timestampSkew);
    }

    public static int getTenantId(String tenantDomain) throws IdentityOAuth2Exception {
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        try {
            return realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            String error = "Error in obtaining tenant ID from tenant domain : " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    public static String getTenantDomain(int tenantId) throws IdentityOAuth2Exception {
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        try {
            return realmService.getTenantManager().getDomain(tenantId);
        } catch (UserStoreException e) {
            String error = "Error in obtaining tenant domain from tenant ID : " + tenantId;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    public static int getTenantIdFromUserName(String username) throws IdentityOAuth2Exception {

        String domainName = MultitenantUtils.getTenantDomain(username);
        return getTenantId(domainName);
    }

    public static String hashScopes(String[] scope) {
        return DigestUtils.md5Hex(OAuth2Util.buildScopeString(scope));
    }

    public static String hashScopes(String scope) {
        if (scope != null) {
            //first converted to an array to sort the scopes
            return DigestUtils.md5Hex(OAuth2Util.buildScopeString(buildScopeArray(scope)));
        } else {
            return null;
        }
    }

    public static AuthenticatedUser getUserFromUserName(String username) throws IllegalArgumentException {
        if (StringUtils.isNotBlank(username)) {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            String tenantAwareUsernameWithNoUserDomain = UserCoreUtil.removeDomainFromName(tenantAwareUsername);
            String userStoreDomain = IdentityUtil.extractDomainFromName(username).toUpperCase();
            AuthenticatedUser user = new AuthenticatedUser();
            user.setUserName(tenantAwareUsernameWithNoUserDomain);
            user.setTenantDomain(tenantDomain);
            user.setUserStoreDomain(userStoreDomain);

            return user;
        }
        throw new IllegalArgumentException("Cannot create user from empty user name");
    }

    public static String getIDTokenIssuer() {
        String issuer = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenIssuerIdentifier();
        if (StringUtils.isBlank(issuer)) {
            issuer = OAuthURL.getOAuth2TokenEPUrl();
        }
        return issuer;
    }

    public static class OAuthURL {

        public static String getOAuth1RequestTokenUrl() {
            String oauth1RequestTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1RequestTokenUrl();
            if(StringUtils.isBlank(oauth1RequestTokenUrl)){
                oauth1RequestTokenUrl = IdentityUtil.getServerURL("oauth/request-token", true, true);
            }
            return oauth1RequestTokenUrl;
        }

        public static String getOAuth1AuthorizeUrl() {
            String oauth1AuthorizeUrl = OAuthServerConfiguration.getInstance().getOAuth1AuthorizeUrl();
            if(StringUtils.isBlank(oauth1AuthorizeUrl)){
                oauth1AuthorizeUrl = IdentityUtil.getServerURL("oauth/authorize-url", true, true);
            }
            return oauth1AuthorizeUrl;
        }

        public static String getOAuth1AccessTokenUrl() {
            String oauth1AccessTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1AccessTokenUrl();
            if(StringUtils.isBlank(oauth1AccessTokenUrl)){
                oauth1AccessTokenUrl = IdentityUtil.getServerURL("oauth/access-token", true, true);
            }
            return oauth1AccessTokenUrl;
        }

        public static String getOAuth2AuthzEPUrl() {
            String oauth2AuthzEPUrl = OAuthServerConfiguration.getInstance().getOAuth2AuthzEPUrl();
            if(StringUtils.isBlank(oauth2AuthzEPUrl)){
                oauth2AuthzEPUrl = IdentityUtil.getServerURL("oauth2/authorize", true, false);
            }
            return oauth2AuthzEPUrl;
        }

        public static String getOAuth2TokenEPUrl() {
            String oauth2TokenEPUrl = OAuthServerConfiguration.getInstance().getOAuth2TokenEPUrl();
            if(StringUtils.isBlank(oauth2TokenEPUrl)){
                oauth2TokenEPUrl = IdentityUtil.getServerURL("oauth2/token", true, false);
            }
            return oauth2TokenEPUrl;
        }

        public static String getOAuth2DCREPUrl(String tenantDomain) throws URISyntaxException {
            String oauth2TokenEPUrl = OAuthServerConfiguration.getInstance().getOAuth2DCREPUrl();
            if (StringUtils.isBlank(oauth2TokenEPUrl)) {
                oauth2TokenEPUrl = IdentityUtil.getServerURL("/identity/connect/register", true, false);
            }
            if (StringUtils.isNotBlank(tenantDomain) && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals
                    (tenantDomain)) {
                oauth2TokenEPUrl = getTenantUrl(oauth2TokenEPUrl, tenantDomain);
            }
            return oauth2TokenEPUrl;
        }

        public static String getOAuth2JWKSPageUrl(String tenantDomain) throws URISyntaxException {
            String auth2JWKSPageUrl = OAuthServerConfiguration.getInstance().getOAuth2JWKSPageUrl();
            if (StringUtils.isBlank(auth2JWKSPageUrl)) {
                auth2JWKSPageUrl = IdentityUtil.getServerURL("/oauth2/jwks", true, false);
            }
            if (StringUtils.isNotBlank(tenantDomain) && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals
                    (tenantDomain)) {
                auth2JWKSPageUrl = getTenantUrl(auth2JWKSPageUrl, tenantDomain);
            }
            return auth2JWKSPageUrl;
        }

        public static String getOidcWebFingerEPUrl() {
            String oauth2TokenEPUrl = OAuthServerConfiguration.getInstance().getOidcWebFingerEPUrl();
            if (StringUtils.isBlank(oauth2TokenEPUrl)) {
                oauth2TokenEPUrl = IdentityUtil.getServerURL(".well-know/webfinger", true, false);
            }
            return oauth2TokenEPUrl;
        }

        public static String getOidcDiscoveryEPUrl(String tenantDomain) throws URISyntaxException {
            String oidcDiscoveryEPUrl = OAuthServerConfiguration.getInstance().getOidcDiscoveryUrl();
            if (StringUtils.isBlank(oidcDiscoveryEPUrl)) {
                oidcDiscoveryEPUrl = IdentityUtil.getServerURL("/oauth2/oidcdiscovery", true, false);
            }
            if (StringUtils.isNotBlank(tenantDomain) && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals
                    (tenantDomain)) {
                oidcDiscoveryEPUrl = getTenantUrl(oidcDiscoveryEPUrl, tenantDomain);
            }
            return oidcDiscoveryEPUrl;
        }

        public static String getOAuth2UserInfoEPUrl() {
            String oauth2UserInfoEPUrl = OAuthServerConfiguration.getInstance().getOauth2UserInfoEPUrl();
            if(StringUtils.isBlank(oauth2UserInfoEPUrl)){
                oauth2UserInfoEPUrl = IdentityUtil.getServerURL("oauth2/userinfo", true, false);
            }
            return oauth2UserInfoEPUrl;
        }

        public static String getOIDCConsentPageUrl() {
            String OIDCConsentPageUrl = OAuthServerConfiguration.getInstance().getOIDCConsentPageUrl();
            if(StringUtils.isBlank(OIDCConsentPageUrl)){
                OIDCConsentPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_consent.do", false,
                        false);
            }
            return OIDCConsentPageUrl;
        }

        public static String getOAuth2ConsentPageUrl() {
            String oAuth2ConsentPageUrl = OAuthServerConfiguration.getInstance().getOauth2ConsentPageUrl();
            if(StringUtils.isBlank(oAuth2ConsentPageUrl)){
                oAuth2ConsentPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_authz.do", false,
                        false);
            }
            return oAuth2ConsentPageUrl;
        }

        public static String getOAuth2ErrorPageUrl() {
            String oAuth2ErrorPageUrl = OAuthServerConfiguration.getInstance().getOauth2ErrorPageUrl();
            if(StringUtils.isBlank(oAuth2ErrorPageUrl)){
                oAuth2ErrorPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_error.do", false, false);
            }
            return oAuth2ErrorPageUrl;
        }

        private static String getTenantUrl(String url, String tenantDomain) throws URISyntaxException {
            URI uri = new URI(url);
            URI uriModified = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), ("/t/" +
                    tenantDomain + uri.getPath()), uri.getQuery(), uri.getFragment());
            return uriModified.toString();
        }
    }

    public static boolean isOIDCAuthzRequest(Set<String> scope) {
        return scope.contains(OAuthConstants.Scope.OPENID);
    }

    public static boolean isOIDCAuthzRequest(String[] scope) {
        for(String openidscope : scope) {
            if (openidscope.equals(OAuthConstants.Scope.OPENID)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifies if the PKCE code verifier is upto specification as per RFC 7636
     * @param codeVerifier PKCE Code Verifier sent with the token request
     * @return
     */
    public static boolean validatePKCECodeVerifier(String codeVerifier) {
        Matcher pkceCodeVerifierMatcher = pkceCodeVerifierPattern.matcher(codeVerifier);
        if(!pkceCodeVerifierMatcher.matches() || (codeVerifier.length() < 43 || codeVerifier.length() > 128)) {
            return false;
        }
        return true;
    }

    /**
     * Verifies if the codeChallenge is upto specification as per RFC 7636
     * @param codeChallenge
     * @param codeChallengeMethod
     * @return
     */
    public static boolean validatePKCECodeChallenge(String codeChallenge, String codeChallengeMethod) {
        if(codeChallengeMethod == null || OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(codeChallengeMethod)) {
            return validatePKCECodeVerifier(codeChallenge);
        }
        else if (OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(codeChallengeMethod)) {
            // SHA256 code challenge is 256 bits that is 256 / 6 ~= 43
            // See https://tools.ietf.org/html/rfc7636#section-3
            if(codeChallenge != null && codeChallenge.trim().length() == 43) {
                return true;
            }
        }
        //provided code challenge method is wrong
        return false;
    }
    public static boolean doPKCEValidation(String referenceCodeChallenge, String codeVerifier, String challenge_method, OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {
        //ByPass PKCE validation if PKCE Support is disabled
        if(!isPKCESupportEnabled()) {
            return true;
        }
        if (oAuthAppDO != null && oAuthAppDO.isPkceMandatory() || referenceCodeChallenge != null) {

            //As per RFC 7636 Fallback to 'plain' if no code_challenge_method parameter is sent
            if(challenge_method == null || challenge_method.trim().length() == 0) {
                challenge_method = "plain";
            }

            //if app with no PKCE code verifier arrives
            if ((codeVerifier == null || codeVerifier.trim().length() == 0)) {
                //if pkce is mandatory, throw error
                if(oAuthAppDO.isPkceMandatory()) {
                    throw new IdentityOAuth2Exception("No PKCE code verifier found.PKCE is mandatory for this " +
                            "oAuth 2.0 application.");
                } else {
                    //PKCE is optional, see if the authz code was requested with a PKCE challenge
                    if(referenceCodeChallenge == null || referenceCodeChallenge.trim().length() == 0) {
                        //since no PKCE challenge was provided
                        return true;
                    } else {
                        throw new IdentityOAuth2Exception("Empty PKCE code_verifier sent. This authorization code " +
                                "requires a PKCE verification to obtain an access token.");
                    }
                }
            }
            //verify that the code verifier is upto spec as per RFC 7636
            if(!validatePKCECodeVerifier(codeVerifier)) {
                throw new IdentityOAuth2Exception("Code verifier used is not up to RFC 7636 specifications.");
            }
            if (OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(challenge_method)) {
                //if the current application explicitly doesn't support plain, throw exception
                if(!oAuthAppDO.isPkceSupportPlain()) {
                    throw new IdentityOAuth2Exception("This application does not allow 'plain' transformation algorithm.");
                }
                if (!referenceCodeChallenge.equals(codeVerifier)) {
                    return false;
                }
            } else if (OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(challenge_method)) {

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

                    byte[] hash = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                    //Trim the base64 string to remove trailing CR LF characters.
                    String referencePKCECodeChallenge = new String(Base64.encodeBase64URLSafe(hash),
                            StandardCharsets.UTF_8).trim();
                    if (!referencePKCECodeChallenge.equals(referenceCodeChallenge)) {
                        return false;
                    }
                } catch (NoSuchAlgorithmException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to create SHA256 Message Digest.");
                    }
                    return false;
                }
            } else {
                //Invalid OAuth2 token response
                throw new IdentityOAuth2Exception("Invalid OAuth2 Token Response. Invalid PKCE Code Challenge Method '"
                        + challenge_method + "'");
            }
        }
        //pkce validation successful
        return true;
    }

    public static boolean isPKCESupportEnabled() {
        return OAuth2ServiceComponentHolder.isPkceEnabled();
    }

    public static boolean isImplicitResponseType(String responseType) {
        if(StringUtils.isNotBlank(responseType) && (responseType.contains(ResponseType.TOKEN.toString()) ||
                responseType.contains(OAuthConstants.ID_TOKEN))) {
            return true;
        }
        return false;
    }

    public static void initiateOIDCScopes(int tenantId) {
        try {
            Map<String, String> scopes = loadScopeConfigFile();
            Registry registry = OAuth2ServiceComponentHolder.getRegistryService().getConfigSystemRegistry(tenantId);

            if (!registry
                    .resourceExists(OAuthConstants.SCOPE_RESOURCE_PATH)) {

                Resource resource = registry.newResource();
                if (scopes.size() > 0) {
                    for (Map.Entry<String, String> entry : scopes.entrySet()) {
                        String valueStr = entry.getValue().toString();
                        resource.setProperty(entry.getKey(), valueStr);
                    }
                }

                registry.put(OAuthConstants.SCOPE_RESOURCE_PATH, resource);
            }
        } catch (RegistryException e) {
            log.error("Error while creating registry collection for :" + OAuthConstants.SCOPE_RESOURCE_PATH, e);
        }
    }

    public static List<String> getOIDCScopes(String tenantDomain) {
        try {
            int tenantId = OAuthComponentServiceHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            Registry registry = OAuth2ServiceComponentHolder.getRegistryService().getConfigSystemRegistry(tenantId);

            if (registry.resourceExists(OAuthConstants.SCOPE_RESOURCE_PATH)) {
                Resource resource = registry.get(OAuthConstants.SCOPE_RESOURCE_PATH);
                Properties properties = resource.getProperties();
                Enumeration e = properties.propertyNames();
                List<String> scopes = new ArrayList();
                while (e.hasMoreElements()) {
                    scopes.add((String) e.nextElement());
                }
                return scopes;
            }
        } catch (RegistryException | UserStoreException e) {
            log.error("Error while retrieving registry collection for :" + OAuthConstants.SCOPE_RESOURCE_PATH, e);
        }
        return new ArrayList<>();
    }

    public static AccessTokenDO getAccessTokenDOfromTokenIdentifier(String accessTokenIdentifier) throws
            IdentityOAuth2Exception {
        boolean cacheHit = false;
        AccessTokenDO accessTokenDO = null;
        // check the cache, if caching is enabled.
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            OAuthCache oauthCache = OAuthCache.getInstance();
            OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
            CacheEntry result = oauthCache.getValueFromCache(cacheKey);
            // cache hit, do the type check.
            if (result instanceof AccessTokenDO) {
                accessTokenDO = (AccessTokenDO) result;
                cacheHit = true;
            }
        }
        // cache miss, load the access token info from the database.
        if (accessTokenDO == null) {
            accessTokenDO = new TokenMgtDAO().retrieveAccessToken(accessTokenIdentifier, false);
        }

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("Invalid access token");
        }

        // add the token back to the cache in the case of a cache miss
        if (OAuthServerConfiguration.getInstance().isCacheEnabled() && !cacheHit) {
            OAuthCache oauthCache = OAuthCache.getInstance();
            OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
            oauthCache.addToCache(cacheKey, accessTokenDO);
            if (log.isDebugEnabled()) {
                log.debug("Access Token Info object was added back to the cache.");
            }
        }

        return accessTokenDO;
    }


    public static String getClientIdForAccessToken(String accessTokenIdentifier) throws IdentityOAuth2Exception {
        AccessTokenDO accessTokenDO = getAccessTokenDOfromTokenIdentifier(accessTokenIdentifier);
        return accessTokenDO.getConsumerKey();
    }

    /***
     * Read the configuration file at server start up.
     * @param tenantId
     */
    public static void initTokenExpiryTimesOfSps(int tenantId) {
        try{
            Registry registry = OAuth2ServiceComponentHolder.getRegistryService().getConfigSystemRegistry(tenantId);
            if (!registry.resourceExists(OAuthConstants.TOKEN_EXPIRE_TIME_RESOURCE_PATH)) {
                Resource resource = registry.newResource();
                registry.put(OAuthConstants.TOKEN_EXPIRE_TIME_RESOURCE_PATH, resource);
            }
        } catch (RegistryException e) {
            log.error("Error while creating registry collection for :" + OAuthConstants.TOKEN_EXPIRE_TIME_RESOURCE_PATH, e);
        }
    }

    /***
     * Return the SP-token Expiry time configuration object when consumer key is given.
     * @param consumerKey
     * @param tenantId
     * @return A SpOAuth2ExpiryTimeConfiguration Object
     */
    public static SpOAuth2ExpiryTimeConfiguration getSpTokenExpiryTimeConfig(String consumerKey, int tenantId) {
        SpOAuth2ExpiryTimeConfiguration spTokenTimeObject = new SpOAuth2ExpiryTimeConfiguration();
        try {
            if (log.isDebugEnabled()) {
                log.debug("SP wise token expiry time feature is applied for tenant id : " + tenantId
                        + "and consumer key : " + consumerKey);
            }
            IdentityTenantUtil.initializeRegistry(tenantId, getTenantDomain(tenantId));
            Registry registry = IdentityTenantUtil.getConfigRegistry(tenantId);
            if (registry.resourceExists(OAuthConstants.TOKEN_EXPIRE_TIME_RESOURCE_PATH)) {
                Resource resource = registry.get(OAuthConstants.TOKEN_EXPIRE_TIME_RESOURCE_PATH);
                String jsonString = "{}";
                Object consumerKeyObject = resource.getProperties().get(consumerKey);
                if (consumerKeyObject instanceof List) {
                    if (!((List) consumerKeyObject).isEmpty()) {
                        jsonString = ((List) consumerKeyObject).get(0).toString();
                    }
                }
                JSONObject spTimeObject = new JSONObject(jsonString);
                if (spTimeObject.length() > 0) {
                    if (spTimeObject.has(USER_ACCESS_TOKEN_TIME_IN_MILLISECONDS) &&
                            !spTimeObject.isNull(USER_ACCESS_TOKEN_TIME_IN_MILLISECONDS)) {
                        try {
                            spTokenTimeObject.setUserAccessTokenExpiryTime(Long.parseLong(spTimeObject
                                    .get(USER_ACCESS_TOKEN_TIME_IN_MILLISECONDS).toString()));
                            if (log.isDebugEnabled()) {
                                log.debug("The user access token expiry time :" + spTimeObject
                                        .get(USER_ACCESS_TOKEN_TIME_IN_MILLISECONDS).toString() +
                                        "  for application id : " + consumerKey);
                            }
                        } catch (NumberFormatException e) {
                            String errorMsg = String.format("Invalid value provided as user access token expiry time for consumer key %s," +
                                    " tenant id : %d. Given value: %s, Expected a long value", consumerKey, tenantId, spTimeObject
                                    .get(USER_ACCESS_TOKEN_TIME_IN_MILLISECONDS).toString());
                            log.error(errorMsg, e);
                        }
                    } else {
                        spTokenTimeObject.setUserAccessTokenExpiryTime(OAuthServerConfiguration.getInstance()
                                .getUserAccessTokenValidityPeriodInSeconds() * 1000);
                    }

                    if (spTimeObject.has(APPLICATION_ACCESS_TOKEN_TIME_IN_MILLISECONDS) &&
                            !spTimeObject.isNull(APPLICATION_ACCESS_TOKEN_TIME_IN_MILLISECONDS)) {
                        try {
                            spTokenTimeObject.setApplicationAccessTokenExpiryTime(Long.parseLong(spTimeObject
                                    .get(APPLICATION_ACCESS_TOKEN_TIME_IN_MILLISECONDS).toString()));
                            if (log.isDebugEnabled()) {
                                log.debug("The application access token expiry time :" + spTimeObject
                                        .get(APPLICATION_ACCESS_TOKEN_TIME_IN_MILLISECONDS).toString() +
                                        "  for application id : " + consumerKey);
                            }
                        } catch (NumberFormatException e) {
                            String errorMsg = String.format("Invalid value provided as application access token expiry time for " +
                                    "consumer key %s, tenant id : %d. Given value: %s, Expected a long value ", consumerKey, tenantId, spTimeObject
                                    .get(APPLICATION_ACCESS_TOKEN_TIME_IN_MILLISECONDS).toString());
                            log.error(errorMsg, e);
                        }
                    } else {
                        spTokenTimeObject.setApplicationAccessTokenExpiryTime(OAuthServerConfiguration.getInstance()
                                .getApplicationAccessTokenValidityPeriodInSeconds() * 1000);
                    }

                    if (spTimeObject.has(REFRESH_TOKEN_TIME_IN_MILLISECONDS) &&
                            !spTimeObject.isNull(REFRESH_TOKEN_TIME_IN_MILLISECONDS)) {
                        try {
                            spTokenTimeObject.setRefreshTokenExpiryTime(Long.parseLong(spTimeObject
                                    .get(REFRESH_TOKEN_TIME_IN_MILLISECONDS).toString()));
                            if (log.isDebugEnabled()) {
                                log.debug("The refresh token expiry time :" + spTimeObject
                                        .get(REFRESH_TOKEN_TIME_IN_MILLISECONDS).toString() +
                                        " for application id : " + consumerKey);
                            }

                        } catch (NumberFormatException e) {
                            String errorMsg = String.format("Invalid value provided as refresh token expiry time for consumer key %s," +
                                    " tenant id : %d. Given value: %s, Expected a long value", consumerKey, tenantId, spTimeObject
                                    .get(REFRESH_TOKEN_TIME_IN_MILLISECONDS).toString());
                            log.error(errorMsg, e);
                        }
                    } else {
                        spTokenTimeObject.setRefreshTokenExpiryTime(OAuthServerConfiguration.getInstance()
                                .getRefreshTokenValidityPeriodInSeconds() * 1000);
                    }
                }
            }
        } catch (RegistryException e) {
            log.error("Error while getting data from the registry.", e);
        } catch (IdentityException e) {
            log.error("Error while getting the tenant domain from tenant id : " + tenantId, e);
        }
        return spTokenTimeObject;
    }

    private static Map<String, String> loadScopeConfigFile() {
        Map<String, String> scopes = new HashMap<>();
        String configDirPath = CarbonUtils.getCarbonConfigDirPath();
        String confXml =
                Paths.get(configDirPath, "identity", OAuthConstants.OIDC_SCOPE_CONFIG_PATH)
                        .toString();
        File configfile = new File(confXml);
        if (!configfile.exists()) {
            log.warn("OIDC scope-claim Configuration File is not present at: " + confXml);
        }

        XMLStreamReader parser = null;
        InputStream stream = null;

        try {
            stream = new FileInputStream(configfile);
            parser = XMLInputFactory.newInstance()
                    .createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                OMElement omElement = (OMElement) iterator.next();
                String configType = omElement.getAttributeValue(new QName(
                        "id"));
                scopes.put(configType, loadClaimConfig(omElement));
            }
        } catch (XMLStreamException e) {
            log.warn("Error while loading scope config.", e);
        } catch (FileNotFoundException e) {
            log.warn("Error while loading email config.", e);
        } finally {
            try {
                if (parser != null) {
                    parser.close();
                }
                if (stream != null) {
                    IdentityIOStreamUtils.closeInputStream(stream);
                }
            } catch (XMLStreamException e) {
                log.error("Error while closing XML stream", e);
            }
        }
        return scopes;
    }

    private static String loadClaimConfig(OMElement configElement) {
        StringBuilder claimConfig = new StringBuilder();
        Iterator it = configElement.getChildElements();
        while (it.hasNext()) {
            OMElement element = (OMElement) it.next();
            if ("Claim".equals(element.getLocalName())) {
                String commaSeparatedClaimNames = element.getText();
                if(StringUtils.isNotBlank(commaSeparatedClaimNames)){
                    claimConfig.append(commaSeparatedClaimNames.trim());
                }
            }
        }
        return claimConfig.toString();
    }

    /**
     * Get Oauth application information
     *
     * @param clientId
     * @return Oauth app information
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static OAuthAppDO getAppInformationByClientId(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO != null) {
            return oAuthAppDO;
        } else {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId);
            AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
            return oAuthAppDO;
        }
    }

    /**
     * Get the tenant domain of an oauth application
     *
     * @param oAuthAppDO
     * @return
     */
    public static String getTenantDomainOfOauthApp(OAuthAppDO oAuthAppDO) {
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (oAuthAppDO != null) {
            AuthenticatedUser appDeveloper = oAuthAppDO.getUser();
            tenantDomain = appDeveloper.getTenantDomain();
        }
        return tenantDomain;
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     *
     * @param signatureAlgorithm
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String mapSignatureAlgorithm(String signatureAlgorithm)
            throws IdentityOAuth2Exception {
        if ("SHA256withRSA".equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS256.getName();
        } else if ("SHA384withRSA".equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS384.getName();
        } else if ("SHA512withRSA".equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS512.getName();
        } else if ("SHA256withHMAC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS256.getName();
        } else if ("SHA384withHMAC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS384.getName();
        } else if ("SHA512withHMAC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS512.getName();
        } else if ("SHA256withEC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES256.getName();
        } else if ("SHA384withEC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES384.getName();
        } else if ("SHA512withEC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES512.getName();
        } else if (ALGORITHM_NONE.equals(signatureAlgorithm)) {
            return JWSAlgorithm.NONE.getName();
        }
        log.error("Unsupported Signature Algorithm in identity.xml");
        throw new IdentityOAuth2Exception("Unsupported Signature Algorithm in identity.xml");
    }


    /**
     * Generate the unique user domain value in the format of "FEDERATED:idp_name".
     *
     * @param authenticatedIDP : Name of the IDP, which authenticated the user.
     * @return
     */
    public static String getFederatedUserDomain(String authenticatedIDP) {
        if (IdentityUtil.isNotBlank(authenticatedIDP)) {
            return OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX + OAuthConstants.UserType.FEDERATED_USER_DOMAIN_SEPARATOR +
                    authenticatedIDP;
        } else {
            return OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX;
        }
    }
}
