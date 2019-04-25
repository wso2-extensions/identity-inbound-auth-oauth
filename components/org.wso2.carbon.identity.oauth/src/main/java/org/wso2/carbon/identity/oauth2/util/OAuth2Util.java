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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
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
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.config.SpOAuth2ExpiryTimeConfiguration;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
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
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
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
    private static final String ESSENTAIL = "essential";
    public static final String CONFIG_ELEM_OAUTH = "OAuth";
    public static final String OPENID_CONNECT = "OpenIDConnect";
    public static final String ENABLE_OPENID_CONNECT_AUDIENCES = "EnableAudiences";
    public static final String OPENID_CONNECT_AUDIENCE = "audience";
    private static final String OPENID_CONNECT_AUDIENCES = "Audiences";
    private static final String DOT_SEPARATER = ".";
    private static final String IDP_ENTITY_ID = "IdPEntityId";

    public static final String DEFAULT_TOKEN_TYPE = "Default";

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
    public static final String USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS = "userAccessTokenExpireTime";

    /***
     * Constant for refresh token expiry time.
     */
    public static final String REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS = "refreshTokenExpireTime";

    /***
     * Constant for application access token expiry time.
     */
    public static final String APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS = "applicationAccessTokenExpireTime";

    private static Log log = LogFactory.getLog(OAuth2Util.class);
    private static long timestampSkew = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
    private static ThreadLocal<Integer> clientTenantId = new ThreadLocal<>();
    private static ThreadLocal<OAuthTokenReqMessageContext> tokenRequestContext = new ThreadLocal<>();
    private static ThreadLocal<OAuthAuthzReqMessageContext> authzRequestContext = new ThreadLocal<>();
    //Precompile PKCE Regex pattern for performance improvement
    private static Pattern pkceCodeVerifierPattern = Pattern.compile("[\\w\\-\\._~]+");

    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();

    // Supported Signature Algorithms
    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";
    private static final String SHA256_WITH_PS = "SHA256withPS";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";

    // Supported Client Authentication Methods
    private static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    private static final String CLIENT_SECRET_POST = "client_secret_post";
    private static final String PRIVATE_KEY_JWT = "private_key_jwt";

    private OAuth2Util() {

    }

    /**
     * @return
     */
    public static OAuthAuthzReqMessageContext getAuthzRequestContext() {

        if (log.isDebugEnabled()) {
            log.debug("Retreived OAuthAuthzReqMessageContext from threadlocal");
        }
        return authzRequestContext.get();
    }

    /**
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
     * @return
     */
    public static OAuthTokenReqMessageContext getTokenRequestContext() {

        if (log.isDebugEnabled()) {
            log.debug("Retreived OAuthTokenReqMessageContext from threadlocal");
        }
        return tokenRequestContext.get();
    }

    /**
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

        if (clientTenantId.get() == null) {
            return -1;
        }
        return clientTenantId.get();
    }

    /**
     * @param tenantId
     */
    public static void setClientTenatId(int tenantId) {

        Integer id = tenantId;
        clientTenantId.set(id);
    }

    /**
     *
     */
    public static void clearClientTenantId() {

        clientTenantId.remove();
    }

    /**
     * Build a comma separated list of scopes passed as a String set by OLTU.
     *
     * @param scopes set of scopes
     * @return Comma separated list of scopes
     */
    public static String buildScopeString(String[] scopes) {

        if (scopes != null) {
            Arrays.sort(scopes);
            return StringUtils.join(scopes, " ");
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

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
        if (appDO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a valid application with the provided client_id: " + clientId);
            }
            return false;
        }

        // Cache miss
        boolean isHashDisabled = isHashDisabled();
        String appClientSecret = appDO.getOauthConsumerSecret();
        if (isHashDisabled) {
            if (!StringUtils.equals(appClientSecret, clientSecretProvided)) {
                if (log.isDebugEnabled()) {
                    log.debug("Provided the Client ID : " + clientId +
                            " and Client Secret do not match with the issued credentials.");
                }
                return false;
            }
        } else {
            TokenPersistenceProcessor persistenceProcessor = getPersistenceProcessor();
            // We convert the provided client_secret to the processed form stored in the DB.
            String processedProvidedClientSecret = persistenceProcessor.getProcessedClientSecret(clientSecretProvided);

            if (!StringUtils.equals(appClientSecret, processedProvidedClientSecret)) {
                if (log.isDebugEnabled()) {
                    log.debug("Provided the Client ID : " + clientId +
                            " and Client Secret do not match with the issued credentials.");
                }
                return false;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Successfully authenticated the client with client id : " + clientId);
        }

        return true;
    }

    private static TokenPersistenceProcessor getPersistenceProcessor() {

        TokenPersistenceProcessor persistenceProcessor;
        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            String msg = "Error retrieving TokenPersistenceProcessor configured in OAuth.TokenPersistenceProcessor " +
                    "in identity.xml. Defaulting to PlainTextPersistenceProcessor.";
            log.warn(msg);
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }
        return persistenceProcessor;
    }

    /**
     * Check whether hashing oauth keys (consumer secret, access token, refresh token and authorization code)
     * configuration is disabled or not in identity.xml file.
     *
     * @return Whether hash feature is disabled or not.
     */
    public static boolean isHashDisabled() {

        boolean isHashEnabled = OAuthServerConfiguration.getInstance().isClientSecretHashEnabled();
        return !isHashEnabled;

    }

    /**
     * @param clientId             Consumer Key/Id
     * @param clientSecretProvided Consumer Secret issued during the time of registration
     * @return Username of the user which own client id and client secret if authentication is
     * successful. Empty string otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     * @deprecated Authenticate the OAuth consumer and return the username of user which own the provided client id
     * and client secret.
     */
    public static String getAuthenticatedUsername(String clientId, String clientSecretProvided)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        boolean cacheHit = false;
        String username = null;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(username);

        if (OAuth2Util.authenticateClient(clientId, clientSecretProvided)) {

            CacheEntry cacheResult =
                    OAuthCache.getInstance().getValueFromCache(new OAuthCacheKey(clientId + ":" + username));
            if (cacheResult != null && cacheResult instanceof ClientCredentialDO) {
                // Ugh. This is fugly. Have to have a generic way of caching a key:value pair
                username = ((ClientCredentialDO) cacheResult).getClientSecret();
                cacheHit = true;
                if (log.isDebugEnabled()) {
                    log.debug("Username was available in the cache : " + username);
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

            if (username != null && !cacheHit) {
                /*
                  Using the same ClientCredentialDO to host username. Semantically wrong since ClientCredentialDo
                  accept a client secret and we're storing a username in the secret variable. Do we have to make our
                  own cache key and cache entry class every time we need to put something to it? Ideal solution is
                  to have a generalized way of caching a key:value pair
                 */
                if (isUsernameCaseSensitive) {
                    OAuthCache.getInstance()
                            .addToCache(new OAuthCacheKey(clientId + ":" + username), new ClientCredentialDO(username));
                } else {
                    OAuthCache.getInstance().addToCache(new OAuthCacheKey(clientId + ":" + username.toLowerCase()),
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

    /**
     * Build the cache key string when storing token info in cache
     *
     * @param clientId
     * @param scope
     * @param authorizedUser
     * @return
     */
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUser) {

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (isUsernameCaseSensitive) {
            return clientId + ":" + authorizedUser + ":" + scope;
        } else {
            return clientId + ":" + authorizedUser.toLowerCase() + ":" + scope;
        }
    }

    public static AccessTokenDO validateAccessTokenDO(AccessTokenDO accessTokenDO) {

        long validityPeriodMillis = accessTokenDO.getValidityPeriodInMillis();
        long issuedTime = accessTokenDO.getIssuedTime().getTime();

        //check the validity of cached OAuth2AccessToken Response
        long accessTokenValidityMillis = getTimeToExpire(issuedTime, validityPeriodMillis);

        if (accessTokenValidityMillis > 1000) {
            long refreshValidityPeriodMillis = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * 1000;
            long refreshTokenValidityMillis = getTimeToExpire(issuedTime, refreshValidityPeriodMillis);
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
        //TreeMap is used to ignore the case sensitivity of key. Because when user logged in, the case of the username is ignored.
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

    /**
     * Returns the mapped user store if a mapping is defined for this user store in AccessTokenPartitioningDomains
     * element in identity.xml, or the original userstore domain if the mapping is not available.
     *
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getMappedUserStoreDomain(String userStoreDomain) throws IdentityOAuth2Exception {

        String mappedUserStoreDomain = userStoreDomain;

        Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
        if (userStoreDomain != null && availableDomainMappings.containsKey(userStoreDomain)) {
            mappedUserStoreDomain = availableDomainMappings.get(userStoreDomain);
        }

        return mappedUserStoreDomain;
    }

    /**
     * Returns the updated table name using user store domain if a mapping is defined for this users store in
     * AccessTokenPartitioningDomains element in identity.xml,
     * or the original table name if the mapping is not available.
     * <p>
     * Updated table name derived by appending a underscore and mapped user store domain name to the origin table name.
     *
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getPartitionedTableByUserStore(String tableName, String userStoreDomain)
            throws IdentityOAuth2Exception {

        if (StringUtils.isNotBlank(tableName) && StringUtils.isNotBlank(userStoreDomain) &&
                !IdentityUtil.getPrimaryDomainName().equalsIgnoreCase(userStoreDomain)) {
            String mappedUserStoreDomain = OAuth2Util.getMappedUserStoreDomain(userStoreDomain);
            tableName = tableName + "_" + mappedUserStoreDomain;
        }

        return tableName;
    }

    /**
     * Returns the updated sql using user store domain if access token partitioning enabled & username assertion enabled
     * or the original sql otherwise.
     * <p>
     * Updated sql derived by replacing original table names IDN_OAUTH2_ACCESS_TOKEN & IDN_OAUTH2_ACCESS_TOKEN_SCOPE
     * with the updated table names which derived using {@code getPartitionedTableByUserStore()} method.
     *
     * @param sql
     * @param userStoreDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getTokenPartitionedSqlByUserStore(String sql, String userStoreDomain)
            throws IdentityOAuth2Exception {

        String partitionedSql = sql;

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {

            String partitionedAccessTokenTable = OAuth2Util.getPartitionedTableByUserStore(OAuthConstants.
                    ACCESS_TOKEN_STORE_TABLE, userStoreDomain);

            String accessTokenScopeTable = "IDN_OAUTH2_ACCESS_TOKEN_SCOPE";
            String partitionedAccessTokenScopeTable = OAuth2Util.getPartitionedTableByUserStore(accessTokenScopeTable,
                    userStoreDomain);

            if (log.isDebugEnabled()) {
                log.debug("PartitionedAccessTokenTable: " + partitionedAccessTokenTable +
                        " & PartitionedAccessTokenScopeTable: " + partitionedAccessTokenScopeTable +
                        " for user store domain: " + userStoreDomain);
            }

            String wordBoundaryRegex = "\\b";
            partitionedSql = sql.replaceAll(wordBoundaryRegex + OAuthConstants.ACCESS_TOKEN_STORE_TABLE
                    + wordBoundaryRegex, partitionedAccessTokenTable);
            partitionedSql = partitionedSql.replaceAll(wordBoundaryRegex + accessTokenScopeTable + wordBoundaryRegex,
                    partitionedAccessTokenScopeTable);

            if (log.isDebugEnabled()) {
                log.debug("Original SQL: " + sql);
                log.debug("Partitioned SQL: " + partitionedSql);
            }
        }

        return partitionedSql;
    }

    /**
     * Returns the updated sql using username.
     * <p>
     * If the username contains the domain separator, updated sql derived using
     * {@code getTokenPartitionedSqlByUserStore()} method. Returns the original sql otherwise.
     *
     * @param sql
     * @param username
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getTokenPartitionedSqlByUserId(String sql, String username) throws IdentityOAuth2Exception {

        String partitionedSql = sql;

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Calculating partitioned sql for username: " + username);
            }

            String userStore = null;
            if (username != null) {
                String[] strArr = username.split(UserCoreConstants.DOMAIN_SEPARATOR);
                if (strArr != null && strArr.length > 1) {
                    userStore = strArr[0];
                }
            }

            partitionedSql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStore);
        }

        return partitionedSql;
    }

    /**
     * Returns the updated sql using token.
     * <p>
     * If the token contains the username appended, updated sql derived using
     * {@code getTokenPartitionedSqlByUserId()} method. Returns the original sql otherwise.
     *
     * @param sql
     * @param token
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getTokenPartitionedSqlByToken(String sql, String token) throws IdentityOAuth2Exception {

        String partitionedSql = sql;

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Calculating partitioned sql for token: " + token);
                } else {
                    // Avoid logging token since its a sensitive information.
                    log.debug("Calculating partitioned sql for token");
                }
            }

            String userId = OAuth2Util.getUserIdFromAccessToken(token); //i.e: 'foo.com/admin' or 'admin'
            partitionedSql = OAuth2Util.getTokenPartitionedSqlByUserId(sql, userId);
        }

        return partitionedSql;
    }

    public static String getUserStoreDomainFromUserId(String userId)
            throws IdentityOAuth2Exception {

        String userStoreDomain = null;

        if (userId != null) {
            String[] strArr = userId.split(UserCoreConstants.DOMAIN_SEPARATOR);
            if (strArr != null && strArr.length > 1) {
                userStoreDomain = getMappedUserStoreDomain(strArr[0]);
            }
        }
        return userStoreDomain;
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

    @Deprecated
    public static String getAccessTokenStoreTableFromUserId(String userId)
            throws IdentityOAuth2Exception {

        String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
        String userStore;
        if (userId != null) {
            String[] strArr = userId.split(UserCoreConstants.DOMAIN_SEPARATOR);
            if (strArr != null && strArr.length > 1) {
                userStore = strArr[0];
                accessTokenStoreTable = OAuth2Util.getPartitionedTableByUserStore(OAuthConstants.ACCESS_TOKEN_STORE_TABLE,
                        userStore);
            }
        }
        return accessTokenStoreTable;
    }

    @Deprecated
    public static String getAccessTokenStoreTableFromAccessToken(String apiKey)
            throws IdentityOAuth2Exception {

        String userId = getUserIdFromAccessToken(apiKey); //i.e: 'foo.com/admin' or 'admin'
        return OAuth2Util.getAccessTokenStoreTableFromUserId(userId);
    }

    public static String getUserIdFromAccessToken(String apiKey) {

        String userId = null;
        String decodedKey = new String(Base64.decodeBase64(apiKey.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
        String[] tmpArr = decodedKey.split(":");
        if (tmpArr != null && tmpArr.length > 1) {
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

        if (accessTokenValidity > 1000 && (refreshTokenValidity > 1000 || refreshTokenValidity < 0)) {
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
        long refreshTokenValidity = getTimeToExpire(refreshTokenIssuedTime, refreshTokenValidityPeriodMillis);
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
        long validityMillis = getTimeToExpire(issuedTime, validityPeriodMillis);
        if (validityMillis > 1000) {
            return validityMillis;
        } else {
            return 0;
        }
    }

    @Deprecated
    public static long calculateValidityInMillis(long issuedTimeInMillis, long validityPeriodMillis) {

        return getTimeToExpire(issuedTimeInMillis, validityPeriodMillis);
    }

    /**
     * Util method to calculate the validity period after applying skew corrections.
     *
     * @param issuedTimeInMillis
     * @param validityPeriodMillis
     * @return skew corrected validity period in milliseconds
     */
    public static long getTimeToExpire(long issuedTimeInMillis, long validityPeriodMillis) {

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
            if (StringUtils.isBlank(oauth1RequestTokenUrl)) {
                oauth1RequestTokenUrl = IdentityUtil.getServerURL("oauth/request-token", true, true);
            }
            return oauth1RequestTokenUrl;
        }

        public static String getOAuth1AuthorizeUrl() {

            String oauth1AuthorizeUrl = OAuthServerConfiguration.getInstance().getOAuth1AuthorizeUrl();
            if (StringUtils.isBlank(oauth1AuthorizeUrl)) {
                oauth1AuthorizeUrl = IdentityUtil.getServerURL("oauth/authorize-url", true, true);
            }
            return oauth1AuthorizeUrl;
        }

        public static String getOAuth1AccessTokenUrl() {

            String oauth1AccessTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1AccessTokenUrl();
            if (StringUtils.isBlank(oauth1AccessTokenUrl)) {
                oauth1AccessTokenUrl = IdentityUtil.getServerURL("oauth/access-token", true, true);
            }
            return oauth1AccessTokenUrl;
        }

        public static String getOAuth2AuthzEPUrl() {

            String oauth2AuthzEPUrl = OAuthServerConfiguration.getInstance().getOAuth2AuthzEPUrl();
            if (StringUtils.isBlank(oauth2AuthzEPUrl)) {
                oauth2AuthzEPUrl = IdentityUtil.getServerURL("oauth2/authorize", true, false);
            }
            return oauth2AuthzEPUrl;
        }

        public static String getOAuth2TokenEPUrl() {

            String oauth2TokenEPUrl = OAuthServerConfiguration.getInstance().getOAuth2TokenEPUrl();
            if (StringUtils.isBlank(oauth2TokenEPUrl)) {
                oauth2TokenEPUrl = IdentityUtil.getServerURL("oauth2/token", true, false);
            }
            return oauth2TokenEPUrl;
        }

        public static String getOAuth2DCREPUrl(String tenantDomain) throws URISyntaxException {

            String oauth2TokenEPUrl = OAuthServerConfiguration.getInstance().getOAuth2DCREPUrl();
            if (StringUtils.isBlank(oauth2TokenEPUrl)) {
                oauth2TokenEPUrl = IdentityUtil.getServerURL("/api/identity/oauth2/dcr/v1.0/register", true, false);
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
            if (StringUtils.isBlank(oauth2UserInfoEPUrl)) {
                oauth2UserInfoEPUrl = IdentityUtil.getServerURL("oauth2/userinfo", true, false);
            }
            return oauth2UserInfoEPUrl;
        }

        public static String getOIDCConsentPageUrl() {

            String OIDCConsentPageUrl = OAuthServerConfiguration.getInstance().getOIDCConsentPageUrl();
            if (StringUtils.isBlank(OIDCConsentPageUrl)) {
                OIDCConsentPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_consent.do", false,
                        false);
            }
            return OIDCConsentPageUrl;
        }

        public static String getOAuth2ConsentPageUrl() {

            String oAuth2ConsentPageUrl = OAuthServerConfiguration.getInstance().getOauth2ConsentPageUrl();
            if (StringUtils.isBlank(oAuth2ConsentPageUrl)) {
                oAuth2ConsentPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_authz.do", false,
                        false);
            }
            return oAuth2ConsentPageUrl;
        }

        public static String getOAuth2ErrorPageUrl() {

            String oAuth2ErrorPageUrl = OAuthServerConfiguration.getInstance().getOauth2ErrorPageUrl();
            if (StringUtils.isBlank(oAuth2ErrorPageUrl)) {
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

        for (String openidscope : scope) {
            if (openidscope.equals(OAuthConstants.Scope.OPENID)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifies if the PKCE code verifier is upto specification as per RFC 7636
     *
     * @param codeVerifier PKCE Code Verifier sent with the token request
     * @return
     */
    public static boolean validatePKCECodeVerifier(String codeVerifier) {

        Matcher pkceCodeVerifierMatcher = pkceCodeVerifierPattern.matcher(codeVerifier);
        if (!pkceCodeVerifierMatcher.matches() || (codeVerifier.length() < 43 || codeVerifier.length() > 128)) {
            return false;
        }
        return true;
    }

    /**
     * Verifies if the codeChallenge is upto specification as per RFC 7636
     *
     * @param codeChallenge
     * @param codeChallengeMethod
     * @return
     */
    public static boolean validatePKCECodeChallenge(String codeChallenge, String codeChallengeMethod) {

        if (codeChallengeMethod == null || OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(codeChallengeMethod)) {
            return validatePKCECodeVerifier(codeChallenge);
        } else if (OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(codeChallengeMethod)) {
            // SHA256 code challenge is 256 bits that is 256 / 6 ~= 43
            // See https://tools.ietf.org/html/rfc7636#section-3
            if (codeChallenge != null && codeChallenge.trim().length() == 43) {
                return true;
            }
        }
        //provided code challenge method is wrong
        return false;
    }

    @Deprecated
    public static boolean doPKCEValidation(String referenceCodeChallenge, String codeVerifier, String challenge_method,
                                           OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {

        return validatePKCE(referenceCodeChallenge, codeVerifier, challenge_method, oAuthAppDO);
    }

    public static boolean validatePKCE(String referenceCodeChallenge, String verificationCode, String challenge_method,
                                       OAuthAppDO oAuthApp) throws IdentityOAuth2Exception {

        if (oAuthApp != null && oAuthApp.isPkceMandatory() || referenceCodeChallenge != null) {

            //As per RFC 7636 Fallback to 'plain' if no code_challenge_method parameter is sent
            if (challenge_method == null || challenge_method.trim().length() == 0) {
                challenge_method = "plain";
            }

            //if app with no PKCE code verifier arrives
            if ((verificationCode == null || verificationCode.trim().length() == 0)) {
                //if pkce is mandatory, throw error
                if (oAuthApp.isPkceMandatory()) {
                    throw new IdentityOAuth2Exception("No PKCE code verifier found.PKCE is mandatory for this " +
                            "oAuth 2.0 application.");
                } else {
                    //PKCE is optional, see if the authz code was requested with a PKCE challenge
                    if (referenceCodeChallenge == null || referenceCodeChallenge.trim().length() == 0) {
                        //since no PKCE challenge was provided
                        return true;
                    } else {
                        throw new IdentityOAuth2Exception("Empty PKCE code_verifier sent. This authorization code " +
                                "requires a PKCE verification to obtain an access token.");
                    }
                }
            }
            //verify that the code verifier is upto spec as per RFC 7636
            if (!validatePKCECodeVerifier(verificationCode)) {
                throw new IdentityOAuth2Exception("Code verifier used is not up to RFC 7636 specifications.");
            }
            if (OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(challenge_method)) {
                //if the current application explicitly doesn't support plain, throw exception
                if (!oAuthApp.isPkceSupportPlain()) {
                    throw new IdentityOAuth2Exception("This application does not allow 'plain' transformation algorithm.");
                }
                if (!referenceCodeChallenge.equals(verificationCode)) {
                    return false;
                }
            } else if (OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(challenge_method)) {

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

                    byte[] hash = messageDigest.digest(verificationCode.getBytes(StandardCharsets.US_ASCII));
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

    @Deprecated
    public static boolean isPKCESupportEnabled() {

        return OAuth2ServiceComponentHolder.isPkceEnabled();
    }

    public static boolean isImplicitResponseType(String responseType) {

        if (StringUtils.isNotBlank(responseType) && (responseType.contains(ResponseType.TOKEN.toString()) ||
                responseType.contains(OAuthConstants.ID_TOKEN))) {
            return true;
        }
        return false;
    }

    /**
     * To populate the database in the very first server startup.
     *
     * @param tenantId tenant id
     */
    public static void initiateOIDCScopes(int tenantId) {

        List<ScopeDTO> scopeClaimsList = loadScopeConfigFile();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().addScopes(tenantId,
                    scopeClaimsList);
        } catch (IdentityOAuth2Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public static List<String> getOIDCScopes(String tenantDomain) {

        List<String> scopes = new ArrayList<>();
        try {
            int tenantId = OAuthComponentServiceHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            // Get the scopes from the cache or the db
            List<ScopeDTO> scopesDTOList = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    getScopes(tenantId);

            if (CollectionUtils.isNotEmpty(scopesDTOList)) {
                for (ScopeDTO scope : scopesDTOList) {
                    scopes.add(scope.getName());
                }
            }

        } catch (UserStoreException | IdentityOAuth2Exception e) {
            log.error("Error while retrieving OIDC scopes.", e);
        }
        return scopes;
    }

    public static AccessTokenDO getAccessTokenDOfromTokenIdentifier(String accessTokenIdentifier) throws
            IdentityOAuth2Exception {

        return getAccessTokenDOFromTokenIdentifier(accessTokenIdentifier, false);
    }

    public static AccessTokenDO getAccessTokenDOFromTokenIdentifier(String accessTokenIdentifier,
                                                                    boolean includeExpired)
            throws IdentityOAuth2Exception {

        boolean cacheHit = false;
        AccessTokenDO accessTokenDO = null;

        // check the cache, if caching is enabled.
        OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
        CacheEntry result = OAuthCache.getInstance().getValueFromCache(cacheKey);
        // cache hit, do the type check.
        if (result != null && result instanceof AccessTokenDO) {
            accessTokenDO = (AccessTokenDO) result;
            cacheHit = true;
        }

        // cache miss, load the access token info from the database.
        if (accessTokenDO == null) {
            accessTokenDO = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getAccessToken(accessTokenIdentifier, includeExpired);
        }

        if (accessTokenDO == null) {
            // this means the token is not active so we can't proceed further
            throw new IllegalArgumentException("Invalid Access Token. Access token is not ACTIVE.");
        }

        // add the token back to the cache in the case of a cache miss
        if (!cacheHit) {
            cacheKey = new OAuthCacheKey(accessTokenIdentifier);
            OAuthCache.getInstance().addToCache(cacheKey, accessTokenDO);
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
     * @deprecated due to UI implementation.
     */
    @Deprecated
    public static void initTokenExpiryTimesOfSps(int tenantId) {

        try {
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
     * @deprecated due to UI implementation
     */
    @Deprecated
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
                    if (spTimeObject.has(USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS) &&
                            !spTimeObject.isNull(USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS)) {
                        try {
                            spTokenTimeObject.setUserAccessTokenExpiryTime(Long.parseLong(spTimeObject
                                    .get(USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString()));
                            if (log.isDebugEnabled()) {
                                log.debug("The user access token expiry time :" + spTimeObject
                                        .get(USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString() +
                                        "  for application id : " + consumerKey);
                            }
                        } catch (NumberFormatException e) {
                            String errorMsg = String.format("Invalid value provided as user access token expiry time " +
                                            "for consumer key %s, tenant id : %d. Given value: %s, Expected a long value",
                                    consumerKey, tenantId, spTimeObject.get(USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString());
                            log.error(errorMsg, e);
                        }
                    } else {
                        spTokenTimeObject.setUserAccessTokenExpiryTime(OAuthServerConfiguration.getInstance()
                                .getUserAccessTokenValidityPeriodInSeconds() * 1000);
                    }

                    if (spTimeObject.has(APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS) &&
                            !spTimeObject.isNull(APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS)) {
                        try {
                            spTokenTimeObject.setApplicationAccessTokenExpiryTime(Long.parseLong(spTimeObject
                                    .get(APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString()));
                            if (log.isDebugEnabled()) {
                                log.debug("The application access token expiry time :" + spTimeObject
                                        .get(APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString() +
                                        "  for application id : " + consumerKey);
                            }
                        } catch (NumberFormatException e) {
                            String errorMsg = String.format("Invalid value provided as application access token " +
                                            "expiry time for consumer key %s, tenant id : %d. Given value: %s, Expected a long value ",
                                    consumerKey, tenantId, spTimeObject.get(APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString());
                            log.error(errorMsg, e);
                        }
                    } else {
                        spTokenTimeObject.setApplicationAccessTokenExpiryTime(OAuthServerConfiguration.getInstance()
                                .getApplicationAccessTokenValidityPeriodInSeconds() * 1000);
                    }

                    if (spTimeObject.has(REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS) &&
                            !spTimeObject.isNull(REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS)) {
                        try {
                            spTokenTimeObject.setRefreshTokenExpiryTime(Long.parseLong(spTimeObject
                                    .get(REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS).toString()));
                            if (log.isDebugEnabled()) {
                                log.debug("The refresh token expiry time :" + spTimeObject
                                        .get(REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS).toString() +
                                        " for application id : " + consumerKey);
                            }

                        } catch (NumberFormatException e) {
                            String errorMsg = String.format("Invalid value provided as refresh token expiry time for " +
                                            "consumer key %s, tenant id : %d. Given value: %s, Expected a long value", consumerKey,
                                    tenantId, spTimeObject.get(REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS).toString());
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

    /**
     * Retrieve audience configured for the particular service provider.
     *
     * @param clientId
     * @param oAuthAppDO
     * @return
     */
    public static List<String> getOIDCAudience(String clientId, OAuthAppDO oAuthAppDO) {

        List<String> oidcAudiences = getDefinedCustomOIDCAudiences(oAuthAppDO);
        // Need to add client_id as an audience value according to the spec.
        if (!oidcAudiences.contains(clientId)) {
            oidcAudiences.add(0, clientId);
        } else {
            Collections.swap(oidcAudiences, oidcAudiences.indexOf(clientId), 0);
        }
        return oidcAudiences;
    }

    private static List<String> getDefinedCustomOIDCAudiences(OAuthAppDO oAuthAppDO) {

        List<String> audiences = new ArrayList<>();

        // Priority should be given to service provider specific audiences over globally configured ones.
        if (OAuth2ServiceComponentHolder.isAudienceEnabled()) {
            audiences = getAudienceListFromOAuthAppDO(oAuthAppDO);
            if (CollectionUtils.isNotEmpty(audiences)) {
                if (log.isDebugEnabled()) {
                    log.debug("OIDC Audiences " + audiences + " had been retrieved for the client_id: " +
                            oAuthAppDO.getOauthConsumerKey());
                }
                return audiences;
            }
        }

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);
        if (oauthElem == null) {
            log.warn("Error in OAuth Configuration: <OAuth> configuration element is not available in identity.xml.");
            return audiences;
        }

        OMElement oidcConfig = oauthElem.getFirstChildWithName(new QName(IdentityCoreConstants.
                IDENTITY_DEFAULT_NAMESPACE, OPENID_CONNECT));
        if (oidcConfig == null) {
            log.warn("Error in OAuth Configuration: <OpenIDConnect> element is not available in identity.xml.");
            return audiences;
        }

        OMElement audienceConfig = oidcConfig.getFirstChildWithName(new QName(IdentityCoreConstants.
                IDENTITY_DEFAULT_NAMESPACE, OPENID_CONNECT_AUDIENCES));
        if (audienceConfig == null) {
            return audiences;
        }

        Iterator iterator = audienceConfig.getChildrenWithName(new QName(IdentityCoreConstants.
                IDENTITY_DEFAULT_NAMESPACE, OPENID_CONNECT_AUDIENCE));
        while (iterator.hasNext()) {
            OMElement supportedAudience = (OMElement) iterator.next();
            String supportedAudienceName;
            if (supportedAudience != null) {
                supportedAudienceName = IdentityUtil.fillURLPlaceholders(supportedAudience.getText());
                if (StringUtils.isNotBlank(supportedAudienceName)) {
                    audiences.add(supportedAudienceName);
                }
            }
        }
        return audiences;
    }

    private static List<String> getAudienceListFromOAuthAppDO(OAuthAppDO oAuthAppDO) {

        if (oAuthAppDO.getAudiences() == null) {
            return new ArrayList<>();
        } else {
            return new ArrayList<>(Arrays.asList(oAuthAppDO.getAudiences()));
        }
    }

    /**
     * Returns oauth token issuer registered in the service provider app
     *
     * @param clientId client id of the oauth app
     * @return oauth token issuer
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static OauthTokenIssuer getOAuthTokenIssuerForOAuthApp(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO appDO = null;
        try {
            appDO = getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + clientId, e);
        }
        return getOAuthTokenIssuerForOAuthApp(appDO);
    }

    /**
     * Returns oauth token issuer registered in the service provider app.
     *
     * @param appDO oauth app data object
     * @return oauth token issuer
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static OauthTokenIssuer getOAuthTokenIssuerForOAuthApp(OAuthAppDO appDO) throws IdentityOAuth2Exception {

        OauthTokenIssuer oauthIdentityTokenGenerator;
        if (appDO.getTokenType() != null) {
            oauthIdentityTokenGenerator = OAuthServerConfiguration.getInstance()
                    .addAndReturnTokenIssuerInstance(appDO.getTokenType());
            if (oauthIdentityTokenGenerator == null) {
                //get server level configured token issuer
                oauthIdentityTokenGenerator = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();
            }
        } else {
            oauthIdentityTokenGenerator = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();
            if (log.isDebugEnabled()) {
                log.debug("Token type is not set for service provider app with client Id: " +
                        appDO.getOauthConsumerKey() + ". Hence the default Identity OAuth token issuer will be used. "
                        + "No custom token generator is set.");
            }
        }
        return oauthIdentityTokenGenerator;
    }

    private static List<ScopeDTO> loadScopeConfigFile() {

        List<ScopeDTO> listOIDCScopesClaims = new ArrayList<>();
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
                ScopeDTO scope = new ScopeDTO();
                OMElement omElement = (OMElement) iterator.next();
                String configType = omElement.getAttributeValue(new QName(
                        "id"));
                scope.setName(configType);
                scope.setClaim(loadClaimConfig(omElement));
                listOIDCScopesClaims.add(scope);
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
        return listOIDCScopesClaims;
    }

    private static String[] loadClaimConfig(OMElement configElement) {

        StringBuilder claimConfig = new StringBuilder();
        Iterator it = configElement.getChildElements();
        while (it.hasNext()) {
            OMElement element = (OMElement) it.next();
            if ("Claim".equals(element.getLocalName())) {
                String commaSeparatedClaimNames = element.getText();
                if (StringUtils.isNotBlank(commaSeparatedClaimNames)) {
                    claimConfig.append(commaSeparatedClaimNames.trim());
                }
            }
        }
        return (claimConfig.toString().split(","));
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
            if (oAuthAppDO != null) {
                AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
            }
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
     * This is used to get the tenant domain of an application by clientId.
     *
     * @param clientId Consumer key of Application
     * @return Tenant Domain
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static String getTenantDomainOfOauthApp(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = getAppInformationByClientId(clientId);
        return getTenantDomainOfOauthApp(oAuthAppDO);
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     *
     * @param signatureAlgorithm name of the signature algorithm
     * @return mapped JWSAlgorithm name
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    public static String mapSignatureAlgorithm(String signatureAlgorithm) throws IdentityOAuth2Exception {

        return mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm).getName();
    }

    /**
     * This method maps the encryption algorithm name defined in identity.xml to a respective
     * nimbus encryption algorithm.
     *
     * @param encryptionAlgorithm name of the encryption algorithm
     * @return mapped JWEAlgorithm
     * @throws IdentityOAuth2Exception
     */
    public static JWEAlgorithm mapEncryptionAlgorithmForJWEAlgorithm(String encryptionAlgorithm)
            throws IdentityOAuth2Exception {

        // Parse method in JWEAlgorithm is used to get a JWEAlgorithm object from the algorithm name.
        JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(encryptionAlgorithm);

        // Parse method returns a new JWEAlgorithm with requirement set to null if unknown algorithm name is passed.
        if (jweAlgorithm.getRequirement() != null) {
            return jweAlgorithm;
        } else {
            throw new IdentityOAuth2Exception("Unsupported Encryption Algorithm: " + encryptionAlgorithm);
        }
    }

    /**
     * This method maps the encryption method name defined in identity.xml to a respective nimbus
     * encryption method.
     *
     * @param encryptionMethod name of the encryption method
     * @return mapped EncryptionMethod
     * @throws IdentityOAuth2Exception
     */
    public static EncryptionMethod mapEncryptionMethodForJWEAlgorithm(String encryptionMethod)
            throws IdentityOAuth2Exception {

        // Parse method in EncryptionMethod is used to get a EncryptionMethod object from the method name.
        EncryptionMethod method = EncryptionMethod.parse(encryptionMethod);

        // Parse method returns a new EncryptionMethod with requirement set to null if unknown method name is passed.
        if (method.getRequirement() != null) {
            return method;
        } else {
            log.error("Unsupported Encryption Method in identity.xml");
            throw new IdentityOAuth2Exception("Unsupported Encryption Method: " + encryptionMethod);
        }
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     *
     * @param signatureAlgorithm name of the signature algorithm
     * @return mapped JWSAlgorithm
     * @throws IdentityOAuth2Exception
     */
    public static JWSAlgorithm mapSignatureAlgorithmForJWSAlgorithm(String signatureAlgorithm) throws IdentityOAuth2Exception {

        if (NONE.equalsIgnoreCase(signatureAlgorithm)) {
            return new JWSAlgorithm(JWSAlgorithm.NONE.getName());
        } else if (SHA256_WITH_RSA.equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS256;
        } else if (SHA384_WITH_RSA.equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS384;
        } else if (SHA512_WITH_RSA.equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS512;
        } else if (SHA256_WITH_HMAC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS256;
        } else if (SHA384_WITH_HMAC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS384;
        } else if (SHA512_WITH_HMAC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS512;
        } else if (SHA256_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES256;
        } else if (SHA384_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES384;
        } else if (SHA512_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES512;
        } else if (SHA256_WITH_PS.equals(signatureAlgorithm)) {
            return JWSAlgorithm.PS256;
        } else {
            log.error("Unsupported Signature Algorithm in identity.xml");
            throw new IdentityOAuth2Exception("Unsupported Signature Algorithm in identity.xml");
        }
    }

    /**
     * Check if audiences are enabled by reading configuration file at server startup.
     *
     * @return
     */
    public static boolean checkAudienceEnabled() {

        boolean isAudienceEnabled = false;
        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

        if (oauthElem == null) {
            log.warn("Error in OAuth Configuration. OAuth element is not available.");
            return isAudienceEnabled;
        }
        OMElement configOpenIDConnect = oauthElem.getFirstChildWithName(new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE,
                        OPENID_CONNECT));

        if (configOpenIDConnect == null) {
            log.warn("Error in OAuth Configuration. OpenID element is not available.");
            return isAudienceEnabled;
        }
        OMElement configAudience = configOpenIDConnect.getFirstChildWithName(new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE,
                        ENABLE_OPENID_CONNECT_AUDIENCES));

        if (configAudience != null) {
            String configAudienceValue = configAudience.getText();
            if (StringUtils.isNotBlank(configAudienceValue)) {
                isAudienceEnabled = Boolean.parseBoolean(configAudienceValue);
            }
        }
        return isAudienceEnabled;
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

    /**
     * Validate Id token signature
     *
     * @param idToken Id token
     * @return validation state
     */
    public static boolean validateIdToken(String idToken) {

        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String tenantDomain;
        try {
            String clientId = SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
            if (isJWTSignedWithSPKey) {
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
                tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            } else {
                //It is not sending tenant domain with the subject in id_token by default, So to work this as
                //expected, need to enable the option "Use tenant domain in local subject identifier" in SP config
                tenantDomain = MultitenantUtils.getTenantDomain(SignedJWT.parse(idToken).getJWTClaimsSet().getSubject());
            }
            if (StringUtils.isEmpty(tenantDomain)) {
                return false;
            }
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RSAPublicKey publicKey;
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(jksName).getCertificate(tenantDomain)
                        .getPublicKey();
            } else {
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException | ParseException e) {
            log.error("Error occurred while validating id token signature.");
            return false;
        } catch (Exception e) {
            log.error("Error occurred while validating id token signature.");
            return false;
        }
    }

    /**
     * This method maps signature algorithm define in identity.xml to digest algorithms to generate the at_hash
     *
     * @param signatureAlgorithm
     * @return the mapped digest algorithm
     * @throws IdentityOAuth2Exception
     */
    public static String mapDigestAlgorithm(Algorithm signatureAlgorithm) throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.HS256.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES256.equals(signatureAlgorithm) || JWSAlgorithm.PS256.equals(signatureAlgorithm)) {
            return SHA256;
        } else if (JWSAlgorithm.RS384.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES384.equals(signatureAlgorithm)) {
            return SHA384;
        } else if (JWSAlgorithm.RS512.equals(signatureAlgorithm) || JWSAlgorithm.HS512.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            return SHA512;
        } else {
            throw new RuntimeException("Provided signature algorithm: " + signatureAlgorithm +
                    " is not supported");
        }
    }

    /**
     * This is the generic Encryption function which calls algorithm specific encryption function
     * depending on the algorithm name.
     *
     * @param jwtClaimsSet        contains JWT body
     * @param encryptionAlgorithm JWT encryption algorithm
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @return encrypted JWT token
     * @throws IdentityOAuth2Exception
     */
    public static JWT encryptJWT(JWTClaimsSet jwtClaimsSet, JWEAlgorithm encryptionAlgorithm,
                                 EncryptionMethod encryptionMethod, String spTenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        if (isRSAAlgorithm(encryptionAlgorithm)) {
            return encryptWithRSA(jwtClaimsSet, encryptionAlgorithm, encryptionMethod, spTenantDomain, clientId);
        } else {
            throw new RuntimeException("Provided encryption algorithm: " + encryptionAlgorithm +
                    " is not supported");
        }
    }

    /**
     * Encrypt JWT id token using RSA algorithm.
     *
     * @param jwtClaimsSet        contains JWT body
     * @param encryptionAlgorithm JWT signing algorithm
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @return encrypted JWT token
     * @throws IdentityOAuth2Exception
     */
    private static JWT encryptWithRSA(JWTClaimsSet jwtClaimsSet, JWEAlgorithm encryptionAlgorithm,
                                      EncryptionMethod encryptionMethod, String spTenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isBlank(spTenantDomain)) {
                spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                if (log.isDebugEnabled()) {
                    log.debug("Assigned super tenant domain as signing domain when encrypting id token for " +
                            "client_id: " + clientId);
                }
            }

            Certificate publicCert = getX509CertOfOAuthApp(clientId, spTenantDomain);
            Key publicKey = publicCert.getPublicKey();

            JWEHeader.Builder headerBuilder = new JWEHeader.Builder(encryptionAlgorithm, encryptionMethod);
            String thumbPrint = getThumbPrint(publicCert);
            headerBuilder.keyID(thumbPrint);
            headerBuilder.x509CertThumbprint(new Base64URL(thumbPrint));
            JWEHeader header = headerBuilder.build();
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);

            if (log.isDebugEnabled()) {
                log.debug("Encrypting JWT using the algorithm: " + encryptionAlgorithm + ", method: " +
                        encryptionMethod + ", tenant: " + spTenantDomain + " & header: " + header.toString());
            }

            JWEEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
            encryptedJWT.encrypt(encrypter);

            return encryptedJWT;
        } catch (JOSEException | NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IdentityOAuth2Exception("Error occurred while encrypting JWT for the client_id: " + clientId
                    + " with the tenant domain: " + spTenantDomain, e);
        }
    }

    /**
     * Generic Signing function
     *
     * @param jwtClaimsSet       contains JWT body
     * @param signatureAlgorithm JWT signing algorithm
     * @param tenantDomain       tenant domain
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    public static JWT signJWT(JWTClaimsSet jwtClaimsSet, JWSAlgorithm signatureAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm) || JWSAlgorithm.PS256.equals(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, signatureAlgorithm, tenantDomain);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            // return signWithHMAC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            throw new RuntimeException("Provided signature algorithm: " + signatureAlgorithm +
                    " is not supported");
        } else {
            // return signWithEC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            throw new RuntimeException("Provided signature algorithm: " + signatureAlgorithm +
                    " is not supported");
        }
    }

    /**
     * sign JWT token from RSA algorithm
     *
     * @param jwtClaimsSet       contains JWT body
     * @param signatureAlgorithm JWT signing algorithm
     * @param tenantDomain       tenant domain
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    //TODO: Can make this private after removing deprecated "signJWTWithRSA" methods in DefaultIDTokenBuilder
    public static JWT signJWTWithRSA(JWTClaimsSet jwtClaimsSet, JWSAlgorithm signatureAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                if (log.isDebugEnabled()) {
                    log.debug("Assign super tenant domain as signing domain.");
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Signing JWT using the algorithm: " + signatureAlgorithm + " & key of the tenant: " +
                        tenantDomain);
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder((JWSAlgorithm) signatureAlgorithm);
            headerBuilder.keyID(getThumbPrint(tenantDomain, tenantId));
            headerBuilder.x509CertThumbprint(new Base64URL(getThumbPrint(tenantDomain, tenantId)));
            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    public static Key getPrivateKey(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        Key privateKey;
        if (!(privateKeys.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain,
                        e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                // obtain private key
                privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

            } else {
                try {
                    privateKey = tenantKSM.getDefaultPrivateKey();
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error while obtaining private key for super tenant", e);
                }
            }
            //privateKey will not be null always
            privateKeys.put(tenantId, privateKey);
        } else {
            //privateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
            // does not allow to store null values
            privateKey = privateKeys.get(tenantId);
        }
        return privateKey;
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    public static String getThumbPrint(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        try {

            Certificate certificate = getCertificate(tenantDomain, tenantId);

            // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization
            return getThumbPrint(certificate);

        } catch (Exception e) {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private static String getThumbPrint(Certificate certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
        // Generate the SHA-1 thumbprint of the certificate.
        MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
        byte[] der = certificate.getEncoded();
        digestValue.update(der);
        byte[] digestInBytes = digestValue.digest();

        String publicCertThumbprint = hexify(digestInBytes);
        return new String(new Base64(0, null, true).encode(
                publicCertThumbprint.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
    }

    private static boolean isRSAAlgorithm(JWEAlgorithm algorithm) {

        return (JWEAlgorithm.RSA_OAEP.equals(algorithm) || JWEAlgorithm.RSA1_5.equals(algorithm) ||
                JWEAlgorithm.RSA_OAEP_256.equals(algorithm));
    }

    private static Certificate getCertificate(String tenantDomain, int tenantId) throws Exception {

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain, e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } else {
                publicCert = tenantKSM.getDefaultPrimaryCertificate();
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return hexadecimal representation
     */
    private static String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                +'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }

    public static List<String> getEssentialClaims(String essentialClaims, String claimType) {

        JSONObject jsonObjectClaims = new JSONObject(essentialClaims);
        List<String> essentialClaimsList = new ArrayList<>();
        if (jsonObjectClaims.toString().contains(claimType)) {
            JSONObject newJSON = jsonObjectClaims.getJSONObject(claimType);
            if (newJSON != null) {
                Iterator<?> keys = newJSON.keys();
                while (keys.hasNext()) {
                    String key = (String) keys.next();
                    if (!newJSON.isNull(key)) {
                        String value = newJSON.get(key).toString();
                        JSONObject jsonObjectValues = new JSONObject(value);
                        Iterator<?> claimKeyValues = jsonObjectValues.keys();
                        while (claimKeyValues.hasNext()) {
                            String claimKey = (String) claimKeyValues.next();
                            String claimValue = jsonObjectValues.get(claimKey).toString();
                            if (Boolean.parseBoolean(claimValue) && claimKey.equals(OAuthConstants.OAuth20Params.ESSENTIAL)) {
                                essentialClaimsList.add(key);
                            }
                        }
                    }
                }
            }
        }

        return essentialClaimsList;
    }

    /**
     * Returns the domain name convert to upper case if the domain is not not empty, else return primary domain name.
     *
     * @param userStoreDomain
     * @return
     */
    public static String getSanitizedUserStoreDomain(String userStoreDomain) {

        if (StringUtils.isNotBlank(userStoreDomain)) {
            userStoreDomain = userStoreDomain.toUpperCase();
        } else {
            userStoreDomain = IdentityUtil.getPrimaryDomainName();
        }
        return userStoreDomain;
    }

    /**
     * Returns the mapped user store domain representation federated users according to the MapFederatedUsersToLocal
     * configuration in the identity.xml file.
     *
     * @param authenticatedUser
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getUserStoreForFederatedUser(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception {

        if (authenticatedUser == null) {
            throw new IllegalArgumentException("Authenticated user cannot be null");
        }

        String userStoreDomain = OAuth2Util.getUserStoreDomainFromUserId(authenticatedUser.toString());
        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && authenticatedUser.
                isFederatedUser()) {
            userStoreDomain = OAuth2Util.getFederatedUserDomain(authenticatedUser.getFederatedIdPName());
        }
        return userStoreDomain;
    }

    /**
     * Returns Base64 encoded token which have username appended.
     *
     * @param authenticatedUser
     * @param token
     * @return
     */
    public static String addUsernameToToken(AuthenticatedUser authenticatedUser, String token) {

        if (authenticatedUser == null) {
            throw new IllegalArgumentException("Authenticated user cannot be null");
        }

        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be blank");
        }

        String usernameForToken = authenticatedUser.toString();
        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && authenticatedUser.isFederatedUser()) {
            usernameForToken = OAuth2Util.getFederatedUserDomain(authenticatedUser.getFederatedIdPName());
            usernameForToken = usernameForToken + UserCoreConstants.DOMAIN_SEPARATOR + authenticatedUser.
                    getAuthenticatedSubjectIdentifier();
        }

        //use ':' for token & userStoreDomain separation
        String tokenStrToEncode = token + ":" + usernameForToken;
        return Base64Utils.encode(tokenStrToEncode.getBytes(Charsets.UTF_8));
    }

    /**
     * Validates the json provided.
     *
     * @param redirectURL redirect url
     * @return true if a valid json
     */
    public static boolean isValidJson(String redirectURL) {

        try {
            new JSONObject(redirectURL);
        } catch (JSONException ex) {
            return false;
        }
        return true;
    }

    /**
     * This method returns essential:true claims list from the request parameter of OIDC authorization request
     *
     * @param claimRequestor                  claimrequestor is either id_token or  userinfo
     * @param requestedClaimsFromRequestParam claims defined in the value of the request parameter
     * @return the claim list which have attribute vale essentail :true
     */
    public static List<String> essentialClaimsFromRequestParam(String claimRequestor, Map<String, List<RequestedClaim>>
            requestedClaimsFromRequestParam) {

        List<String> essentialClaimsfromRequestParam = new ArrayList<>();
        List<RequestedClaim> claimsforClaimRequestor = requestedClaimsFromRequestParam.get(claimRequestor);
        if (CollectionUtils.isNotEmpty(claimsforClaimRequestor)) {
            for (RequestedClaim claimforClaimRequestor : claimsforClaimRequestor) {
                String claim = claimforClaimRequestor.getName();
                if (claimforClaimRequestor.isEssential()) {
                    essentialClaimsfromRequestParam.add(claim);
                }
            }
        }
        return essentialClaimsfromRequestParam;
    }

    /* Get authorized user from the {@link AccessTokenDO}. When getting authorized user we also make sure flag to
     * determine whether the user is federated or not is set.
     *
     * @param accessTokenDO accessTokenDO
     * @return user
     */
    public static AuthenticatedUser getAuthenticatedUser(AccessTokenDO accessTokenDO) {

        AuthenticatedUser authenticatedUser = null;
        if (accessTokenDO != null) {
            authenticatedUser = accessTokenDO.getAuthzUser();
        }
        if (authenticatedUser != null) {
            authenticatedUser.setFederatedUser(isFederatedUser(authenticatedUser));
        }
        return authenticatedUser;
    }

    /**
     * Determine whether the user represented by {@link AuthenticatedUser} object is a federated user.
     *
     * @param authenticatedUser
     * @return true if user is federated, false otherwise.
     */
    public static boolean isFederatedUser(AuthenticatedUser authenticatedUser) {

        String userStoreDomain = authenticatedUser.getUserStoreDomain();

        // We consider a user federated if the flag for federated user is set or the user store domain contain the
        // federated user store domain prefix.
        boolean isExplicitlyFederatedUser =
                StringUtils.startsWith(userStoreDomain, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX) ||
                        authenticatedUser.isFederatedUser();

        // Flag to make sure federated user is not mapped to local users.
        boolean isFederatedUserNotMappedToLocalUser =
                !OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal();

        return isExplicitlyFederatedUser && isFederatedUserNotMappedToLocalUser;
    }

    /**
     * Returns the service provider associated with the OAuth clientId.
     *
     * @param clientId     OAuth2/OIDC Client Identifier
     * @param tenantDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static ServiceProvider getServiceProvider(String clientId,
                                                     String tenantDomain) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            // Get the Service Provider.
            return applicationMgtService.getServiceProviderByClientId(
                    clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while obtaining the service provider for client_id: " +
                    clientId + " of tenantDomain: " + tenantDomain, e);
        }
    }

    /**
     * Returns the service provider associated with the OAuth clientId.
     *
     * @param clientId OAuth2/OIDC Client Identifier
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static ServiceProvider getServiceProvider(String clientId) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String tenantDomain = null;
        try {
            tenantDomain = getTenantDomainOfOauthApp(clientId);
            // Get the Service Provider.
            return applicationMgtService.getServiceProviderByClientId(
                    clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while obtaining the service provider for client_id: " +
                    clientId + " of tenantDomain: " + tenantDomain, e);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Could not find an existing app for clientId: " + clientId, e);
        }
    }

    /**
     * Returns the public certificate of the service provider associated with the OAuth consumer app as
     * an X509 @{@link Certificate} object.
     *
     * @param clientId     OAuth2/OIDC Client Identifier
     * @param tenantDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static Certificate getX509CertOfOAuthApp(String clientId,
                                                    String tenantDomain) throws IdentityOAuth2Exception {

        try {
            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId, tenantDomain);
            // Get the certificate content.
            String certificateContent = serviceProvider.getCertificateContent();
            if (StringUtils.isNotBlank(certificateContent)) {
                // Build the Certificate object from cert content.
                return IdentityUtil.convertPEMEncodedContentToCertificate(certificateContent);
            } else {
                throw new IdentityOAuth2Exception("Public certificate not configured for Service Provider with " +
                        "client_id: " + clientId + " of tenantDomain: " + tenantDomain);
            }
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Error while building X509 cert of oauth app with client_id: "
                    + clientId + " of tenantDomain: " + tenantDomain, e);
        }
    }

    /**
     * Return true if the token identifier is JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    public static boolean isJWT(String tokenIdentifier) {
        // JWT token contains 3 base64 encoded components separated by periods.
        return StringUtils.countMatches(tokenIdentifier, DOT_SEPARATER) == 2;
    }

    /**
     * Return true if the JWT id token is encrypted.
     *
     * @param idToken String JWT ID token.
     * @return Boolean state of encryption.
     */
    public static boolean isIDTokenEncrypted(String idToken) {
        // Encrypted ID token contains 5 base64 encoded components separated by periods.
        return StringUtils.countMatches(idToken, DOT_SEPARATER) == 4;
    }

    /**
     * @deprecated We cannot determine the token issuer this way. Have a look at the
     * {@link #findAccessToken(String, boolean)} method.
     */
    @Deprecated
    public static OauthTokenIssuer getTokenIssuer(String accessToken) throws IdentityOAuth2Exception {

        OauthTokenIssuer oauthTokenIssuer = null;
        String consumerKey = null;
        if (isJWT(accessToken) || isIDTokenEncrypted(accessToken)) {
            oauthTokenIssuer = new JWTTokenIssuer();
        } else {
            try {
                consumerKey = OAuth2Util.getClientIdForAccessToken(accessToken);
                if (consumerKey != null) {
                    oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
                }
            } catch (IllegalArgumentException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Consumer key is not found for token identifier: " + accessToken, e);
                }
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception(
                        "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
            }
        }
        return oauthTokenIssuer;
    }

    /**
     * Publish event on token generation error.
     *
     * @param exception Exception occurred.
     * @param params Additional parameters.
     */
    public static void triggerOnTokenExceptionListeners(Throwable exception, Map<String, Object> params) {

        try {
            OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                                                                                          .getOAuthEventInterceptorProxy();

            if (oAuthEventInterceptorProxy != null) {
                try {
                    oAuthEventInterceptorProxy.onTokenIssueException(exception, params);
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error while invoking OAuthEventInterceptor for onTokenIssueException", e);
                }
            }
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging purposes.
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while executing oAuthEventInterceptorProxy for onTokenIssueException.", e);
            }
        }
    }

    /**
     * Extract information related to the token introspection and publish the event on introspection error.
     *
     * @param
     */
    public static void triggerOnIntrospectionExceptionListeners(OAuth2TokenValidationRequestDTO introspectionRequest,
            OAuth2IntrospectionResponseDTO introspectionResponse) {

        Map<String, Object> params = new HashMap<>();
        params.put("error", introspectionResponse.getError());

        try {
            OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                    .getOAuthEventInterceptorProxy();

            if (oAuthEventInterceptorProxy != null) {
                try {
                    oAuthEventInterceptorProxy.onTokenValidationException(introspectionRequest, params);
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error while invoking OAuthEventInterceptor for onTokenValidationException", e);
                }
            }
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging purposes.
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while executing oAuthEventInterceptorProxy for onTokenValidationException.",
                        e);
            }
        }
    }

    /**
     * Get the supported oauth grant types
     *
     * @return list of grant types
     */
    public static List<String> getSupportedGrantTypes() {

        Map<String, AuthorizationGrantHandler> supportedGrantTypesMap = OAuthServerConfiguration.getInstance()
                .getSupportedGrantTypes();
        List<String> supportedGrantTypes = new ArrayList<>();
        if (supportedGrantTypesMap != null && !supportedGrantTypesMap.isEmpty()) {
            supportedGrantTypes = supportedGrantTypesMap.keySet().stream().collect(Collectors.toList());
        }
        return supportedGrantTypes;
    }

    /**
     * Get the supported client authentication methods
     *
     * @return list of client authentication methods
     */
    public static List<String> getSupportedClientAuthenticationMethods() {

        List<String> clientAuthenticationMethods = new ArrayList<>();
        clientAuthenticationMethods.add(CLIENT_SECRET_BASIC);
        clientAuthenticationMethods.add(CLIENT_SECRET_POST);

        return clientAuthenticationMethods;
    }

    /**
     * Get the supported request object signing algorithms
     *
     * @return list of algorithms
     */
    public static List<String> getRequestObjectSigningAlgValuesSupported() {

        List<String> requestObjectSigningAlgValues = new ArrayList<>();
        requestObjectSigningAlgValues.add(JWSAlgorithm.RS256.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.RS384.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.RS512.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.PS256.getName());
        requestObjectSigningAlgValues.add(JWSAlgorithm.NONE.getName());

        return requestObjectSigningAlgValues;
    }

    /**
     * Check whether the request object parameter is supported
     *
     * @return true if supported
     */
    public static boolean isRequestParameterSupported() {

        return Boolean.TRUE;
    }

    /**
     * Check whether the claims parameter is supported
     *
     * @return true if supported
     */
    public static boolean isClaimsParameterSupported() {

        return Boolean.TRUE;
    }

    /**
     * Returns the federated IdP resolved from the given domain.
     * For a federated user the user store domain is in the format of FEDERATED:{federated-idp-name}
     *
     * @param userStoreDomain user store domain to be resolved from
     * @return federated IdP name if user store domain is of format FEDERATED:{federated-idp-name}. Else returns null.
     */
    public static String getFederatedIdPFromDomain(String userStoreDomain) {

        if (StringUtils.startsWith(userStoreDomain, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX)) {

            String[] tokens = userStoreDomain.split(OAuthConstants.UserType.FEDERATED_USER_DOMAIN_SEPARATOR);
            if (tokens.length == 2) {
                return tokens[1];
            }
        }

        return null;
    }

    /**
     * Creates an instance on AuthenticatedUser{@link AuthenticatedUser} for the given parameters.
     * If given user store domain is of format FEDERATED:{federated-idp-name}, the authenticated user instance will
     * be flagged as a federated user.
     *
     * @param username        username of the user
     * @param userStoreDomain user store domain
     * @param tenantDomain    tenent domain
     * @return an instance of AuthenticatedUser{@link AuthenticatedUser}
     */
    public static AuthenticatedUser createAuthenticatedUser(String username, String userStoreDomain, String tenantDomain) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setTenantDomain(tenantDomain);
        if (StringUtils.startsWith(userStoreDomain, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX) &&
                !OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal()) {
            if (log.isDebugEnabled()) {
                log.debug("Federated prefix found in domain: " + userStoreDomain + " for user: " + username + " in " +
                        "tenant domain:" + tenantDomain + ". Flag user as a federated user.");
            }
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(OAuth2Util.getFederatedIdPFromDomain(userStoreDomain));
        } else {
            authenticatedUser.setUserStoreDomain(userStoreDomain);
        }

        return authenticatedUser;
    }

    public static String getIdTokenIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        IdentityProvider identityProvider = getResidentIdp(tenantDomain);
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        return IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                IDP_ENTITY_ID).getValue();
    }

    private static IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Used to build an OAuth revocation request DTO.
     *
     * @param oAuthClientAuthnContext  OAuth client authentication context.
     * @param accessToken Access token to be revoked.
     * @return Returns a OAuth revocation request DTO.
     */
    public static OAuthRevocationRequestDTO buildOAuthRevocationRequest(OAuthClientAuthnContext oAuthClientAuthnContext,
                                                                        String accessToken){

        OAuthRevocationRequestDTO revocationRequestDTO = new OAuthRevocationRequestDTO();

        revocationRequestDTO.setToken(accessToken);
        revocationRequestDTO.setOauthClientAuthnContext(oAuthClientAuthnContext);
        revocationRequestDTO.setConsumerKey(oAuthClientAuthnContext.getClientId());

        return revocationRequestDTO;
    }

    /**
     * Find access tokenDO from token identifier by chaining through all available token issuers.
     *
     * @param tokenIdentifier access token data object from the validation request.
     * @return AccessTokenDO
     * @throws IdentityOAuth2Exception
     */
    public static AccessTokenDO findAccessToken(String tokenIdentifier, boolean includeExpired)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO;

        // Get a copy of the list of token issuers .
        Map<String, OauthTokenIssuer> allOAuthTokenIssuerMap = new HashMap<>(
                OAuthServerConfiguration.getInstance().getOauthTokenIssuerMap());

        // Differentiate default token issuers and other issuers for better performance.
        Map<String, OauthTokenIssuer> defaultOAuthTokenIssuerMap = new HashMap<>();
        extractDefaultOauthTokenIssuers(allOAuthTokenIssuerMap, defaultOAuthTokenIssuerMap);

        // First try default token issuers.
        accessTokenDO = getAccessTokenDOFromMatchingTokenIssuer(tokenIdentifier, defaultOAuthTokenIssuerMap,
                includeExpired);
        if (accessTokenDO != null) {
            return accessTokenDO;
        }

        // Loop through other issuer and try to get the hash.
        return getAccessTokenDOFromMatchingTokenIssuer(tokenIdentifier, allOAuthTokenIssuerMap, includeExpired);
    }

    /**
     * Loop through provided token issuer list and tries to get the access token DO.
     *
     * @param tokenIdentifier Provided token identifier.
     * @param tokenIssuerMap  List of token issuers.
     * @return Obtained matching access token DO if possible.
     * @throws IdentityOAuth2Exception
     */
    private static AccessTokenDO getAccessTokenDOFromMatchingTokenIssuer(String tokenIdentifier,
                                                                         Map<String, OauthTokenIssuer> tokenIssuerMap,
                                                                         boolean includeExpired)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO;
        if (tokenIssuerMap != null) {
            for (Map.Entry<String, OauthTokenIssuer> oauthTokenIssuerEntry: tokenIssuerMap.entrySet()) {
                try {
                    OauthTokenIssuer oauthTokenIssuer = oauthTokenIssuerEntry.getValue();
                    String tokenAlias = oauthTokenIssuer.getAccessTokenHash(tokenIdentifier);
                    if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                        accessTokenDO =  OAuth2Util.getAccessTokenDOFromTokenIdentifier(tokenAlias, includeExpired);
                    } else {
                        accessTokenDO =  OAuth2Util.getAccessTokenDOFromTokenIdentifier(tokenIdentifier, includeExpired);
                    }
                    if (accessTokenDO != null) {
                        return accessTokenDO;
                    }
                } catch (OAuthSystemException e) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and" +
                                    " failed to parse the received token: " + tokenIdentifier);
                        } else {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and" +
                                    " failed to parse the received token.");
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Differentiate default token issuers from all available token issuers map.
     *
     * @param allOAuthTokenIssuerMap Map of all available token issuers.
     * @param
     */
    private static void extractDefaultOauthTokenIssuers( Map<String, OauthTokenIssuer> allOAuthTokenIssuerMap,
            Map<String, OauthTokenIssuer> defaultOAuthTokenIssuerMap) {

        // TODO: 4/9/19 Implement logic to read default issuer from config.
        // TODO: 4/9/19 add sorting mechanism to use JWT issuer first.
        defaultOAuthTokenIssuerMap.put(OAuthServerConfiguration.JWT_TOKEN_TYPE,
                allOAuthTokenIssuerMap.get(OAuthServerConfiguration.JWT_TOKEN_TYPE));
        allOAuthTokenIssuerMap.remove(OAuthServerConfiguration.JWT_TOKEN_TYPE);

        defaultOAuthTokenIssuerMap.put(OAuthServerConfiguration.DEFAULT_TOKEN_TYPE,
                allOAuthTokenIssuerMap.get(OAuthServerConfiguration.DEFAULT_TOKEN_TYPE));
        allOAuthTokenIssuerMap.remove(OAuthServerConfiguration.DEFAULT_TOKEN_TYPE);
    }

    /**
     * Return access token identifier from OAuth2TokenValidationResponseDTO. This method validated the token against
     * the cache and the DB.
     *
     * @param tokenResponse OAuth2TokenValidationResponseDTO object.
     * @return extracted access token identifier.
     * @throws UserInfoEndpointException
     */
    public static String getAccessTokenIdentifier(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        if (tokenResponse.getAuthorizationContextToken().getTokenString() != null) {
            AccessTokenDO accessTokenDO = null;
            try {
                accessTokenDO = OAuth2Util.findAccessToken(
                        tokenResponse.getAuthorizationContextToken().getTokenString(), false);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("Error occurred while obtaining access token.", e);
            }

            if (accessTokenDO != null) {
                return accessTokenDO.getAccessToken();
            }
        }
        return null;
    }

    /**
     * There are cases where we store an 'alias' of the token returned to the client as the token inside IS.
     * For example, in the case of JWT access tokens we store the 'jti' claim in the database instead of the
     * actual JWT. Therefore we need to cache an AccessTokenDO with the stored token identifier.
     *
     * @param newTokenBean token DO to be added to the cache.
     */
    public static void addTokenDOtoCache(AccessTokenDO newTokenBean) throws IdentityOAuth2Exception  {

        OauthTokenIssuer tokenIssuer = null;
        try {
            tokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(newTokenBean.getConsumerKey());
            String tokenAlias = tokenIssuer.getAccessTokenHash(newTokenBean.getAccessToken());
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(tokenAlias);
            AccessTokenDO tokenDO = AccessTokenDO.clone(newTokenBean);
            tokenDO.setAccessToken(tokenAlias);
            OAuthCache.getInstance().addToCache(accessTokenCacheKey, tokenDO);
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Access token DO was added to OAuthCache with cache key: "
                            + accessTokenCacheKey.getCacheKeyString());
                } else {
                    log.debug("Access token DO was added to OAuthCache");
                }
            }
        } catch (OAuthSystemException e) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                throw new IdentityOAuth2Exception("Error while getting the token alias from token issuer: " +
                        tokenIssuer.toString() + " for the token: " + newTokenBean.getAccessToken(), e);
            } else {
                throw new IdentityOAuth2Exception("Error while getting the token alias from token issuer: " +
                        tokenIssuer.toString(), e);
            }
        } catch (InvalidOAuthClientException e) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                throw new IdentityOAuth2Exception("Error while getting the token issuer for the token: " +
                        newTokenBean.getAccessToken(), e);
            } else {
                throw new IdentityOAuth2Exception("Error while getting the token issuer", e);
            }
        }
    }
}
