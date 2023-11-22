/*
 * Copyright (c) 2013-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.apache.oltu.oauth2.common.exception.OAuthRuntimeException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.consent.server.configs.mgt.exceptions.ConsentServerConfigsMgtException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
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
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.dto.TokenBindingMetaDataDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.config.SpOAuth2ExpiryTimeConfiguration;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAUTH_BUILD_ISSUER_WITH_HOSTNAME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AEndpoints.OAUTH_AUTHZ_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AEndpoints.OAUTH_REQUEST_TOKEN_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AEndpoints.OAUTH_TOKEN_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.DEVICE_AUTHZ_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_AUTHZ_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_CONSENT_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_DCR_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_DISCOVERY_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_ERROR_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_INTROSPECT_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_JWKS_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_PAR_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_REVOKE_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_TOKEN_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_USER_INFO_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OIDC_CONSENT_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OIDC_WEB_FINGER_EP_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ALLOWED_GRANT_TYPES_CONFIG;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.SignatureAlgorithms.KID_HASHING_ALGORITHM;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.SignatureAlgorithms.PREVIOUS_KID_HASHING_ALGORITHM;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.PERMISSIONS_BINDING_TYPE;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_SUCCESS_ENDPOINT_PATH;

/**
 * Utility methods for OAuth 2.0 implementation.
 */
public class OAuth2Util {

    public static final String REMOTE_ACCESS_TOKEN = "REMOTE_ACCESS_TOKEN";
    public static final String JWT_ACCESS_TOKEN = "JWT_ACCESS_TOKEN";
    public static final String ACCESS_TOKEN_DO = "AccessTokenDo";
    public static final String OAUTH2_VALIDATION_MESSAGE_CONTEXT = "OAuth2TokenValidationMessageContext";
    public static final String CONFIG_ELEM_OAUTH = "OAuth";
    public static final String OPENID_CONNECT = "OpenIDConnect";
    public static final String ENABLE_OPENID_CONNECT_AUDIENCES = "EnableAudiences";
    public static final String OPENID_CONNECT_AUDIENCE = "audience";
    public static final String OPENID_SCOPE = "openid";
    /*
     * Maintain a separate parameter "OPENID_CONNECT_AUDIENCE_IDENTITY_CONFIG" to get the audience from the identity.xml
     * when user didn't add any audience in the UI while creating service provider.
     */
    public static final String OPENID_CONNECT_AUDIENCE_IDENTITY_CONFIG = "Audience";
    private static final String OPENID_CONNECT_AUDIENCES = "Audiences";
    private static final String DOT_SEPARATER = ".";
    private static final String IDP_ENTITY_ID = "IdPEntityId";
    public static final String OIDC_ROLE_CLAIM_URI = "roles";

    public static final String DEFAULT_TOKEN_TYPE = "Default";

    /*
     * OPTIONAL. A JSON string containing a space-separated list of scopes associated with this token, in the format
     * described in Section 3.3 of OAuth 2.0
     */
    public static final String SCOPE = "scope";
    public static final String INTERNAL_LOGIN_SCOPE = "internal_login";

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

    /**
     * FIdp Role Based authentication application config.
     */
    public static final String FIDP_ROLE_BASED_AUTHZ_APP_CONFIG = "FIdPRoleBasedAuthzApplications.AppName";

    private static final String INBOUND_AUTH2_TYPE = "oauth2";
    private static final Log log = LogFactory.getLog(OAuth2Util.class);
    private static final Log diagnosticLog = LogFactory.getLog("diagnostics");
    public static final String JWT = "JWT";
    private static long timestampSkew = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
    private static ThreadLocal<Integer> clientTenantId = new ThreadLocal<>();
    private static ThreadLocal<OAuthTokenReqMessageContext> tokenRequestContext = new ThreadLocal<>();
    private static ThreadLocal<OAuthAuthzReqMessageContext> authzRequestContext = new ThreadLocal<>();
    //Precompile PKCE Regex pattern for performance improvement
    private static Pattern pkceCodeVerifierPattern = Pattern.compile("[\\w\\-\\._~]+");
    // System flag to allow the weak keys (key length less than 2048) to be used for the signing.
    private static final String ALLOW_WEAK_RSA_SIGNER_KEY = "allow_weak_rsa_signer_key";

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
    private static final String PS256 = "PS256";
    private static final String ES256 = "ES256";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";

    // Supported Client Authentication Methods
    private static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    private static final String CLIENT_SECRET_POST = "client_secret_post";
    private static final String PRIVATE_KEY_JWT = "private_key_jwt";

    public static final String ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE = "Invalid Access Token. Access token is " +
            "not ACTIVE.";
    public static final String IS_EXTENDED_TOKEN = "isExtendedToken";
    public static final String DYNAMIC_TOKEN_DATA_FUNCTION = "dynamicTokenData";
    public static final String ACCESS_TOKEN_JS_OBJECT = "access_token";
    public static final int EXTENDED_REFRESH_TOKEN_DEFAULT_TIME = -2;

    private static final String EXTERNAL_CONSENT_PAGE_CONFIGURATIONS = "external_consent_page_configurations";
    private static final String EXTERNAL_CONSENT_PAGE = "external_consent_page";
    private static final String EXTERNAL_CONSENT_PAGE_URL = "external_consent_page_url";

    private static final String BASIC_AUTHORIZATION_PREFIX = "Basic ";

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
     * Authenticate the OAuth Consumer.
     * This method is deprecated as it uses the tenant present in thread local to retrieve the consumer app.
     * Use {@link #authenticateClient(String, String, String)} instead.
     *
     * @param clientId             Consumer Key/Id
     * @param clientSecretProvided Consumer Secret issued during the time of registration
     * @return true, if the authentication is successful, false otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     */
    @Deprecated
    public static boolean authenticateClient(String clientId, String clientSecretProvided)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
        if (appDO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a valid application with the provided client_id: " + clientId);
            }
            return false;
        }

        String tenantDomain = null;
        try {
            tenantDomain = appDO.getAppOwner().getTenantDomain();
        } catch (NullPointerException e) {
            // Ignore and proceed.
        }
        if (tenantDomain != null && !isTenantActive(tenantDomain)) {
            log.error("Cannot retrieve application inside deactivated tenant: " + tenantDomain);
            throw new InvalidOAuthClientException("Cannot retrieve application inside deactivated tenant: "
                    + tenantDomain);
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

    /**
     * Authenticate the OAuth Consumer.
     *
     * @param clientId             Consumer Key/ Id.
     * @param clientSecretProvided Consumer Secret issued during the time of registration.
     * @param appTenant            Tenant domain of the application.
     * @return true, if the authentication is successful, false otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     */
    public static boolean authenticateClient(String clientId, String clientSecretProvided, String appTenant)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId, appTenant);
        if (appDO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a valid application with the provided client_id: " + clientId);
            }
            return false;
        }

        if (StringUtils.isNotEmpty(appTenant) && !isTenantActive(appTenant)) {
            throw new InvalidOAuthClientException("Cannot retrieve application inside deactivated tenant: "
                    + appTenant);
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

    private static boolean isTenantActive(String tenantDomain) throws IdentityOAuth2Exception {
        try {
            TenantManager tenantManager = OAuthComponentServiceHolder.getInstance()
                    .getRealmService().getTenantManager();
            int tenantId = tenantManager.getTenantId(tenantDomain);
            return tenantManager.isTenantActive(tenantId);
        } catch (UserStoreException e) {
            String error = "Error in obtaining tenant ID from tenant domain : " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    public static TokenPersistenceProcessor getPersistenceProcessor() {

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
     * Check whether hashing oauth keys (consumer secret, access token, refresh token and authorization code)
     * configuration is enabled or not in identity.xml file.
     *
     * @return Whether hash feature is enable or not.
     */
    public static boolean isHashEnabled() {

        boolean isHashEnabled = OAuthServerConfiguration.getInstance().isClientSecretHashEnabled();
        return isHashEnabled;
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
    @Deprecated
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
     * @deprecated To make the cache key completely unique the authenticated IDP should also be introduced.
     * Use {@link #buildCacheKeyStringForTokenWithUserId(String, String, String, String, String)} instead.
     */
    @Deprecated
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUser) {


        AuthenticatedUser authenticatedUser = OAuth2Util.getUserFromUserName(authorizedUser);
        try {
            return clientId + ":" + authenticatedUser.getUserId() + ":" + scope;
        } catch (UserIdNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("Cache could not be built for user: " + authorizedUser, e);
            }
        }
        return null;
    }

    /**
     * Build the cache key string when storing token info in cache.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUser   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @return Cache key string combining the input parameters.
     * @deprecated use {@link #buildCacheKeyStringForTokenWithUserId(String, String, String, String, String)} instead.
     */
    @Deprecated
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUser,
                                                     String authenticatedIDP) {

        AuthenticatedUser authenticatedUser = OAuth2Util.getUserFromUserName(authorizedUser);
        try {
            return clientId + ":" + authenticatedUser.getUserId() + ":" + scope + ":" + authenticatedIDP;
        } catch (UserIdNotFoundException e) {
            log.error("Cache could not be built for user: " + authorizedUser, e);
        }
        return null;
    }

    /**
     * Build the cache key string when storing token info in cache.
     * Use {@link #buildCacheKeyStringForTokenWithUserId(String, String, String, String, String)} instead.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUser   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @param tokenBindingReference Token binding reference.
     * @return Cache key string combining the input parameters.
     */
    @Deprecated
    public static String buildCacheKeyStringForToken(String clientId, String scope, String authorizedUser,
            String authenticatedIDP, String tokenBindingReference) {

        AuthenticatedUser authenticatedUser = OAuth2Util.getUserFromUserName(authorizedUser);
        try {
            return clientId + ":" + authenticatedUser.getUserId() + ":" + scope + ":" + authenticatedIDP + ":"
                    + tokenBindingReference;
        } catch (UserIdNotFoundException e) {
            log.error("Cache could not be built for user: " + authorizedUser, e);
        }
        return null;
    }

    /**
     * Build the cache key string when storing token info in cache.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUserId   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @param tokenBindingReference Token binding reference.
     * @return Cache key string combining the input parameters.
     */
    @Deprecated
    public static String buildCacheKeyStringForTokenWithUserId(String clientId, String scope, String authorizedUserId,
                                                     String authenticatedIDP, String tokenBindingReference) {

        String oauthCacheKey =
                clientId + ":" + authorizedUserId + ":" + scope + ":" + authenticatedIDP + ":" + tokenBindingReference;
        if (log.isDebugEnabled()) {
            log.debug(String.format("Building cache key: %s to access OAuthCache.", oauthCacheKey));
        }
        return oauthCacheKey;
    }

    /**
     * Build the cache key string when storing token info in cache.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUserId   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @param tokenBindingReference Token binding reference.
     * @return Cache key string combining the input parameters.
     */
    public static String buildCacheKeyStringForTokenWithUserIdOrgId(String clientId, String scope,
                                                                    String authorizedUserId, String authenticatedIDP,
                                                                    String tokenBindingReference,
                                                                    String authorizedOrganization) {

        String oauthCacheKey =
                clientId + ":" + authorizedUserId + ":" + scope + ":" + authenticatedIDP + ":" + tokenBindingReference +
                        ":" + authorizedOrganization;
        if (log.isDebugEnabled()) {
            log.debug(String.format("Building cache key: %s to access OAuthCache.", oauthCacheKey));
        }
        return oauthCacheKey;
    }
    /**
     * Build the cache key string when storing token info in cache.
     *
     * @param clientId         ClientId of the App.
     * @param scope            Scopes used.
     * @param authorizedUserId   Authorised user.
     * @param authenticatedIDP Authenticated IdP.
     * @return Cache key string combining the input parameters.
     */
    public static String buildCacheKeyStringForTokenWithUserId(String clientId, String scope, String authorizedUserId,
                                                               String authenticatedIDP) {

        return clientId + ":" + authorizedUserId + ":" + scope + ":" + authenticatedIDP;
    }

    @SuppressFBWarnings("WEAK_MESSAGE_DIGEST_MD5")
    public static String getTokenBindingReference(String tokenBindingValue) {

        if (StringUtils.isBlank(tokenBindingValue)) {
            return null;
        }
        return DigestUtils.md5Hex(tokenBindingValue);
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
        // TreeMap is used to ignore the case sensitivity of key. Because when user logged in, the case of the
        // username is ignored.
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
            partitionedSql = partitionedSql.replaceAll(
                    wordBoundaryRegex + OAuthConstants.ACCESS_TOKEN_STORE_ATTRIBUTES_TABLE + wordBoundaryRegex,
                    partitionedAccessTokenTable);
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
            if (strArr.length > 1) {
                userStore = strArr[0];
                accessTokenStoreTable =
                        OAuth2Util.getPartitionedTableByUserStore(OAuthConstants.ACCESS_TOKEN_STORE_TABLE, userStore);
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

    /**
     * Get token expire time in milliseconds.
     *
     * @param accessTokenDO Access token data object.
     * @return expire time in milliseconds.
     * @deprecated Instead use {@link #getTokenExpireTimeMillis(AccessTokenDO, boolean)}.
     */
    @Deprecated
    public static long getTokenExpireTimeMillis(AccessTokenDO accessTokenDO) {

        return getTokenExpireTimeMillis(accessTokenDO, true);
    }

    /**
     * Get token expire time in milliseconds.
     *
     * @param accessTokenDO Access token data object.
     * @param considerSkew  Consider time stamp skew when calculating expire time.
     * @return expire time in milliseconds.
     */
    public static long getTokenExpireTimeMillis(AccessTokenDO accessTokenDO, boolean considerSkew) {

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }

        long accessTokenValidity = getAccessTokenExpireMillis(accessTokenDO, considerSkew);
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

    /**
     * Get access token expire time in milliseconds.
     *
     * @param accessTokenDO Access token data object.
     * @return expire time in milliseconds.
     * @deprecated {@link #getAccessTokenExpireMillis(AccessTokenDO, boolean)}.
     */
    @Deprecated
    public static long getAccessTokenExpireMillis(AccessTokenDO accessTokenDO) {

        return getAccessTokenExpireMillis(accessTokenDO, true);
    }

    /**
     * Get access token expire time in milliseconds.
     *
     * @param accessTokenDO Access token data object.
     * @param considerSkew  Consider time stamp skew when calculating expire time.
     * @return expire time in milliseconds.
     */
    public static long getAccessTokenExpireMillis(AccessTokenDO accessTokenDO, boolean considerSkew) {

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
        long validityMillis = getTimeToExpire(issuedTime, validityPeriodMillis, considerSkew);
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
     * @deprecated use {@link #getTimeToExpire(long, long, boolean)}.
     */
    @Deprecated
    public static long getTimeToExpire(long issuedTimeInMillis, long validityPeriodMillis) {

        return getTimeToExpire(issuedTimeInMillis, validityPeriodMillis, true);
    }

    /**
     * Util method to calculate the validity period.
     *
     * @param issuedTimeInMillis    Issued time in milliseconds.
     * @param validityPeriodMillis  Validity period in milliseconds.
     * @param considerSkew          Consider timestamp skew when calculating exipry time.
     * @return skew corrected validity period in milliseconds.
     */
    public static long getTimeToExpire(long issuedTimeInMillis, long validityPeriodMillis, boolean considerSkew) {

        if (considerSkew) {
            return issuedTimeInMillis + validityPeriodMillis - (System.currentTimeMillis() - timestampSkew);
        }
        return issuedTimeInMillis + validityPeriodMillis - (System.currentTimeMillis());
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

    @SuppressFBWarnings("WEAK_MESSAGE_DIGEST_MD5")
    public static String hashScopes(String[] scope) {

        return DigestUtils.md5Hex(OAuth2Util.buildScopeString(scope));
    }

    @SuppressFBWarnings("WEAK_MESSAGE_DIGEST_MD5")
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

    /**
     * OAuth URL related utility functions.
     */
    public static class OAuthURL {

        public static String getOAuth1RequestTokenUrl() {

            String oauth1RequestTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1RequestTokenUrl();
            if (StringUtils.isBlank(oauth1RequestTokenUrl)) {
                oauth1RequestTokenUrl = IdentityUtil.getServerURL(OAUTH_REQUEST_TOKEN_EP_URL, true, true);
            }
            return oauth1RequestTokenUrl;
        }

        public static String getOAuth1AuthorizeUrl() {

            String oauth1AuthorizeUrl = OAuthServerConfiguration.getInstance().getOAuth1AuthorizeUrl();
            if (StringUtils.isBlank(oauth1AuthorizeUrl)) {
                oauth1AuthorizeUrl = IdentityUtil.getServerURL(OAUTH_AUTHZ_EP_URL, true, true);
            }
            return oauth1AuthorizeUrl;
        }

        public static String getOAuth1AccessTokenUrl() {

            String oauth1AccessTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1AccessTokenUrl();
            if (StringUtils.isBlank(oauth1AccessTokenUrl)) {
                oauth1AccessTokenUrl = IdentityUtil.getServerURL(OAUTH_TOKEN_EP_URL, true, true);
            }
            return oauth1AccessTokenUrl;
        }

        public static String getOAuth2AuthzEPUrl() {

            return buildUrl(OAUTH2_AUTHZ_EP_URL, OAuthServerConfiguration.getInstance()::getOAuth2AuthzEPUrl);
        }

        public static String getOAuth2ParEPUrl() {

            return buildUrl(OAUTH2_PAR_EP_URL, OAuthServerConfiguration.getInstance()::getOAuth2ParEPUrl);
        }

        public static String getOAuth2TokenEPUrl() {

            return buildUrl(OAUTH2_TOKEN_EP_URL, OAuthServerConfiguration.getInstance()::getOAuth2TokenEPUrl);
        }

        /**
         * This method is used to get the resolved URL for the OAuth2 Registration Endpoint.
         *
         * @param tenantDomain Tenant Domain.
         * @return String of the resolved URL for the Registration endpoint.
         * @throws URISyntaxException URI Syntax Exception.
         */
        public static String getOAuth2DCREPUrl(String tenantDomain) throws URISyntaxException {

            String oauth2TokenEPUrl =
                    buildUrl(OAUTH2_DCR_EP_URL, OAuthServerConfiguration.getInstance()::getOAuth2DCREPUrl);

            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && isNotSuperTenant(tenantDomain)) {
                //Append tenant domain to path when the tenant-qualified url mode is disabled.
                oauth2TokenEPUrl = appendTenantDomainAsPathParamInLegacyMode(oauth2TokenEPUrl, tenantDomain);
            }
            return oauth2TokenEPUrl;
        }

        /**
         * This method is used to get the resolved URL for the JWKS Page.
         *
         * @param tenantDomain Tenant Domain.
         * @return String of the resolved URL for the JWKS page.
         * @throws URISyntaxException URI Syntax Exception.
         */
        public static String getOAuth2JWKSPageUrl(String tenantDomain) throws URISyntaxException {

            String auth2JWKSPageUrl = buildUrl(OAUTH2_JWKS_EP_URL,
                    OAuthServerConfiguration.getInstance()::getOAuth2JWKSPageUrl);

            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && isNotSuperTenant(tenantDomain)) {
                //Append tenant domain to path when the tenant-qualified url mode is disabled.
                auth2JWKSPageUrl = appendTenantDomainAsPathParamInLegacyMode(auth2JWKSPageUrl, tenantDomain);
            }
            return auth2JWKSPageUrl;
        }

        public static String getOidcWebFingerEPUrl() {

            return buildUrl(OIDC_WEB_FINGER_EP_URL, OAuthServerConfiguration.getInstance()::getOidcWebFingerEPUrl);
        }

        public static String getOidcDiscoveryEPUrl(String tenantDomain) throws URISyntaxException {

            String oidcDiscoveryEPUrl = buildUrl(OAUTH2_DISCOVERY_EP_URL,
                    OAuthServerConfiguration.getInstance()::getOidcDiscoveryUrl);

            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && isNotSuperTenant(tenantDomain)) {
                //Append tenant domain to path when the tenant-qualified url mode is disabled.
                oidcDiscoveryEPUrl = appendTenantDomainAsPathParamInLegacyMode(oidcDiscoveryEPUrl, tenantDomain);
            }
            return oidcDiscoveryEPUrl;
        }

        public static String getOAuth2UserInfoEPUrl() {

            return buildUrl(OAUTH2_USER_INFO_EP_URL, OAuthServerConfiguration.getInstance()::getOauth2UserInfoEPUrl);
        }

        /**
         * Get oauth2 revocation endpoint URL.
         *
         * @return Revocation Endpoint URL.
         */
        public static String getOAuth2RevocationEPUrl() {

            return buildUrl(OAUTH2_REVOKE_EP_URL, OAuthServerConfiguration.getInstance()::getOauth2RevocationEPUrl);
        }

        /**
         * Get oauth2 introspection endpoint URL.
         *
         * @return Introspection Endpoint URL.
         */
        public static String getOAuth2IntrospectionEPUrl() {

            return buildUrl(OAUTH2_INTROSPECT_EP_URL,
                    OAuthServerConfiguration.getInstance()::getOauth2IntrospectionEPUrl);
        }

        /**
         * This method is used to get the resolved URL for the OAuth2 introspection endpoint.
         *
         * @param tenantDomain Tenant Domain.
         * @return String of the resolved URL for the introspection endpoint.
         * @throws URISyntaxException URI Syntax Exception.
         */
        public static String getOAuth2IntrospectionEPUrl(String tenantDomain) throws URISyntaxException {

            String getOAuth2IntrospectionEPUrl = buildUrl(OAUTH2_INTROSPECT_EP_URL,
                    OAuthServerConfiguration.getInstance()::getOauth2IntrospectionEPUrl);

            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && isNotSuperTenant(tenantDomain)) {
                // Append tenant domain to path when the tenant-qualified url mode is disabled.
                getOAuth2IntrospectionEPUrl =
                        appendTenantDomainAsPathParamInLegacyMode(getOAuth2IntrospectionEPUrl, tenantDomain);
            }
            return getOAuth2IntrospectionEPUrl;
        }

        public static String getOIDCConsentPageUrl() {

            return buildUrl(OIDC_CONSENT_EP_URL, OAuthServerConfiguration.getInstance()::getOIDCConsentPageUrl);
        }

        public static String getOAuth2ConsentPageUrl() {

            return buildUrl(OAUTH2_CONSENT_EP_URL, OAuthServerConfiguration.getInstance()::getOauth2ConsentPageUrl);
        }

        public static String getOAuth2ErrorPageUrl() {

            return buildUrl(OAUTH2_ERROR_EP_URL, OAuthServerConfiguration.getInstance()::getOauth2ErrorPageUrl);
        }

        private static String appendTenantDomainAsPathParamInLegacyMode(String url, String tenantDomain)
                throws URISyntaxException {

            URI uri = new URI(url);
            URI uriModified = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), ("/t/" +
                    tenantDomain + uri.getPath()), uri.getQuery(), uri.getFragment());
            return uriModified.toString();
        }

        public static String getDeviceAuthzEPUrl() {

            return buildUrl(DEVICE_AUTHZ_EP_URL, OAuthServerConfiguration.getInstance()::getDeviceAuthzEPUrl);
        }
    }

    /**
     * This method is used to generate the device flow authentication completed page URI.
     *
     * @param appName       Service provider name.
     * @param tenantDomain  Tenant domain.
     * @return Redirection URI
     */
    public static String getDeviceFlowCompletionPageURI(String appName, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            String pageURI = ServiceURLBuilder.create().addPath(DEVICE_SUCCESS_ENDPOINT_PATH)
                    .build().getAbsolutePublicURL();
            URIBuilder uriBuilder = new URIBuilder(pageURI);
            uriBuilder.addParameter(org.wso2.carbon.identity.oauth2.device.constants.Constants.APP_NAME, appName);
            if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && isNotSuperTenant(tenantDomain)) {
                // Append tenant domain to path when the tenant-qualified url mode is disabled.
                uriBuilder.addParameter(FrameworkUtils.TENANT_DOMAIN, tenantDomain);
            }
            return uriBuilder.build().toString();
        } catch (URISyntaxException | URLBuilderException e) {
            throw new IdentityOAuth2Exception("Error occurred when getting the device flow  authentication completed" +
                    " page URI.", e);
        }
    }

    /**
     * Builds a URL with a given context in both the tenant-qualified url supported mode and the legacy mode.
     * Returns the absolute URL build from the default context in the tenant-qualified url supported mode. Gives
     * precedence to the file configurations in the legacy mode and returns the absolute url build from file
     * configuration context.
     *
     * @param defaultContext              Default URL context.
     * @param getValueFromFileBasedConfig File-based Configuration.
     * @return Absolute URL.
     */
    private static String buildUrl(String defaultContext, Supplier<String> getValueFromFileBasedConfig) {

        String oauth2EndpointURLInFile = null;
        if (getValueFromFileBasedConfig != null) {
            oauth2EndpointURLInFile = getValueFromFileBasedConfig.get();
        }
        return buildServiceUrl(defaultContext, oauth2EndpointURLInFile);
    }

    /**
     * Returns the public service url given the default context and the url picked from the configuration based on
     * the 'tenant_context.enable_tenant_qualified_urls' mode set in deployment.toml.
     *
     * @param defaultContext default url context path
     * @param oauth2EndpointURLInFile  url picked from the file configuration
     * @return absolute public url of the service if 'enable_tenant_qualified_urls' is 'true', else returns the url
     * from the file config
     */
    public static String buildServiceUrl(String defaultContext, String oauth2EndpointURLInFile) {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            try {
                String organizationId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getOrganizationId();
                return ServiceURLBuilder.create().addPath(defaultContext).setOrganization(organizationId).build()
                        .getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                throw new OAuthRuntimeException("Error while building url for context: " + defaultContext);
            }
        } else if (StringUtils.isNotBlank(oauth2EndpointURLInFile)) {
            // Use the value configured in the file.
            return oauth2EndpointURLInFile;
        }
        // Use the default context.
        try {
            return ServiceURLBuilder.create().addPath(defaultContext).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new OAuthRuntimeException("Error while building url for context: " + defaultContext);
        }
    }

    private static boolean isNotSuperTenant(String tenantDomain) {

        return (StringUtils.isNotBlank(tenantDomain) &&
                !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain));
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
    public static boolean doPKCEValidation(String referenceCodeChallenge, String codeVerifier, String challengeMethod,
                                           OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {

        return validatePKCE(referenceCodeChallenge, codeVerifier, challengeMethod, oAuthAppDO);
    }

    public static boolean validatePKCE(String referenceCodeChallenge, String verificationCode, String challengeMethod,
                                       OAuthAppDO oAuthApp) throws IdentityOAuth2Exception {

        if (oAuthApp != null && oAuthApp.isPkceMandatory() || referenceCodeChallenge != null) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_PKCE);
                diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                if (oAuthApp != null) {
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, oAuthApp.getOauthConsumerKey());
                }
                diagnosticLogBuilder.inputParam("verification code", verificationCode)
                        .inputParam("code challenge", referenceCodeChallenge)
                        .inputParam("challenge method", challengeMethod);
            }

            //As per RFC 7636 Fallback to 'plain' if no code_challenge_method parameter is sent
            if (challengeMethod == null || challengeMethod.trim().length() == 0) {
                challengeMethod = "plain";
            }

            //if app with no PKCE code verifier arrives
            if ((verificationCode == null || verificationCode.trim().length() == 0)) {
                //if pkce is mandatory, throw error
                if (oAuthApp.isPkceMandatory()) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    if (diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("No PKCE code verifier found. PKCE is mandatory for the " +
                                "application.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    throw new IdentityOAuth2Exception("No PKCE code verifier found.PKCE is mandatory for this " +
                            "oAuth 2.0 application.");
                } else {
                    //PKCE is optional, see if the authz code was requested with a PKCE challenge
                    if (referenceCodeChallenge == null || referenceCodeChallenge.trim().length() == 0) {
                        //since no PKCE challenge was provided
                        if (diagnosticLogBuilder != null) {
                            // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                            diagnosticLogBuilder.resultMessage("PKCE challenge is not provided.");
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                        return true;
                    } else {
                        // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                        if (diagnosticLogBuilder != null) {
                            diagnosticLogBuilder.resultMessage("Empty PKCE code_verifier sent. This authorization " +
                                    "code requires a PKCE verification to obtain an access token.");
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                        throw new IdentityOAuth2Exception("Empty PKCE code_verifier sent. This authorization code " +
                                "requires a PKCE verification to obtain an access token.");
                    }
                }
            }
            //verify that the code verifier is upto spec as per RFC 7636
            if (!validatePKCECodeVerifier(verificationCode)) {
                // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("Code verifier used is not up to RFC 7636 specifications.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new IdentityOAuth2Exception("Code verifier used is not up to RFC 7636 specifications.");
            }
            if (OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE.equals(challengeMethod)) {
                //if the current application explicitly doesn't support plain, throw exception
                if (!oAuthApp.isPkceSupportPlain()) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    if (diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("This application does not allow 'plain' transformation " +
                                "algorithm.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    throw new IdentityOAuth2Exception(
                            "This application does not allow 'plain' transformation algorithm.");
                }
                if (!referenceCodeChallenge.equals(verificationCode)) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    if (diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("Reference code challenge does not match with " +
                                "verification code.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    return false;
                }
            } else if (OAuthConstants.OAUTH_PKCE_S256_CHALLENGE.equals(challengeMethod)) {

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

                    byte[] hash = messageDigest.digest(verificationCode.getBytes(StandardCharsets.US_ASCII));
                    //Trim the base64 string to remove trailing CR LF characters.
                    String referencePKCECodeChallenge = new String(Base64.encodeBase64URLSafe(hash),
                            StandardCharsets.UTF_8).trim();
                    if (!referencePKCECodeChallenge.equals(referenceCodeChallenge)) {
                        // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                        if (diagnosticLogBuilder != null) {
                            diagnosticLogBuilder.resultMessage("Reference code challenge does not match with " +
                                    "verification code.");
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                        return false;
                    }
                } catch (NoSuchAlgorithmException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to create SHA256 Message Digest.");
                    }
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    if (diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("System error occurred.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    return false;
                }
            } else {
                //Invalid OAuth2 token response
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                    diagnosticLogBuilder.resultMessage("Invalid PKCE Code Challenge Method.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new IdentityOAuth2Exception("Invalid OAuth2 Token Response. Invalid PKCE Code Challenge Method '"
                        + challengeMethod + "'");
            }
        }
        // PKCE validation successful.
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_PKCE)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .resultMessage("PKCE validation is successful for the token request."));
        }
        return true;
    }

    @Deprecated
    public static boolean isPKCESupportEnabled() {

        return OAuth2ServiceComponentHolder.isPkceEnabled();
    }

    /**
     * To check whether the given response type is for Implicit flow.
     *
     * @param responseType response type
     * @return true if the response type is for Implicit flow
     */
    public static boolean isImplicitResponseType(String responseType) {

        return (StringUtils.isNotBlank(responseType) && (OAuthConstants.ID_TOKEN).equals(responseType) ||
                (OAuthConstants.TOKEN).equals(responseType) || (OAuthConstants.IDTOKEN_TOKEN).equals(responseType));
    }

    /**
     * To check whether the given response type is for Hybrid flow.
     *
     * @param responseType response type
     * @return true if the response type is for Hybrid flow.
     */
    public static boolean isHybridResponseType(String responseType) {

        return (StringUtils.isNotBlank(responseType) && (OAuthConstants.CODE_TOKEN).equals(responseType) ||
                (OAuthConstants.CODE_IDTOKEN).equals(responseType) || (OAuthConstants.CODE_IDTOKEN_TOKEN).equals
                (responseType));
    }

    /**
     * To populate the database in the very first server startup.
     *
     * @param tenantId tenant id
     */
    public static void initiateOIDCScopes(int tenantId) {

        List<ScopeDTO> scopeClaimsList = OAuth2ServiceComponentHolder.getInstance().getOIDCScopesClaims();
        try {
            OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().initScopeClaimMapping(tenantId,
                    scopeClaimsList);
        } catch (IdentityOAuth2ClientException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
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

        // As the server implementation knows about the PersistenceProcessor Processed Access Token,
        // we are converting before adding to the cache.
        String processedToken = getPersistenceProcessor().getProcessedAccessTokenIdentifier(accessTokenIdentifier);

        // check the cache, if caching is enabled.
        OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
        CacheEntry result = OAuthCache.getInstance().getValueFromCache(cacheKey);
        // cache hit, do the type check.
        if (result != null && result instanceof AccessTokenDO) {
            accessTokenDO = (AccessTokenDO) result;
            cacheHit = true;
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Hit OAuthCache for accessTokenIdentifier: " + accessTokenIdentifier);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Hit OAuthCache with accessTokenIdentifier");
                }
            }
        }

        // cache miss, load the access token info from the database.
        if (accessTokenDO == null) {
            accessTokenDO = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getAccessToken(accessTokenIdentifier, includeExpired);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Retrieved active access token from OAuthCache for token Identifier: " +
                        accessTokenDO.getTokenId());
            }
        }

        if (accessTokenDO == null) {
            // this means the token is not active so we can't proceed further
            throw new IllegalArgumentException(ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);
        }

        // Add the token back to the cache in the case of a cache miss but don't add to cache when OAuth2 token
        // hashing feature enabled inorder to reduce the complexity.
        if (!cacheHit & OAuth2Util.isHashDisabled()) {
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
            log.error("Error while creating registry collection for :" + OAuthConstants.TOKEN_EXPIRE_TIME_RESOURCE_PATH,
                    e);
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
                            String errorMsg = String.format(
                                    "Invalid value provided as user access token expiry time for consumer " +
                                            "key %s, tenant id : %d. Given value: %s, Expected a long value",
                                    consumerKey, tenantId,
                                    spTimeObject.get(USER_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString());
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
                            String errorMsg = String.format(
                                    "Invalid value provided as application access token expiry time for consumer " +
                                            "key %s, tenant id : %d. Given value: %s, Expected a long value ",
                                    consumerKey, tenantId,
                                    spTimeObject.get(APPLICATION_ACCESS_TOKEN_EXP_TIME_IN_MILLISECONDS).toString());
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
                            String errorMsg = String.format(
                                    "Invalid value provided as refresh token expiry time for consumer key %s, tenant " +
                                            "id : %d. Given value: %s, Expected a long value",
                                    consumerKey, tenantId,
                                    spTimeObject.get(REFRESH_TOKEN_EXP_TIME_IN_MILLISECONDS).toString());
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
                IDENTITY_DEFAULT_NAMESPACE, OPENID_CONNECT_AUDIENCE_IDENTITY_CONFIG));
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

        OAuthAppDO appDO;
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

    /**
     * Get Oauth application information. Internally it uses the tenant present in the carbon context.
     * This method is deprecated as it uses the tenant present in thread local to retrieve the client.
     * Use {@link #getAppInformationByClientId(String, String)} instead.
     *
     * @param clientId Client id of the application.
     * @return Oauth app information.
     * @throws IdentityOAuth2Exception      Error while retrieving the application.
     * @throws InvalidOAuthClientException  If an application not found for the given client ID.
     */
    @Deprecated
    public static OAuthAppDO getAppInformationByClientId(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO != null) {
            return oAuthAppDO;
        } else {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId, IdentityTenantUtil.getLoginTenantId());
            if (oAuthAppDO != null) {
                AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
            }
            return oAuthAppDO;
        }
    }

    /**
     * Get Oauth application information.
     * 
     * @param clientId      Client id of the application.
     * @param tenantDomain  Tenant domain of the application.
     * @return Oauth app information.
     * @throws IdentityOAuth2Exception      Error while retrieving the application.
     * @throws InvalidOAuthClientException  If an application not found for the given client ID.
     */
    public static OAuthAppDO getAppInformationByClientId(String clientId, String tenantDomain)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO == null) {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId, IdentityTenantUtil.getTenantId(tenantDomain));
            if (oAuthAppDO != null) {
                AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
            }
        }
        return oAuthAppDO;
    }

    /**
     * Get Oauth application information for a given client id. This method doesn't utilize the tenant and
     * treats the client ID as unique across the server.
     *
     * @param clientId Client id of the application.
     * @return Oauth app information.
     * @throws IdentityOAuth2Exception      Error while retrieving the application.
     * @throws InvalidOAuthClientException  If an application not found for the given client ID.
     */
    public static OAuthAppDO getAppInformationByClientIdOnly(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO == null) {
            OAuthAppDO[] appList = new OAuthAppDAO().getAppsForConsumerKey(clientId);
            if (appList == null || appList.length != 1) {
                String message = OAuthConstants.OAuthError.AuthorizationResponsei18nKey.APPLICATION_NOT_FOUND;
                if (log.isDebugEnabled()) {
                    log.debug("Cannot find an unique application associated with the given client ID: " + clientId);
                }
                throw new InvalidOAuthClientException(message);
            }
            oAuthAppDO = appList[0];
            AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
        }
        return oAuthAppDO;
    }

    /**
     * Get Oauth application information given an access token DO.
     *
     * @param accessTokenDO Access token data object.
     * @return Oauth app information.
     * @throws IdentityOAuth2Exception      Error while retrieving the application.
     * @throws InvalidOAuthClientException  If an application not found for the given client ID.
     */
    public static OAuthAppDO getAppInformationByAccessTokenDO(AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        String clientId = accessTokenDO.getConsumerKey();

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO == null) {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId, accessTokenDO);
            if (oAuthAppDO != null) {
                AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
            }
        }
        return oAuthAppDO;
    }

    /**
     * Get the tenant domain of an oauth application
     *
     * @param oAuthAppDO
     * @return
     */
    public static String getTenantDomainOfOauthApp(OAuthAppDO oAuthAppDO) {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (oAuthAppDO != null && oAuthAppDO.getUser() != null) {
            tenantDomain = oAuthAppDO.getUser().getTenantDomain();
        }
        return tenantDomain;
    }

    /**
     * This is used to get the tenant domain of an application by clientId. Internally it uses the tenant present in
     * the carbon context.
     *
     * @param clientId Consumer key of Application.
     * @return Tenant Domain.
     * @throws IdentityOAuth2Exception      Error while retrieving the application.
     * @throws InvalidOAuthClientException  If an application not found for the given client ID.
     */
    public static String getTenantDomainOfOauthApp(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = getAppInformationByClientId(clientId);
        return getTenantDomainOfOauthApp(oAuthAppDO);
    }

    /**
     * Get all the OAuth applications for the client ID.
     *
     * @param clientId Client ID.
     * @return  Array of OAuthApp data objects.
     * @throws IdentityOAuth2Exception      If an error occurred while retrieving the applications.
     * @throws InvalidOAuthClientException  If an application not found for the given client ID.
     */
    public static OAuthAppDO[] getAppsForClientId(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        return new OAuthAppDAO().getAppsForConsumerKey(clientId);
    }

    /**
     * Get the client secret of the application.
     * This method is deprecated as it uses the tenant present in thread local to retrieve the client.
     * Use {@link #getClientSecret(String, String)} instead.
     *
     * @param consumerKey Consumer Key provided by the user.
     * @return Consumer Secret.
     * @throws IdentityOAuth2Exception Error when loading the application.
     * @throws InvalidOAuthClientException Error when loading the application.
     */
    @Deprecated
    public static String getClientSecret(String consumerKey) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = getAppInformationByClientId(consumerKey);
        if (oAuthAppDO == null) {
            throw new InvalidOAuthClientException("Unable to retrieve app information for consumer key: "
                    + consumerKey);
        }
        return oAuthAppDO.getOauthConsumerSecret();
    }

    /**
     * Get the client secret of the application.
     *
     * @param consumerKey   Consumer Key provided by the user.
     * @param tenantDomain  Tenant domain of the application.
     * @return Consumer Secret.
     * @throws IdentityOAuth2Exception      Error when loading the application.
     * @throws InvalidOAuthClientException  Error when loading the application.
     */
    public static String getClientSecret(String consumerKey, String tenantDomain) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = getAppInformationByClientId(consumerKey, tenantDomain);
        if (oAuthAppDO == null) {
            throw new InvalidOAuthClientException("Unable to retrieve app information for consumer key: "
                    + consumerKey + " and tenant: " + tenantDomain);
        }
        return oAuthAppDO.getOauthConsumerSecret();
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
    public static JWSAlgorithm mapSignatureAlgorithmForJWSAlgorithm(String signatureAlgorithm)
            throws IdentityOAuth2Exception {

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
        } else if (SHA256_WITH_EC.equals(signatureAlgorithm) || ES256.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES256;
        } else if (SHA384_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES384;
        } else if (SHA512_WITH_EC.equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES512;
        } else if (SHA256_WITH_PS.equals(signatureAlgorithm) || PS256.equals(signatureAlgorithm)) {
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
        OMElement configOpenIDConnect = oauthElem
                .getFirstChildWithName(new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, OPENID_CONNECT));

        if (configOpenIDConnect == null) {
            log.warn("Error in OAuth Configuration. OpenID element is not available.");
            return isAudienceEnabled;
        }
        OMElement configAudience = configOpenIDConnect.getFirstChildWithName(
                new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, ENABLE_OPENID_CONNECT_AUDIENCES));

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
            return OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX +
                    OAuthConstants.UserType.FEDERATED_USER_DOMAIN_SEPARATOR + authenticatedIDP;
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
                tenantDomain =
                        MultitenantUtils.getTenantDomain(SignedJWT.parse(idToken).getJWTClaimsSet().getSubject());
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
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating id token signature.");
            }
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
     * @deprecated replaced by
     * {@link #encryptJWT(JWTClaimsSet, JWSAlgorithm, String, JWEAlgorithm, EncryptionMethod, String, String)}
     */
    @Deprecated
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
     * This is the generic Encryption function which calls algorithm specific encryption function
     * depending on the algorithm name.
     *
     * @param jwtClaimsSet        JwtClaimsSet to encrypt
     * @param signatureAlgorithm  Signature algorithm
     * @param signingTenantDomain Tenant Domain for signing
     * @param encryptionAlgorithm JWT encryption algorithm
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @return encrypted JWT token
     * @throws IdentityOAuth2Exception
     */
    public static JWT encryptJWT(JWTClaimsSet jwtClaimsSet, JWSAlgorithm signatureAlgorithm, String signingTenantDomain,
                                 JWEAlgorithm encryptionAlgorithm, EncryptionMethod encryptionMethod,
                                 String spTenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        if (isRSAAlgorithm(encryptionAlgorithm)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Signing JWT before encryption using the algorithm: %s ."
                        , signatureAlgorithm));
            }
            SignedJWT signedJwt = (SignedJWT) OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain);
            return encryptWithRSA(signedJwt, encryptionAlgorithm, encryptionMethod, spTenantDomain, clientId);
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
     * @deprecated replaced by {@link #encryptWithRSA(SignedJWT, JWEAlgorithm, EncryptionMethod, String, String)}
     */
    @Deprecated
    private static JWT encryptWithRSA(JWTClaimsSet jwtClaimsSet, JWEAlgorithm encryptionAlgorithm,
                                      EncryptionMethod encryptionMethod, String spTenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        if (StringUtils.isBlank(spTenantDomain)) {
            spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            if (log.isDebugEnabled()) {
                log.debug("Assigned super tenant domain as signing domain when encrypting id token for " +
                        "client_id: " + clientId);
            }
        }
        String jwksUri = getSPJwksUrl(clientId, spTenantDomain);
        Certificate publicCert;
        String thumbPrint;

        if (StringUtils.isBlank(jwksUri)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Jwks uri is not configured for the service provider associated with " +
                                "client_id: %s. Checking for x509 certificate", clientId));
            }
            publicCert = getX509CertOfOAuthApp(clientId, spTenantDomain);
            thumbPrint = getThumbPrint(publicCert);

        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Fetching public keys for the client %s from jwks uri %s", clientId,  jwksUri));
            }
            publicCert = getPublicCertFromJWKS(jwksUri);
            thumbPrint = getJwkThumbPrint(publicCert);
        }
        Key publicKey = publicCert.getPublicKey();
        return encryptWithPublicKey(publicKey, jwtClaimsSet, encryptionAlgorithm, encryptionMethod,
                spTenantDomain, clientId, thumbPrint);
    }

    /**
     * Encrypt JWT id token using RSA algorithm.
     *
     * @param signedJwt           contains signed JWT body
     * @param encryptionAlgorithm JWT signing algorithm
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @return encrypted JWT token
     * @throws IdentityOAuth2Exception
     */
    private static JWT encryptWithRSA(SignedJWT signedJwt, JWEAlgorithm encryptionAlgorithm,
                                      EncryptionMethod encryptionMethod, String spTenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isBlank(spTenantDomain)) {
                spTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Assigned super tenant domain as signing domain when encrypting id token " +
                            "for client_id: %s .", clientId));
                }
            }
            String jwksUri = getSPJwksUrl(clientId, spTenantDomain);

            if (StringUtils.isBlank(jwksUri)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Jwks uri is not configured for the service provider associated with " +
                            "client_id: %s , Checking for x509 certificate.", clientId));
                }
                return encryptUsingSPX509Certificate(signedJwt, encryptionAlgorithm, encryptionMethod, spTenantDomain,
                        clientId);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Jwks uri is configured for the service provider associated with" +
                            " client %s from jwks uri %s .", clientId, jwksUri));
                }
                return encryptUsingJwksPublicKey(signedJwt, encryptionAlgorithm, encryptionMethod, spTenantDomain,
                        clientId, jwksUri);
            }

        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error occurred while encrypting JWT for the client_id: " + clientId
                    + " with the tenant domain: " + spTenantDomain, e);
        }
    }

    /**
     * Encrypt jwt using service provider's configured X509 certificate
     *
     * @param signedJwt           contains signed JWT body
     * @param encryptionAlgorithm JWT signing algorithm
     * @param encryptionMethod    Encryption method
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @return
     * @throws IdentityOAuth2Exception
     */
    private static JWT encryptUsingSPX509Certificate(SignedJWT signedJwt, JWEAlgorithm encryptionAlgorithm,
                                                     EncryptionMethod encryptionMethod, String spTenantDomain,
                                                     String clientId) throws IdentityOAuth2Exception {

        Certificate publicCert = getX509CertOfOAuthApp(clientId, spTenantDomain);
        if (publicCert == null) {
            throw new IdentityOAuth2Exception("Error while retrieving X509 cert from oauth app with "
                    + "client_id: " + clientId + " of tenantDomain: " + spTenantDomain);
        }
        Key publicKey = publicCert.getPublicKey();
        if (publicKey == null) {
            throw new IdentityOAuth2Exception("Error while retrieving public key from X509 cert of oauth app with "
                   + "client_id: " + clientId + " of tenantDomain: " + spTenantDomain);
        }
        String kid = getThumbPrint(publicCert);
        return encryptWithPublicKey(publicKey, signedJwt, encryptionAlgorithm, encryptionMethod,
                spTenantDomain, clientId, kid);
    }

    /**
     * Encrypt jwt using publickey fetched from jwks
     *
     * @param signedJwt           contains signed JWT body
     * @param encryptionAlgorithm JWT signing algorithm
     * @param encryptionMethod    Encryption method
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @param jwksUri             jwks url
     * @return
     * @throws IdentityOAuth2Exception
     * @throws JOSEException
     * @throws ParseException
     */
    private static JWT encryptUsingJwksPublicKey(SignedJWT signedJwt, JWEAlgorithm encryptionAlgorithm,
                                                 EncryptionMethod encryptionMethod, String spTenantDomain,
                                                 String clientId, String jwksUri)
            throws IdentityOAuth2Exception, JOSEException, ParseException {

        JWK encryptionJwk = getEncryptionJWKFromJWKS(jwksUri, encryptionAlgorithm);
        Key publicKey = RSAKey.parse(encryptionJwk.toJSONString()).toRSAPublicKey();
        String kid = getKidValueFromJwk(encryptionJwk);
        return encryptWithPublicKey(publicKey, signedJwt, encryptionAlgorithm, encryptionMethod,
                spTenantDomain, clientId, kid);
    }

    /**
     * Get kid value from the jwk
     *
     * @param encryptionJwk Encryption jwk
     * @return
     */
    private static String getKidValueFromJwk(JWK encryptionJwk) {

        String kid;
        Certificate publicCert;
        if (encryptionJwk.getKeyID() != null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Kid value is available in jwk %s .", encryptionJwk.getKeyID()));
            }
            kid = encryptionJwk.getKeyID();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Kid value is not available in jwk, attempting to set x5c thumbprint as kid.");
            }
            try {
                publicCert = getPublicCertFromJWK(encryptionJwk);
                kid = getJwkThumbPrint(publicCert);
            } catch (IdentityOAuth2Exception e) {
                log.error("Failed to set x5c thumbprint as kid value.", e);
                kid = null;
            }
        }
        return kid;
    }

    /**
     * Get encryption jwk from JWKS list when JWKS Uri is given.
     *
     * @param jwksUri - JWKS Uri
     * @param encryptionAlgorithm encryption algorithm
     * @return - encryption JWK from the jwks url
     * @throws IdentityOAuth2Exception - IdentityOAuth2Exception
     */
    private static JWK getEncryptionJWKFromJWKS(String jwksUri, JWEAlgorithm encryptionAlgorithm)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Attempting to retrieve encryption jwk from the Jwks uri: %s , algorithm : %s",
                    jwksUri, encryptionAlgorithm));
        }
        try {
            JWKSet publicKeys = JWKSet.load(new URL(jwksUri));
            // Get the first key, use as enc and alg from the list
            JWKMatcher keyMatcherWithAlgAndEncryptionUse =
                    new JWKMatcher.Builder().algorithm(encryptionAlgorithm).keyUse(KeyUse.ENCRYPTION).build();
            List<JWK> jwkList = new JWKSelector(keyMatcherWithAlgAndEncryptionUse).select(publicKeys);

            if (jwkList.isEmpty()) {
                // If empty, then get the first key, use as enc from the list
                JWKMatcher keyMatcherWithEncryptionUse = new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).build();
                jwkList = new JWKSelector(keyMatcherWithEncryptionUse).select(publicKeys);

                if (jwkList.isEmpty()) {
                    // failover defaults to ->, then get the first key, use as sig from the list
                    JWKMatcher keyMatcherWithSignatureUse = new JWKMatcher.Builder().keyUse(KeyUse.SIGNATURE).build();
                    jwkList = new JWKSelector(keyMatcherWithSignatureUse).select(publicKeys);
                }
            }

            if (jwkList.isEmpty()) {
                throw new IdentityOAuth2Exception(String.format("Failed to retrieve valid jwk from " +
                        "jwks uri: %s, algorithm : %s ", jwksUri, encryptionAlgorithm));
            } else {
                return jwkList.get(0);
            }
        } catch (ParseException | IOException e) {
            throw new IdentityOAuth2Exception(String.format("Failed to retrieve jwk from jwks uri: %s, algorithm : %s",
                    jwksUri, encryptionAlgorithm), e);
        }
    }

    /**
     * Get public certificate from JWK
     *
     * @param jwk
     * @return
     * @throws IdentityOAuth2Exception
     */
    private static X509Certificate getPublicCertFromJWK(JWK jwk) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Attempting to retrieve public certificate from the Jwk kid: %s ."
                    , jwk.getKeyID()));
        }
        X509Certificate certificate;
        if (jwk != null && jwk.getParsedX509CertChain() != null) {
            certificate = jwk.getParsedX509CertChain().get(0);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Retrieved the public signing certificate successfully from the " +
                        "jwk : %s .", jwk));
            }
            return certificate;
        }
        throw new IdentityOAuth2Exception("Failed to retrieve public certificate from jwk due to null.");
    }

    /**
     * Encrypt the JWT token with with given public key.
     *
     * @param publicKey           public key used to encrypt
     * @param jwtClaimsSet        contains JWT body
     * @param encryptionAlgorithm JWT signing algorithm
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @param thumbPrint          value used as 'kid'
     * @return encrypted JWT token
     * @throws IdentityOAuth2Exception
     * @deprecated replaced by
     * {@link #encryptWithPublicKey(Key, SignedJWT, JWEAlgorithm, EncryptionMethod, String, String, String)}
     */
    @Deprecated
    private static JWT encryptWithPublicKey(Key publicKey, JWTClaimsSet jwtClaimsSet,
                                            JWEAlgorithm encryptionAlgorithm, EncryptionMethod encryptionMethod,
                                            String spTenantDomain, String clientId,
                                            String thumbPrint) throws IdentityOAuth2Exception {

        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(encryptionAlgorithm, encryptionMethod);

        try {
            headerBuilder.keyID(thumbPrint);
            JWEHeader header = headerBuilder.build();
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);

            if (log.isDebugEnabled()) {
                log.debug("Encrypting JWT using the algorithm: " + encryptionAlgorithm + ", method: " +
                        encryptionMethod + ", tenant: " + spTenantDomain + " & header: " + header.toString());
            }

            JWEEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
            encryptedJWT.encrypt(encrypter);
            return encryptedJWT;
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while encrypting JWT for the client_id: " + clientId
                    + " with the tenant domain: " + spTenantDomain, e);
        }
    }

    /**
     * Encrypt the JWT token with with given public key.
     *
     * @param publicKey           public key used to encrypt
     * @param signedJwt           contains signed JWT body
     * @param encryptionAlgorithm JWT signing algorithm
     * @param spTenantDomain      Service provider tenant domain
     * @param clientId            ID of the client
     * @param kid                 value used as 'kid'
     * @return encrypted JWT token
     * @throws IdentityOAuth2Exception
     */
    private static JWT encryptWithPublicKey(Key publicKey, SignedJWT signedJwt,
                                            JWEAlgorithm encryptionAlgorithm, EncryptionMethod encryptionMethod,
                                            String spTenantDomain, String clientId,
                                            String kid) throws IdentityOAuth2Exception {

        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(encryptionAlgorithm, encryptionMethod);

        try {
            if (StringUtils.isNotBlank(kid)) {
                headerBuilder.keyID(kid);
            }
            headerBuilder.contentType(JWT); // Required to indicate nested JWT.
            JWEHeader header = headerBuilder.build();

            JWEObject jweObject = new JWEObject(header, new Payload(signedJwt));
            // Encrypt with the recipient's public key.
            jweObject.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));

            EncryptedJWT encryptedJWT = EncryptedJWT.parse(jweObject.serialize());

            if (log.isDebugEnabled()) {
                log.debug("Encrypting JWT using the algorithm: " + encryptionAlgorithm + ", method: " +
                        encryptionMethod + ", tenant: " + spTenantDomain + " & header: " + header.toString());
            }

            return encryptedJWT;
        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error occurred while encrypting JWT for the client_id: " + clientId
                    + " with the tenant domain: " + spTenantDomain, e);
        }
    }

    /**
     * Create JWSSigner using the server level configurations and return.
     *
     * @param privateKey RSA Private key.
     * @return  JWSSigner
     */
    public static JWSSigner createJWSSigner(RSAPrivateKey privateKey) {

        boolean allowWeakKey = Boolean.parseBoolean(System.getProperty(ALLOW_WEAK_RSA_SIGNER_KEY));
        if (allowWeakKey && log.isDebugEnabled()) {
            log.debug("System flag 'allow_weak_rsa_signer_key' is  enabled. So weak keys (key length less than 2048) " +
                    " will be allowed for signing.");
        }
        return new RSASSASigner(privateKey, allowWeakKey);
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
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder((JWSAlgorithm) signatureAlgorithm);
            headerBuilder.keyID(getKID(getCertificate(tenantDomain, tenantId), signatureAlgorithm, tenantDomain));
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
     * Helper method to add algo into to JWT_HEADER to signature verification.
     *
     * @param certThumbprint
     * @param signatureAlgorithm
     * @return
     *
     */
    public static String getKID(String certThumbprint, JWSAlgorithm signatureAlgorithm) {

        return certThumbprint + "_" + signatureAlgorithm.toString();
    }

    /**
     * Method to obtain 'kid' value for the signing key to be included the JWT header.
     *
     * @param certificate        Signing Certificate.
     * @param signatureAlgorithm relevant signature algorithm.
     * @return KID value as a String.
     */
    public static String getKID(Certificate certificate, JWSAlgorithm signatureAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception {

        return OAuth2ServiceComponentHolder.getKeyIDProvider().getKeyId(certificate, signatureAlgorithm, tenantDomain);
    }

    /**
     * Method to obtain 'kid' value generated with SHA-1 alg for the signing key to be included the JWT header.
     *
     * @param certificate        Signing Certificate.
     * @param signatureAlgorithm relevant signature algorithm.
     * @return                   KID value as a String.
     * @throws IdentityOAuth2Exception
     */
    public static String getPreviousKID(Certificate certificate, JWSAlgorithm signatureAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception {

        return OAuth2ServiceComponentHolder.getKeyIDProvider()
                .getPreviousKeyId(certificate, signatureAlgorithm, tenantDomain);
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

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     * This creates thumbPrints directly from given certificates
     *
     * @param certificate
     * @param alias
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String getThumbPrint(Certificate certificate, String alias) throws IdentityOAuth2Exception {

        return getThumbPrint(certificate);
    }

    /**
     * Method to obtain certificate thumbprint with default SHA-256 algorithm.
     *
     * @param certificate java.security.cert type certificate.
     * @return Certificate thumbprint as a String.
     * @throws IdentityOAuth2Exception When failed to obtain the thumbprint.
     */
    public static String getThumbPrint(Certificate certificate) throws IdentityOAuth2Exception {

        return getThumbPrintWithAlgorithm(certificate, KID_HASHING_ALGORITHM);
    }

    public static String getThumbPrintWithPrevAlgorithm(Certificate certificate)
            throws IdentityOAuth2Exception {

        return getThumbPrintWithAlgorithm(certificate, PREVIOUS_KID_HASHING_ALGORITHM);
    }

    private static String getThumbPrintWithAlgorithm(Certificate certificate, String algorithm)
            throws IdentityOAuth2Exception {

        try {
            MessageDigest digestValue = MessageDigest.getInstance(algorithm);
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();
            String publicCertThumbprint = hexify(digestInBytes);
            String thumbprint = new String(new Base64(0, null, true).
                    encode(publicCertThumbprint.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Thumbprint value: %s calculated for Certificate: %s using algorithm: %s",
                        thumbprint, certificate, digestValue.getAlgorithm()));
            }
            return thumbprint;
        } catch (CertificateEncodingException e) {
            String error = "Error occurred while encoding thumbPrint from certificate.";
            throw new IdentityOAuth2Exception(error, e);
        } catch (NoSuchAlgorithmException e) {
            String error = String.format("Error in obtaining %s thumbprint from certificate.", algorithm);
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private static boolean isRSAAlgorithm(JWEAlgorithm algorithm) {

        return (JWEAlgorithm.RSA_OAEP.equals(algorithm) || JWEAlgorithm.RSA1_5.equals(algorithm) ||
                JWEAlgorithm.RSA_OAEP_256.equals(algorithm));
    }

    /**
     * Method to obatin Default Signing certificate for the tenant.
     *
     * @param tenantDomain Tenant Domain as a String.
     * @param tenantId     Tenan ID as an integer.
     * @return Default Signing Certificate of the tenant domain.
     * @throws IdentityOAuth2Exception When failed to obtain the certificate for the requested tenant.
     */
    public static Certificate getCertificate(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Obtaining certificate for the tenant %s", tenantDomain));
            }
            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant " + tenantDomain,
                        e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Loading default tenant certificate for tenant : %s from the KeyStore" +
                            " %s", tenantDomain, ksName));
                }
                try {
                    keyStore = tenantKSM.getKeyStore(jksName);
                    publicCert = keyStore.getCertificate(tenantDomain);
                } catch (KeyStoreException e) {
                    throw new IdentityOAuth2Exception("Error occurred while loading public certificate for tenant: " +
                            tenantDomain, e);
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error occurred while loading Keystore for tenant: " +
                            tenantDomain, e);
                }

            } else {
                try {
                    publicCert = tenantKSM.getDefaultPrimaryCertificate();
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error occurred while loading default public " +
                            "certificate for tenant: " + tenantDomain, e);
                }
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

    /**
     * Returns essential claims according to claim type: id_token/userinfo .
     *
     * @param essentialClaims
     * @param claimType
     * @return essential claims list
     */
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
                            if (Boolean.parseBoolean(claimValue) &&
                                    claimKey.equals(OAuthConstants.OAuth20Params.ESSENTIAL)) {
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
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                // When the IDP_ID column is available it was decided to set the
                // domain name for federated users to 'FEDERATED'.
                // This is a system reserved word and users stores cannot be created with this name.
                userStoreDomain = FrameworkConstants.FEDERATED_IDP_NAME;
            } else {
                userStoreDomain = OAuth2Util.getFederatedUserDomain(authenticatedUser.getFederatedIdPName());
            }
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
        if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() &&
                authenticatedUser.isFederatedUser()) {
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
            throw new IdentityOAuth2ClientException("Could not find an existing app for clientId: " + clientId, e);
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
     * Return true if the token identifier is a parsable JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    public static boolean isParsableJWT(String tokenIdentifier) {

        if (StringUtils.isBlank(tokenIdentifier)) {
            return false;
        }
        try {
            JWTParser.parse(tokenIdentifier);
            return true;
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Provided token identifier is not a parsable JWT.", e);
            }
            return false;
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
            OAuthEventInterceptor oAuthEventInterceptorProxy =
                    OAuthComponentServiceHolder.getInstance().getOAuthEventInterceptorProxy();

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
     * Get the supported code challenge methods.
     *
     * @return list of code challenge methods.
     */
    public static List<String> getSupportedCodeChallengeMethods() {

        List<String> codeChallengeMethods = new ArrayList<>();
        codeChallengeMethods.add(OAuthConstants.OAUTH_PKCE_S256_CHALLENGE);
        codeChallengeMethods.add(OAuthConstants.OAUTH_PKCE_PLAIN_CHALLENGE);

        return codeChallengeMethods;
    }

    /**
     * Get the supported response modes.
     *
     * @return list of response modes supported.
     */
    public static List<String> getSupportedResponseModes() {

        return OAuthServerConfiguration.getInstance().getSupportedResponseModeNames();
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
     * @deprecated use {@link #createAuthenticatedUser(String, String, String, String)} instead.
     */
    @Deprecated
    public static AuthenticatedUser createAuthenticatedUser(String username, String userStoreDomain,
                                                            String tenantDomain) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setTenantDomain(tenantDomain);
        if (StringUtils.startsWith(userStoreDomain, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX) &&
                !OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal()) {
            if (log.isDebugEnabled()) {
                log.debug("Federated prefix found in domain: " + userStoreDomain + " for user: " + username
                        + " in tenant domain: " + tenantDomain + ". Flag user as a federated user.");
            }
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(OAuth2Util.getFederatedIdPFromDomain(userStoreDomain));
        } else {
            authenticatedUser.setUserStoreDomain(userStoreDomain);
        }

        return authenticatedUser;
    }

    /**
     * Creates an instance of AuthenticatedUser{@link AuthenticatedUser} for the given parameters.
     *
     * @param username        username of the user
     * @param userStoreDomain user store domain
     * @param tenantDomain    tenent domain
     * @param idpName         idp name
     * @return an instance of AuthenticatedUser{@link AuthenticatedUser}
     */
    public static AuthenticatedUser createAuthenticatedUser(String username, String userStoreDomain, String
            tenantDomain, String idpName) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setTenantDomain(tenantDomain);

        /* When the IDP_ID column is available it was decided to set the
         domain name for federated users to 'FEDERATED'.
         This is a system reserved word and user stores cannot be created with this name.

         For jwt bearer grant and saml bearer grant types, assertion issuing idp is set as
         the authenticated idp, but this may not always be the idp user is in;
         i.e, for an assertion issued by IS, idp name will be 'LOCAL', yet the user could have been
         authenticated with some external idp.
         Therefore, we cannot stop setting 'FEDERATED' as the user store domain for federated users.*/
        if (StringUtils.startsWith(userStoreDomain, OAuthConstants.UserType.FEDERATED_USER_DOMAIN_PREFIX) &&
                !OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal()) {
            authenticatedUser.setFederatedUser(true);
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                authenticatedUser.setFederatedIdPName(idpName);
            } else {
                authenticatedUser.setFederatedIdPName(OAuth2Util.getFederatedIdPFromDomain(userStoreDomain));
            }
            authenticatedUser.setUserId(getUserIdOfFederatedUser(username, tenantDomain, idpName));
            if (log.isDebugEnabled()) {
                log.debug("Federated prefix found in domain: " + userStoreDomain + " for user: " + username +
                        " in tenant domain: " + tenantDomain + ". Flag user as a federated user. " +
                        authenticatedUser.getFederatedIdPName() + " is set as the authenticated idp.");
            }
        } else {
            authenticatedUser.setUserStoreDomain(userStoreDomain);
            authenticatedUser.setFederatedIdPName(idpName);
        }

        return authenticatedUser;
    }

    /**
     * Get the user if of the federated user from the user session store.
     *
     * @param username     Username.
     * @param tenantDomain Tenant domain.
     * @param idpName      IDP name.
     * @return User id associated with the given federated user.
     */
    private static String getUserIdOfFederatedUser(String username, String tenantDomain, String idpName) {

        String userId = null;
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            int idpId = UserSessionStore.getInstance().getIdPId(idpName, tenantId);
            userId = UserSessionStore.getInstance().getFederatedUserId(username, tenantId, idpId);
        } catch (UserSessionException e) {
            // In here we better not log the user id.
            log.error("Error occurred while resolving the user id from the username for the federated user", e);
        }
        return userId;
    }

    public static String getIdTokenIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            try {
                return ServiceURLBuilder.create().addPath(OAUTH2_TOKEN_EP_URL).build().getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                String errorMsg = String.format("Error while building the absolute url of the context: '%s',  for the" +
                        " tenant domain: '%s'", OAUTH2_TOKEN_EP_URL, tenantDomain);
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        } else {
            return getIssuerLocation(tenantDomain);
        }
    }

    /**
     * Used to get the issuer url for a given tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return Token issuer url.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    public static String getIssuerLocation(String tenantDomain) throws IdentityOAuth2Exception {

        /*
        * IMPORTANT:
        * This method should only honor the given tenant.
        * Do not add any auto tenant resolving logic.
        */
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled() || isBuildIssuerWithHostname()) {
            try {
                startTenantFlow(tenantDomain);
                return ServiceURLBuilder.create().addPath(OAUTH2_TOKEN_EP_URL).build().getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                String errorMsg = String.format("Error while building the absolute url of the context: '%s',  for the" +
                        " tenant domain: '%s'", OAUTH2_TOKEN_EP_URL, tenantDomain);
                throw new IdentityOAuth2Exception(errorMsg, e);
            } finally {
                endTenantFlow();
            }
        } else {
            return getResidentIdpEntityId(tenantDomain);
        }
    }

    /**
     * Retrieve entity id of the resident identity provider.
     *
     * @param tenantDomain tenant domain.
     * @return idp entity id.
     * @throws IdentityOAuth2Exception when failed to retrieve the idp entity id.
     */
    public static String getResidentIdpEntityId(String tenantDomain) throws IdentityOAuth2Exception {

        IdentityProvider identityProvider = getResidentIdp(tenantDomain);
        FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        return IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                IDP_ENTITY_ID).getValue();
    }

    /**
     * If enabled, hostname will be used to build the issuer of the ID token instead of entity id of the resident IDP.
     *
     * @return true if hostname is to be used to build the issuer of the ID token.
     */
    private static boolean isBuildIssuerWithHostname() {

        String buildIssuerWithHostname = IdentityUtil.getProperty(OAUTH_BUILD_ISSUER_WITH_HOSTNAME);
        return Boolean.parseBoolean(buildIssuerWithHostname);
    }

    private static IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg =
                    String.format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Used to build an OAuth revocation request DTO.
     *
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @param accessToken             Access token to be revoked.
     * @return Returns a OAuth revocation request DTO.
     */
    public static OAuthRevocationRequestDTO buildOAuthRevocationRequest(OAuthClientAuthnContext oAuthClientAuthnContext,
                                                                        String accessToken) {

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
        accessTokenDO = getAccessTokenDOFromMatchingTokenIssuer(tokenIdentifier, allOAuthTokenIssuerMap,
                includeExpired);

        // If the lookup is only for tokens in 'ACTIVE' state, APIs calling this method expect an
        // IllegalArgumentException to be thrown to identify inactive/invalid tokens.
        if (accessTokenDO == null && !includeExpired) {
            throw new IllegalArgumentException("Invalid Access Token. ACTIVE access token is not found.");
        }
        return accessTokenDO;
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
                        accessTokenDO = OAuth2Util.getAccessTokenDOFromTokenIdentifier(tokenAlias, includeExpired);
                    } else {
                        accessTokenDO = OAuth2Util.getAccessTokenDOFromTokenIdentifier(tokenIdentifier, includeExpired);
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
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and"
                                    + " failed to get the token from database: " + tokenIdentifier);
                        } else {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and"
                                    + " failed  to get the token from database.");
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
     * @param defaultOAuthTokenIssuerMap default token issuers
     */
    private static void extractDefaultOauthTokenIssuers(Map<String, OauthTokenIssuer> allOAuthTokenIssuerMap,
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
            AccessTokenDO accessTokenDO;
            try {
                accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                        .getVerifiedAccessToken(tokenResponse.getAuthorizationContextToken().getTokenString(), false);
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
     * Retrieves and verifies an access token data object based on the provided
     * OAuth2TokenValidationResponseDTO, excluding expired tokens from verification.
     *
     * @param tokenResponse The OAuth2TokenValidationResponseDTO containing token information.
     * @return An Optional containing the AccessTokenDO if the token is valid (ACTIVE), or an empty Optional if the
     * token is not found in ACTIVE state.
     * @throws UserInfoEndpointException If an error occurs while obtaining the access token.
     */
    public static Optional<AccessTokenDO> getAccessTokenDO(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException {

        if (tokenResponse.getAuthorizationContextToken().getTokenString() != null) {
            try {
                AccessTokenDO accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                        .getVerifiedAccessToken(tokenResponse.getAuthorizationContextToken().getTokenString(), false);
                return Optional.ofNullable(accessTokenDO);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("Error occurred while obtaining access token.", e);
            }
        } else {
            return Optional.empty();
        }
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

    /**
     * Used to get the authenticated IDP name from a user.
     *
     * @param user Authenticated User.
     * @return Returns the authenticated IDP name.
     */
    public static String getAuthenticatedIDP(AuthenticatedUser user) {

        String authenticatedIDP;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
            if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && user.isFederatedUser()) {
                authenticatedIDP = user.getFederatedIdPName();
                if (log.isDebugEnabled()) {
                    log.debug("IDP_ID column is available. User is federated and not mapped to local users. " +
                            "Authenticated IDP is set to:" + authenticatedIDP + " for user:"
                            + user.getLoggableUserId());
                }
            } else {
                authenticatedIDP = FrameworkConstants.LOCAL_IDP_NAME;
                if (log.isDebugEnabled()) {
                    log.debug("IDP_ID column is available. Authenticated IDP is set to:" + authenticatedIDP +
                            " for user:" + user.getLoggableUserId());
                }
            }
        } else {
            authenticatedIDP = user.getFederatedIdPName();
            if (log.isDebugEnabled()) {
                log.debug("IDP_ID column is not available. Authenticated IDP is set to:" + authenticatedIDP +
                        " for user:" + user.getLoggableUserId());
            }
        }

        return authenticatedIDP;
    }

    /**
     * Used to get the user store domain name from a user.
     *
     * @param user Authenticated User.
     * @return Returns the sanitized user store domain.
     */
    public static String getUserStoreDomain(AuthenticatedUser user) {

        String userDomain;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled() &&
                !OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && user.isFederatedUser()) {
            if (log.isDebugEnabled()) {
                log.debug("IDP_ID column is available. User is federated and not mapped to local users.");
            }
            // When the IDP_ID column is available it was decided to set the
            // domain name for federated users to 'FEDERATED'.
            // This is a system reserved word and users stores cannot be created with this name.
            userDomain = FrameworkConstants.FEDERATED_IDP_NAME;
        } else if (!OAuthServerConfiguration.getInstance().isMapFederatedUsersToLocal() && user.isFederatedUser()) {
            if (log.isDebugEnabled()) {
                log.debug("IDP_ID column is not available. User is federated and not mapped to local users.");
            }
            userDomain = OAuth2Util.getFederatedUserDomain(user.getFederatedIdPName());
        } else {
            userDomain = user.getUserStoreDomain();
            if (log.isDebugEnabled()) {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    log.debug("IDP_ID column is available. User is not federated or mapped to local users.");
                } else {
                    log.debug("IDP_ID column is not available. User is not federated or mapped to local users.");
                }
            }
        }
        String sanitizedUserDomain = OAuth2Util.getSanitizedUserStoreDomain(userDomain);
        if (log.isDebugEnabled()) {
            log.debug("User domain is set to:" + sanitizedUserDomain  + " for user:" + user.getLoggableUserId());
        }

        return sanitizedUserDomain;
    }

    /**
     * Check if the IDP_ID column is available in the relevant tables.
     *
     * @return True if IDP_ID column is available in all the relevant table.
     */
    public static boolean checkIDPIdColumnAvailable() {

        boolean isIdpIdAvailableInAuthzCodeTable;
        boolean isIdpIdAvailableInTokenTable;
        boolean isIdpIdAvailableInTokenAuditTable;
        String columnIdpId = "IDP_ID";

        isIdpIdAvailableInAuthzCodeTable = FrameworkUtils
                .isTableColumnExists("IDN_OAUTH2_AUTHORIZATION_CODE", columnIdpId);
        isIdpIdAvailableInTokenTable = FrameworkUtils
                .isTableColumnExists("IDN_OAUTH2_ACCESS_TOKEN", columnIdpId);
        if (OAuthServerConfiguration.getInstance().useRetainOldAccessTokens()) {
            isIdpIdAvailableInTokenAuditTable = FrameworkUtils
                    .isTableColumnExists("IDN_OAUTH2_ACCESS_TOKEN_AUDIT", columnIdpId);
        } else {
            isIdpIdAvailableInTokenAuditTable = true;
            if (log.isDebugEnabled()) {
                log.debug("Retaining old access tokens in IDN_OAUTH2_ACCESS_TOKEN_AUDIT is disabled, therefore " +
                        "ignoring the availability of IDP_ID column in IDN_OAUTH2_ACCESS_TOKEN_AUDIT table.");
            }
        }

        return isIdpIdAvailableInAuthzCodeTable && isIdpIdAvailableInTokenTable && isIdpIdAvailableInTokenAuditTable;
    }

    public static boolean isAccessTokenExtendedTableExist() {

        return IdentityDatabaseUtil.isTableExists(OAuthConstants.ACCESS_TOKEN_STORE_ATTRIBUTES_TABLE);
    }

    /**
     * Check whether the CONSENTED_TOKEN column is available in IDN_OAUTH2_ACCESS_TOKEN table.
     *
     * @return True if the column is available.
     */
    public static boolean checkConsentedTokenColumnAvailable() {

        return FrameworkUtils.isTableColumnExists("IDN_OAUTH2_ACCESS_TOKEN", "CONSENTED_TOKEN");
    }

    /**
     * This can be used to load the oauth scope permissions bindings in oauth-scope-bindings.xml file.
     */
    public static void initiateOAuthScopePermissionsBindings(int tenantId) {

        if (Oauth2ScopeUtils.isSystemLevelInternalSystemScopeManagementEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth internal scopes permission binding initialization is skipped as the scopes " +
                        "are managed globally.");
            }
            return;
        }
        try {
            //Check login scope is available. If exists, assumes all scopes are loaded using the file.
            if (!hasScopesAlreadyAdded(tenantId)) {
                List<Scope> scopes = OAuth2ServiceComponentHolder.getInstance().getOauthScopeBinding();
                for (Scope scope : scopes) {
                    OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().addScope(scope, tenantId);
                }
                if (log.isDebugEnabled()) {
                    log.debug("OAuth scopes are loaded for the tenant : " + tenantId);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth scopes are already loaded");
                }
            }
        } catch (IdentityOAuth2ScopeException e) {
            log.error("Error while registering OAuth scopes with permissions bindings", e);
        }
    }

    private static boolean hasScopesAlreadyAdded(int tenantId) throws IdentityOAuth2ScopeServerException {

        Scope loginScope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeByName(
                INTERNAL_LOGIN_SCOPE, tenantId);
        if (loginScope == null) {
            return false;
        } else {
            List<ScopeBinding> scopeBindings = loginScope.getScopeBindings();
            for (ScopeBinding scopeBinding : scopeBindings) {
                if (PERMISSIONS_BINDING_TYPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check whether required token binding available in the request.
     *
     * @param tokenBinding token binding.
     * @param request http request.
     * @return true if binding is valid.
     */
    public static boolean isValidTokenBinding(TokenBinding tokenBinding, HttpServletRequest request) {

        if (request == null || tokenBinding == null || StringUtils.isBlank(tokenBinding.getBindingReference())
                || StringUtils.isBlank(tokenBinding.getBindingType())) {
            return true;
        }

        Optional<TokenBinder> tokenBinderOptional = OAuth2ServiceComponentHolder.getInstance()
                .getTokenBinder(tokenBinding.getBindingType());
        if (!tokenBinderOptional.isPresent()) {
            log.warn("Token binder with type: " + tokenBinding.getBindingType() + " is not available.");
            return false;
        }

        return tokenBinderOptional.get().isValidTokenBinding(request, tokenBinding);
    }

    /**
     * Get public certificate from JWKS when kid and JWKS Uri is given.
     *
     * @param jwksUri - JWKS Uri
     * @return - X509Certificate
     * @throws IdentityOAuth2Exception - IdentityOAuth2Exception
     * @deprecated replaced with {@link #getEncryptionJWKFromJWKS(String, JWEAlgorithm)}
     */
    @Deprecated
    private static X509Certificate getPublicCertFromJWKS(String jwksUri) throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Attempting to retrieve public certificate from the Jwks uri: %s.", jwksUri));
        }
        try {
            JWKSet publicKeys = JWKSet.load(new URL(jwksUri));
            JWK jwk = null;
            X509Certificate certificate;
            //Get the first signing JWK from the list
            List<JWK> jwkList = publicKeys.getKeys();

            for (JWK currentJwk : jwkList) {
                if (KeyUse.SIGNATURE == currentJwk.getKeyUse()) {
                    jwk = currentJwk;
                    break;
                }
            }

            if (jwk != null) {
                certificate = jwk.getParsedX509CertChain().get(0);
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Retrieved the public signing certificate successfully from the " +
                            "jwks uri: %s", jwksUri));
                }
                return certificate;
            } else {
                throw new IdentityOAuth2Exception(String.format("Failed to retrieve public certificate from " +
                        "jwks uri: %s", jwksUri));
            }
        } catch (ParseException | IOException e) {
            throw new IdentityOAuth2Exception(String.format("Failed to retrieve public certificate from " +
                    "jwks uri: %s", jwksUri), e);
        }
    }

    /**
     * Get Jwks uri of SP when clientId and spTenantDomain is provided.
     *
     * @param clientId       - ClientId
     * @param spTenantDomain - Tenant domain
     * @return Jwks Url
     * @throws IdentityOAuth2Exception
     */
    public static String getSPJwksUrl(String clientId, String spTenantDomain) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId, spTenantDomain);
        String jwksUri = serviceProvider.getJwksUri();
        if (StringUtils.isNotBlank(jwksUri)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Retrieved jwks uri: %s for the service provider associated with client_id: %s",
                        jwksUri, clientId));
            }
        }
        return jwksUri;
    }

    /**
     * Method to extract the SHA-256 JWK thumbprint from certificates.
     *
     * @param certificate x509 certificate
     * @return String thumbprint
     * @throws IdentityOAuth2Exception When failed to extract thumbprint
     */
    public static String getJwkThumbPrint(Certificate certificate) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Calculating SHA-256 JWK thumb-print for certificate: %s", certificate.toString()));
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance(Constants.X509);
            ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(bais);
            Base64URL jwkThumbprint;
            // check config to maintain backward compatibility with SHA-1 thumbprint
            if (Boolean.parseBoolean(IdentityUtil.getProperty(
                    IdentityConstants.OAuth.ENABLE_SHA256_JWK_THUMBPRINT))) {
                jwkThumbprint = RSAKey.parse(x509).computeThumbprint(Constants.SHA256);
            } else {
                jwkThumbprint = RSAKey.parse(x509).computeThumbprint(Constants.SHA1);
            }

            String thumbprintString = jwkThumbprint.toString();
            if (log.isDebugEnabled()) {
                log.debug(String.format("Calculated SHA-1 JWK thumbprint %s from the certificate",
                        thumbprintString));
            }
            return thumbprintString;
        } catch (CertificateException | JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while generating SHA-1 JWK thumbprint", e);
        }
    }

    /**
     * Validates whether the tenant domain set in context matches with the app's tenant domain in tenant qualified
     * URL mode.
     *
     * @param tenantDomainOfApp Tenant domain of the app.
     * @throws InvalidOAuthClientException
     */
    public static void validateRequestTenantDomain(String tenantDomainOfApp) throws InvalidOAuthClientException {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {

            String tenantDomainFromContext = IdentityTenantUtil.resolveTenantDomain();
            if (!StringUtils.equals(tenantDomainFromContext, tenantDomainOfApp)) {
                // This means the tenant domain sent in the request and app's tenant domain do not match.
                if (log.isDebugEnabled()) {
                    log.debug("A valid client with the given client_id cannot be found in " +
                            "tenantDomain: " + tenantDomainFromContext);
                }
                throw new InvalidOAuthClientException("no.valid.client.in.tenant");
            }
        }
    }

    /**
     * Validates whether the tenant domain set in context matches with the app's tenant domain in tenant qualified
     * URL mode.
     *
     * @param tenantDomainOfApp Tenant domain of the app.
     * @param tokenReqDTO       Access token request DTO object that contains request parameters.
     * @throws InvalidOAuthClientException
     */
    public static void validateRequestTenantDomain(String tenantDomainOfApp, OAuth2AccessTokenReqDTO tokenReqDTO)
            throws InvalidOAuthClientException {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {

            Optional<String> contextTenantDomainFromTokenReqDTO = getContextTenantDomainFromTokenReqDTO(tokenReqDTO);
            String tenantDomainFromContext;
            if (contextTenantDomainFromTokenReqDTO.isPresent()) {
                tenantDomainFromContext = contextTenantDomainFromTokenReqDTO.get();
                if (StringUtils.isBlank(tenantDomainFromContext)) {
                    tenantDomainFromContext = IdentityTenantUtil.resolveTenantDomain();
                }

                if (!StringUtils.equals(tenantDomainFromContext, tenantDomainOfApp)) {
                    // This means the tenant domain sent in the request and app's tenant domain do not match.
                    throw new InvalidOAuthClientException("A valid client with the given client_id cannot be found in "
                            + "tenantDomain: " + tenantDomainFromContext);
                }
            } else {
                validateRequestTenantDomain(tenantDomainOfApp);
            }
        }
    }

    private static Optional<String> getContextTenantDomainFromTokenReqDTO(OAuth2AccessTokenReqDTO tokenReqDTO) {

        if (tokenReqDTO == null || tokenReqDTO.getParameters() == null) {
            return Optional.empty();
        }

       String tenantDomainFromContext =
               tokenReqDTO.getParameters().get(OAuthConstants.TENANT_DOMAIN_FROM_CONTEXT);
        if (StringUtils.isNotBlank(tenantDomainFromContext)) {
            return Optional.of(tenantDomainFromContext);
        }
        return Optional.empty();
    }

    private static void startTenantFlow(String tenantDomain) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(IdentityTenantUtil.getTenantId(tenantDomain));
    }

    private static void endTenantFlow() {

        PrivilegedCarbonContext.endTenantFlow();
    }

    /**
     * Determines if the scope is specified in the allowed scopes list.
     *
     * @param allowedScopesList Allowed scopes list
     * @param scope             The scope key to check.
     * @return - 'true' if the scope is allowed. 'false' if not.
     */
    public static boolean isAllowedScope(List<String> allowedScopesList, String scope) {

        for (String scopeTobeSkipped : allowedScopesList) {
            if (scope.matches(scopeTobeSkipped)) {
                if (log.isDebugEnabled()) {
                    log.debug(scope + " is found in the allowed list of scopes.");
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Util method to get Identity Provider by name and tenant domain.
     *
     * @param identityProviderName Identity provider
     * @param tenantDomain         Tenant domain
     * @return Identity Provider
     * @throws IdentityOAuth2Exception If were unable to get Identity provider.
     */
    public static IdentityProvider getIdentityProvider(String identityProviderName, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            if (OAuth2ServiceComponentHolder.getInstance().getIdpManager() != null) {
                return OAuth2ServiceComponentHolder.getInstance().getIdpManager().getIdPByName(identityProviderName,
                        tenantDomain);
            } else {
                String errorMsg = String.format("Unable to retrieve Idp manager. Error while " +
                        "getting '%s' Identity  Provider of '%s' tenant.", identityProviderName, tenantDomain);
                throw new IdentityOAuth2Exception(errorMsg);
            }
        } catch (IdentityProviderManagementException e) {
            String errorMsg =
                    String.format("Error while getting '%s' Identity Provider of '%s' tenant.", identityProviderName,
                            tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Get Internal/everyone role for corresponding user using realm configuration.
     *
     * @param user Authenticated user
     * @return Internal/everyone role
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    public static String getInternalEveryoneRole(AuthenticatedUser user) throws IdentityOAuth2Exception {

        try {
            RealmConfiguration realmConfiguration;
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            int tenantId = getTenantId(user.getTenantDomain());
            if (realmService != null && tenantId != org.wso2.carbon.base.MultitenantConstants.INVALID_TENANT_ID) {
                UserStoreManager userStoreManager;
                userStoreManager = (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
                if (userStoreManager != null) {
                    realmConfiguration = userStoreManager.getRealmConfiguration();
                    return realmConfiguration.getEveryOneRoleName();
                }
            }
            return null;
        } catch (UserStoreException e) {
            String errorMsg =
                    "Error while getting Realm configuration of tenant " + user.getTenantDomain();
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Get a filtered set of scopes after dropping unregistered scopes.
     *
     * @param requestedScopesArr Array of requested scopes.
     * @param tenantDomain Tenant domain.
     * @return Filtered set of scopes after dropping unregistered scopes.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    public static String[] dropUnregisteredScopes(String[] requestedScopesArr, String tenantDomain)
            throws IdentityOAuth2Exception {

        if (ArrayUtils.isEmpty(requestedScopesArr)) {
            if (log.isDebugEnabled()) {
                log.debug("Scope string is empty. No scopes to check for unregistered scopes.");
            }
            return requestedScopesArr;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            String requestedScopes = StringUtils.join(requestedScopesArr, " ");
            Set<Scope> registeredScopeSet = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO()
                    .getRequestedScopesOnly(tenantId, true, requestedScopes);
            List<String> filteredScopes = new ArrayList<>();
            registeredScopeSet.forEach(scope -> filteredScopes.add(scope.getName()));

            if (log.isDebugEnabled()) {
                log.debug(String.format("Dropping unregistered scopes. Requested scopes: %s | Filtered result: %s",
                        requestedScopes,
                        StringUtils.join(filteredScopes, " ")));
            }
            return filteredScopes.toArray(new String[0]);
        } catch (IdentityOAuth2ScopeServerException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving registered scopes.", e);
        }
    }

    public static String resolveUsernameFromUserId(String tenantDomain, String userId) throws UserStoreException {

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();

        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

        AbstractUserStoreManager userStoreManager
                = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        return userStoreManager.getUserNameFromUserID(userId);
    }

    /**
     * Resolve tenant domain from the httpServlet request.
     *
     * @param request HttpServlet Request.
     * @return Tenant Domain.
     */
    public static String resolveTenantDomain(HttpServletRequest request) {

        if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return IdentityTenantUtil.resolveTenantDomain();
    }

    /**
     * Get user role list from federated user attributes.
     *
     * @param userAttributes User attribute.
     * @return User role-list.
     */
    public static List<String> getRolesFromFederatedUserAttributes(Map<ClaimMapping, String> userAttributes) {

        Optional<ClaimMapping> roleClaimMapping = Optional.ofNullable(userAttributes).get().entrySet().stream()
                .map(entry -> entry.getKey())
                .filter(claim -> StringUtils.equals(OIDC_ROLE_CLAIM_URI, claim.getRemoteClaim().getClaimUri()))
                .findFirst();

        if (roleClaimMapping.isPresent()) {
            return Arrays.asList(userAttributes.get(roleClaimMapping.get())
                    .split(Pattern.quote(FrameworkUtils.getMultiAttributeSeparator())));
        }

        return Collections.emptyList();
    }

    /**
     * Check federated role based authorization enabled or not.
     *
     * @param requestMsgCtx Token request message context.
     * @return Role based authz flow enabled or not.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    public static boolean isFederatedRoleBasedAuthzEnabled(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        return isFederatedRoleBasedAuthzEnabled(clientId);
    }

    /**
     * Check federated role based authorization enabled or not.
     *
     * @param oauthAuthzMsgCtx OAuth authorization request message context.
     * @return Role based authz flow enabled or not.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    public static boolean isFederatedRoleBasedAuthzEnabled(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        String clientId = oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey();
        return isFederatedRoleBasedAuthzEnabled(clientId);
    }

    /**
     * Check federated role based authorization enabled or not.
     *
     * @param clientId Application's client ID.
     * @return Role based authz flow enabled or not.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    public static boolean isFederatedRoleBasedAuthzEnabled(String clientId) throws IdentityOAuth2Exception {

        List<String> federatedRoleBasedAuthzApps = IdentityUtil.getPropertyAsList(FIDP_ROLE_BASED_AUTHZ_APP_CONFIG);
        boolean isFederatedRoleBasedAuthzEnabled = false;
        if (!federatedRoleBasedAuthzApps.isEmpty()) {
            OAuthAppDO app = null;
            try {
                app = getAppInformationByClientId(clientId);
            } catch (InvalidOAuthClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving the Application Information for client id: "
                            + clientId, e);
                }
                throw new IdentityOAuth2Exception(e.getMessage(), e);
            }
            String appTenantDomain = getTenantDomainOfOauthApp(app);
            if (StringUtils.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, appTenantDomain)
                    && federatedRoleBasedAuthzApps.contains(app.getApplicationName())) {
                isFederatedRoleBasedAuthzEnabled = true;
            }
        }
        return isFederatedRoleBasedAuthzEnabled;
    }

    /**
     * Get allowed grant type list for renewing token without revoking existing token.
     *
     * @return Allowed grant type list.
     */
    public static ArrayList<String> getJWTRenewWithoutRevokeAllowedGrantTypes() {

        ArrayList<String> allowedGrantTypes;
        Object value = IdentityConfigParser.getInstance().getConfiguration()
                .get(RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ALLOWED_GRANT_TYPES_CONFIG);
        if (value == null) {
            allowedGrantTypes = new ArrayList<>(Arrays.asList(OAuthConstants.GrantTypes.CLIENT_CREDENTIALS));
        } else if (value instanceof ArrayList) {
            allowedGrantTypes = (ArrayList) value;
        } else {
            allowedGrantTypes = new ArrayList<>(Collections.singletonList((String) value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Allowed grant types for renewing token without revoking existing token: " + allowedGrantTypes);
        }

        return allowedGrantTypes;
    }

    /**
     * Get the external consent page url configured for the tenant domain.
     *
     * @param tenantDomain Tenant Domain.
     * @return External consent page url.
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception.
     */
    public static String resolveExternalConsentPageUrl(String tenantDomain) throws IdentityOAuth2Exception {

        String externalConsentPageUrl = "";
        try {
            externalConsentPageUrl = OAuth2ServiceComponentHolder.getConsentServerConfigsManagementService()
                    .getExternalConsentPageUrl(tenantDomain);

        } catch (ConsentServerConfigsMgtException e) {
            throw new IdentityOAuth2Exception("Error while retrieving external consent page url from the " +
                    "configuration store for tenant domain : " + tenantDomain, e);
        }

        return externalConsentPageUrl;
    }

    /**
     * Check whether the application should be FAPI conformant.
     *
     * @param clientId       Client ID of the application.
     * @return Whether the application should be FAPI conformant.
     * @throws IdentityOAuth2Exception InvalidOAuthClientException
     */
    public static boolean isFapiConformantApp(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI))) {
            return false;
        }
        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
        return oAuthAppDO.isFapiConformanceEnabled();
    }

    /**
     * Check whether basic authorization header exists in a request.
     *
     * @param request Http servlet request.
     * @return True if basic authorization header exists.
     */
    public static boolean isBasicAuthorizationHeaderExists(HttpServletRequest request) {

        String authorizationHeader = request.getHeader(HTTPConstants.HEADER_AUTHORIZATION);
        if (StringUtils.isEmpty(authorizationHeader)) {
            authorizationHeader = request.getHeader(HTTPConstants.HEADER_AUTHORIZATION.toLowerCase());
        }
        /*
            authorizationHeader should be case-insensitive according to the
            "The 'Basic' HTTP Authentication Scheme" spec (https://tools.ietf.org/html/rfc7617#page-3),
            "Note that both scheme and parameter names are matched case-insensitively."
         */
        return StringUtils.isNotEmpty(authorizationHeader)
                && authorizationHeader.toUpperCase().startsWith(BASIC_AUTHORIZATION_PREFIX.toUpperCase());
    }

    /**
     * Get the oauth credentials from the oauth header.
     *
     * @param request Http servlet request.
     * @return An array of string credentials.
     * @throws OAuthClientAuthnException If an error occurs.
     */
    public static String[] extractCredentialsFromAuthzHeader(HttpServletRequest request)
            throws OAuthClientAuthnException {

        if (!isBasicAuthorizationHeaderExists(request)) {
            String errMsg = "Basic authorization header is not available in the request.";
            throw new OAuthClientAuthnException(errMsg, OAuth2ErrorCodes.INVALID_REQUEST);
        }

        String authorizationHeader = request.getHeader(HTTPConstants.HEADER_AUTHORIZATION);
        if (StringUtils.isEmpty(authorizationHeader)) {
            authorizationHeader = request.getHeader(HTTPConstants.HEADER_AUTHORIZATION.toLowerCase());
        }

        return OAuthUtils.decodeClientAuthenticationHeader(authorizationHeader);
    }
  
    /**
     * Retrieve the list of client authentication methods supported by the server.
     *
     * @return     Client authentication methods supported by the server.
     */
    public static String[] getSupportedClientAuthMethods() {

        HashSet<ClientAuthenticationMethodModel> clientAuthenticators = OAuth2Util.getSupportedAuthenticationMethods();
        HashSet<String> supportedClientAuthMethods = new HashSet<>();
        for (ClientAuthenticationMethodModel authMethod : clientAuthenticators) {
            supportedClientAuthMethods.add(authMethod.getName());
        }
        return supportedClientAuthMethods.toArray(new String[0]);
    }

    /**
     * Retrieve the list of client authentication methods supported by the server with the authenticator display name.
     *
     * @return     Client authentication methods supported by the server.
     */
    public static HashSet<ClientAuthenticationMethodModel> getSupportedAuthenticationMethods() {

        List<OAuthClientAuthenticator> clientAuthenticators = OAuth2ServiceComponentHolder.getAuthenticationHandlers();
        HashSet<ClientAuthenticationMethodModel> supportedClientAuthMethods = new HashSet<>();
        for (OAuthClientAuthenticator clientAuthenticator : clientAuthenticators) {
            List<ClientAuthenticationMethodModel> supportedAuthMethods = clientAuthenticator
                    .getSupportedClientAuthenticationMethods();
            if (!supportedAuthMethods.isEmpty()) {
                supportedClientAuthMethods.addAll(supportedAuthMethods);
            }
        }
        return supportedClientAuthMethods;
    }

    /**
     * Check if token persistence is enabled.
     *
     * @return True if token persistence is enabled.
     */
    public static boolean isTokenPersistenceEnabled() {

        if (IdentityUtil.getProperty(OAuth2Constants.OAUTH_TOKEN_PERSISTENCE_ENABLE) != null) {
            return Boolean.parseBoolean(IdentityUtil.getProperty(OAuth2Constants.OAUTH_TOKEN_PERSISTENCE_ENABLE));
        }
        return OAuth2Constants.DEFAULT_PERSIST_ENABLED;
    }

    /**
     * Resolves the grant type from the response type for implicit and hybrid flows.
     *
     * @param responseType Response type Eg: token, id_token
     * @return Grant type
     */
    public static String getGrantType(String responseType) {

        String grantType;
        if (StringUtils.contains(responseType, OAuthConstants.GrantTypes.TOKEN)) {
            // This sets the grant type for implicit when response_type contains 'token' or 'id_token'.
            grantType = OAuthConstants.GrantTypes.IMPLICIT;
        } else {
            grantType = responseType;
        }
        return grantType;
    }

    /**
     * Retrieve the list of token binding types supported by the server.
     *
     * @return     Token binding types supported by the server.
     */
    public static List<String> getSupportedTokenBindingTypes() {

        List<TokenBindingMetaDataDTO> supportedTokenBindings = OAuthComponentServiceHolder.getInstance()
                .getTokenBindingMetaDataDTOs();
        List<String> supportedBindingTypes = new ArrayList<>();
        for (TokenBindingMetaDataDTO tokenBindingMetaDataDTO : supportedTokenBindings) {
            supportedBindingTypes.add(tokenBindingMetaDataDTO.getTokenBindingType());
        }
        return supportedBindingTypes;
    }

    /**
     * Utility method to check if server compatible with client ID tenant unification.
     * With the client ID tenant unification, the OAuth client ID will be unique only for the tenant. This
     * requires enabling both the tenant qualified URLs and tenanted sessions. If any of these configs are disabled,
     * the IDN_OAUTH_CONSUMER_APPS table need to have a unique key constraint for the consumer_key column.
     *
     * @return true if compliant.
     */
    public static boolean isCompliantWithClientIDTenantUnification() throws IdentityOAuth2Exception {

        boolean isClientIdUnique = new OAuthAppDAO().isClientIDUniqueConstraintExistsInConsumerAppsTable();

        if (isClientIdUnique) {
            return true;
        } else {
            return IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && IdentityTenantUtil.isTenantedSessionsEnabled();
        }
    }

    /**
     * Check if oauth code persistence is enabled.
     *
     * @return True if oauth code persistence is enabled.
     */
    public static boolean isAuthCodePersistenceEnabled() {

        if (IdentityUtil.getProperty(OAuth2Constants.OAUTH_CODE_PERSISTENCE_ENABLE) != null) {
            return Boolean.parseBoolean(IdentityUtil.getProperty(OAuth2Constants.OAUTH_CODE_PERSISTENCE_ENABLE));
        }
        return OAuth2Constants.DEFAULT_PERSIST_ENABLED;
    }

    /**
     * Check if revoke token headers is enabled.
     *
     * @return True if oauth code persistence is enabled.
     */
    public static boolean isRevokeTokenHeadersEnabled() {

        if (IdentityUtil.getProperty(OAuth2Constants.OAUTH_ENABLE_REVOKE_TOKEN_HEADERS) != null) {
            return Boolean.parseBoolean(IdentityUtil.getProperty(OAuth2Constants.OAUTH_ENABLE_REVOKE_TOKEN_HEADERS));
        }
        return true;
    }
}
