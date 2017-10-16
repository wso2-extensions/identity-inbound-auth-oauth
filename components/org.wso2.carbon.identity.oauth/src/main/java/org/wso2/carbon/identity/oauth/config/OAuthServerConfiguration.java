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

package org.wso2.carbon.identity.oauth.config;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.util.JavaUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.issuer.UUIDValueGenerator;
import org.apache.oltu.oauth2.as.issuer.ValueGenerator;
import org.apache.oltu.oauth2.as.validator.AuthorizationCodeValidator;
import org.apache.oltu.oauth2.as.validator.ClientCredentialValidator;
import org.apache.oltu.oauth2.as.validator.CodeValidator;
import org.apache.oltu.oauth2.as.validator.PasswordValidator;
import org.apache.oltu.oauth2.as.validator.RefreshTokenValidator;
import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.IDTokenResponseValidator;
import org.wso2.carbon.identity.oauth.common.IDTokenTokenResponseValidator;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.SAML2GrantValidator;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.oauth2.token.handlers.clientauth.ClientAuthenticationHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2TokenCallbackHandler;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeHandler;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

/**
 * Runtime representation of the OAuth Configuration as configured through
 * identity.xml
 */
public class OAuthServerConfiguration {

    private static final String CONFIG_ELEM_OAUTH = "OAuth";
    // Grant Handler Classes
    private static final String AUTHORIZATION_CODE_GRANT_HANDLER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationCodeHandler";
    private static final String CLIENT_CREDENTIALS_GRANT_HANDLER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.ClientCredentialsGrantHandler";
    private static final String PASSWORD_GRANT_HANDLER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler";
    private static final String REFRESH_TOKEN_GRANT_HANDLER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler";
    private static final String SAML20_BEARER_GRANT_HANDLER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2BearerGrantHandler";
    private static final String IWA_NTLM_BEARER_GRANT_HANDLER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.NTLMAuthenticationGrantHandler";
    private static Log log = LogFactory.getLog(OAuthServerConfiguration.class);
    private static OAuthServerConfiguration instance;
    private static String oauth1RequestTokenUrl = null;
    private static String oauth1AuthorizeUrl = null;
    private static String oauth1AccessTokenUrl = null;
    private static String oauth2AuthzEPUrl = null;
    private static String oauth2TokenEPUrl = null;
    private static String oauth2UserInfoEPUrl = null;
    private static String oidcConsentPageUrl = null;
    private static String oauth2DCREPUrl = null;
    private static String oauth2JWKSPageUrl = null;
    private static String oidcWebFingerEPUrl = null;
    private static String oidcDiscoveryUrl = null;
    private static String oauth2ConsentPageUrl = null;
    private static String oauth2ErrorPageUrl = null;
    private long authorizationCodeValidityPeriodInSeconds = 300;
    private long userAccessTokenValidityPeriodInSeconds = 3600;
    private long applicationAccessTokenValidityPeriodInSeconds = 3600;
    private long refreshTokenValidityPeriodInSeconds = 24L * 3600;
    private long timeStampSkewInSeconds = 300;
    private String tokenPersistenceProcessorClassName = "org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor";
    private String oauthTokenGeneratorClassName;
    private OAuthIssuer oauthTokenGenerator;
    private String oauthIdentityTokenGeneratorClassName;
    private OauthTokenIssuer oauthIdentityTokenGenerator;
    private boolean cacheEnabled = false;
    private boolean isRefreshTokenRenewalEnabled = true;
    private boolean assertionsUserNameEnabled = false;
    private boolean accessTokenPartitioningEnabled = false;
    private String accessTokenPartitioningDomains = null;
    private TokenPersistenceProcessor persistenceProcessor = null;
    private Set<OAuthCallbackHandlerMetaData> callbackHandlerMetaData = new HashSet<>();
    private Map<String, String> supportedGrantTypeClassNames = new HashMap<>();
    private Map<String, Boolean> refreshTokenAllowedGrantTypes = new HashMap<>();
    private Map<String, String> idTokenAllowedForGrantTypesMap = new HashMap<>();
    private Set<String> idTokenNotAllowedGrantTypesSet = new HashSet<>();
    private Map<String, AuthorizationGrantHandler> supportedGrantTypes;
    private Map<String, String> supportedGrantTypeValidatorNames = new HashMap<>();
    private Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> supportedGrantTypeValidators;
    private Map<String, String> supportedResponseTypeClassNames = new HashMap<>();
    private Map<String, ResponseTypeHandler> supportedResponseTypes;
    private Map<String, String> supportedResponseTypeValidatorNames = new HashMap<>();
    private Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> supportedResponseTypeValidators;
    private String[] supportedClaims = null;
    private Map<String, Properties> supportedClientAuthHandlerData = new HashMap<>();
    private List<ClientAuthenticationHandler> supportedClientAuthHandlers;
    private String saml2TokenCallbackHandlerName = null;
    private String saml2BearerTokenUserType;
    private boolean mapFederatedUsersToLocal = false;
    private SAML2TokenCallbackHandler saml2TokenCallbackHandler = null;
    private Map<String, String> tokenValidatorClassNames = new HashMap();
    private boolean isAuthContextTokGenEnabled = false;
    private String tokenGeneratorImplClass = "org.wso2.carbon.identity.oauth2.token.JWTTokenGenerator";
    private String claimsRetrieverImplClass = "org.wso2.carbon.identity.oauth2.token.DefaultClaimsRetriever";
    private String consumerDialectURI = "http://wso2.org/claims";
    private String signatureAlgorithm = "SHA256withRSA";
    private String idTokenSignatureAlgorithm = "SHA256withRSA";
    private String userInfoJWTSignatureAlgorithm = "SHA256withRSA";
    private String authContextTTL = "15L";
    // property added to fix IDENTITY-4551 in backward compatible manner
    private boolean useMultiValueSeparatorForAuthContextToken = true;

    // OpenID Connect configurations
    private String openIDConnectIDTokenBuilderClassName = "org.wso2.carbon.identity.openidconnect.DefaultIDTokenBuilder";
    private String openIDConnectIDTokenCustomClaimsHanlderClassName = "org.wso2.carbon.identity.openidconnect.SAMLAssertionClaimsCallback";
    private IDTokenBuilder openIDConnectIDTokenBuilder = null;
    private CustomClaimsCallbackHandler openidConnectIDTokenCustomClaimsCallbackHandler = null;
    private String openIDConnectIDTokenIssuerIdentifier = null;
    private String openIDConnectIDTokenSubClaim = "http://wso2.org/claims/fullname";
    private String openIDConnectSkipUserConsent = "true";
    private String openIDConnectIDTokenExpiration = "300";
    private String openIDConnectUserInfoEndpointClaimDialect = "http://wso2.org/claims";
    private String openIDConnectUserInfoEndpointClaimRetriever = "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoUserStoreClaimRetriever";
    private String openIDConnectUserInfoEndpointRequestValidator = "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInforRequestDefaultValidator";
    private String openIDConnectUserInfoEndpointAccessTokenValidator = "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoISAccessTokenValidator";
    private String openIDConnectUserInfoEndpointResponseBuilder = "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoJSONResponseBuilder";
    private OAuth2ScopeValidator oAuth2ScopeValidator;
    private Set<OAuth2ScopeValidator> oAuth2ScopeValidators = new HashSet<>();
    private Set<OAuth2ScopeHandler> oAuth2ScopeHandlers = new HashSet<>();
    // property added to fix IDENTITY-4492 in backward compatible manner
    private boolean isJWTSignedWithSPKey = false;
    // property added to fix IDENTITY-4534 in backward compatible manner
    private boolean isImplicitErrorFragment = true;

    // property added to fix IDENTITY-4112 in backward compatible manner
    private boolean isRevokeResponseHeadersEnabled = true;

    // Use the SP tenant domain instead of user domain.
    private boolean useSPTenantDomainValue;

    // Property added to customize the token valued generation method. (IDENTITY-6139)
    private ValueGenerator tokenValueGenerator;
    private String tokenValueGeneratorClassName;

    private OAuthServerConfiguration() {
        buildOAuthServerConfiguration();
    }

    public static OAuthServerConfiguration getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OAuthServerConfiguration.class) {
                if (instance == null) {
                    instance = new OAuthServerConfiguration();
                }
            }
        }
        return instance;
    }

    private void buildOAuthServerConfiguration() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

        if (oauthElem == null) {
            warnOnFaultyConfiguration("OAuth element is not available.");
            return;
        }

        // read callback handler configurations
        parseOAuthCallbackHandlers(oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.OAUTH_CALLBACK_HANDLERS)));

        // get the token validators by type
        parseTokenValidators(oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.TOKEN_VALIDATORS)));

        // Get the configured jdbc scope validator
        OMElement scopeValidatorElem = oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.SCOPE_VALIDATOR));

        //Get the configured scope validators
        OMElement scopeValidatorsElem = oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.SCOPE_VALIDATORS));

        if (scopeValidatorElem != null) {
            parseScopeValidator(scopeValidatorElem);
        } else if (scopeValidatorsElem != null) {
            parseScopeValidator(scopeValidatorsElem);
        }

        //Get the configured scope handlers
        OMElement scopeHandlersElem = oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.SCOPE_HANDLERS));

        if (scopeHandlersElem != null) {
            parseScopeHandlers(scopeHandlersElem);
        }

        // read default timeout periods
        parseDefaultValidityPeriods(oauthElem);

        // read OAuth URLs
        parseOAuthURLs(oauthElem);

        // read refresh token renewal config
        parseRefreshTokenRenewalConfiguration(oauthElem);

        // read token persistence processor config
        parseTokenPersistenceProcessorConfig(oauthElem);

        // read supported grant types
        parseSupportedGrantTypesConfig(oauthElem);

        // read supported response types
        parseSupportedResponseTypesConfig(oauthElem);

        // read supported response types
        parseSupportedClientAuthHandlersConfig(oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.CLIENT_AUTH_HANDLERS)));

        // read SAML2 grant config
        parseSAML2GrantConfig(oauthElem);

        // read JWT generator config
        parseAuthorizationContextTokenGeneratorConfig(oauthElem);

        // read the assertions user name config
        parseEnableAssertionsUserNameConfig(oauthElem);

        // read access token partitioning config
        parseAccessTokenPartitioningConfig(oauthElem);

        // read access token partitioning domains config
        parseAccessTokenPartitioningDomainsConfig(oauthElem);

        // read openid connect configurations
        parseOpenIDConnectConfig(oauthElem);

        // parse OAuth 2.0 token generator
        parseOAuthTokenGeneratorConfig(oauthElem);

        // parse OAuth2 implicit grant error in fragment property for backward compatibility
        parseImplicitErrorFragment(oauthElem);

        // parse identity OAuth 2.0 token generator
        parseOAuthTokenIssuerConfig(oauthElem);

        // Parse token value generator class name.
        parseOAuthTokenValueGenerator(oauthElem);

        // Read the value of UseSPTenantDomain config.
        parseUseSPTenantDomainConfig(oauthElem);

        parseRevokeResponseHeadersEnableConfig(oauthElem);
    }

    public Set<OAuthCallbackHandlerMetaData> getCallbackHandlerMetaData() {
        return callbackHandlerMetaData;
    }

    public String getOAuth1RequestTokenUrl() {
        return oauth1RequestTokenUrl;
    }

    public String getOAuth1AuthorizeUrl() {
        return oauth1AuthorizeUrl;
    }

    public String getOAuth1AccessTokenUrl() {
        return oauth1AccessTokenUrl;
    }

    public String getOAuth2AuthzEPUrl() {
        return oauth2AuthzEPUrl;
    }

    public String getOAuth2TokenEPUrl() {
        return oauth2TokenEPUrl;
    }

    public String getOAuth2DCREPUrl() {
        return oauth2DCREPUrl;
    }

    public String getOAuth2JWKSPageUrl() {
        return oauth2JWKSPageUrl;
    }

    public String getOidcDiscoveryUrl() {
        return oidcDiscoveryUrl;
    }

    public String getOidcWebFingerEPUrl() {
        return oidcWebFingerEPUrl;
    }

    public String getOauth2UserInfoEPUrl() {
        return oauth2UserInfoEPUrl;
    }

    /**
     * instantiate the OAuth token generator. to override the default implementation, one can specify the custom class
     * in the identity.xml.
     *
     * @return
     */
    public OAuthIssuer getOAuthTokenGenerator() {

        if (oauthTokenGenerator == null) {
            synchronized (this) {
                if (oauthTokenGenerator == null) {
                    try {
                        if (oauthTokenGeneratorClassName != null) {
                            Class clazz = this.getClass().getClassLoader().loadClass(oauthTokenGeneratorClassName);
                            oauthTokenGenerator = (OAuthIssuer) clazz.newInstance();
                            log.info("An instance of " + oauthTokenGeneratorClassName
                                    + " is created for OAuth token generation.");
                        } else {
                            oauthTokenGenerator = new OAuthIssuerImpl(getTokenValueGenerator());
                            log.info("The default OAuth token issuer will be used. No custom token generator is set.");
                        }
                    } catch (Exception e) {
                        String errorMsg = "Error when instantiating the OAuthIssuer : "
                                + tokenPersistenceProcessorClassName + ". Defaulting to OAuthIssuerImpl";
                        log.error(errorMsg, e);
                        oauthTokenGenerator = new OAuthIssuerImpl(getTokenValueGenerator());
                    }
                }
            }
        }
        return oauthTokenGenerator;
    }

    /**
     * Get the instance of the token value generator according to the identity xml configuration value.
     *
     * @return ValueGenerator object instance.
     */
    public ValueGenerator getTokenValueGenerator() {

        if (tokenValueGenerator == null) {
            synchronized (this) {
                if (tokenValueGenerator == null) {
                    try {
                        if (tokenValueGeneratorClassName != null) {
                            Class clazz = this.getClass().getClassLoader().loadClass(tokenValueGeneratorClassName);
                            tokenValueGenerator = (ValueGenerator) clazz.newInstance();
                            if (log.isDebugEnabled()) {
                                log.debug("An instance of " + tokenValueGeneratorClassName + " is created.");
                            }
                        } else {
                            tokenValueGenerator = new UUIDValueGenerator();
                            if (log.isDebugEnabled()) {
                                log.debug("Default token value generator UUIDValueGenerator will be used.");
                            }
                        }
                    } catch (Exception e) {
                        log.error("Error while initiating the token value generator :" + tokenValueGeneratorClassName +
                                ". Defaulting to UUIDValueGenerator.", e);
                        tokenValueGenerator = new UUIDValueGenerator();
                    }
                }
            }
        }

        return tokenValueGenerator;
    }

    public OauthTokenIssuer getIdentityOauthTokenIssuer() {
        if (oauthIdentityTokenGenerator == null) {
            synchronized (this) {
                if (oauthIdentityTokenGenerator == null) {
                    try {
                        if (oauthIdentityTokenGeneratorClassName != null) {
                            Class clazz = this.getClass().getClassLoader().loadClass
                                    (oauthIdentityTokenGeneratorClassName);
                            oauthIdentityTokenGenerator = (OauthTokenIssuer) clazz.newInstance();
                            log.info("An instance of " + oauthIdentityTokenGeneratorClassName
                                    + " is created for Identity OAuth token generation.");
                        } else {
                            oauthIdentityTokenGenerator = new OauthTokenIssuerImpl();
                            log.info("The default Identity OAuth token issuer will be used. No custom token generator" +
                                    " is set.");
                        }
                    } catch (Exception e) {
                        String errorMsg = "Error when instantiating the OAuthIssuer : "
                                + tokenPersistenceProcessorClassName + ". Defaulting to OAuthIssuerImpl";
                        log.error(errorMsg, e);
                        oauthIdentityTokenGenerator = new OauthTokenIssuerImpl();
                    }
                }
            }
        }
        return oauthIdentityTokenGenerator;
    }

    public String getOIDCConsentPageUrl() {
        return oidcConsentPageUrl;
    }

    public String getOauth2ConsentPageUrl() {
        return oauth2ConsentPageUrl;
    }

    public String getOauth2ErrorPageUrl() {
        return oauth2ErrorPageUrl;
    }

    public long getAuthorizationCodeValidityPeriodInSeconds() {
        return authorizationCodeValidityPeriodInSeconds;
    }

    public long getUserAccessTokenValidityPeriodInSeconds() {
        return userAccessTokenValidityPeriodInSeconds;
    }

    public long getApplicationAccessTokenValidityPeriodInSeconds() {
        return applicationAccessTokenValidityPeriodInSeconds;
    }

    public long getRefreshTokenValidityPeriodInSeconds() {
        return refreshTokenValidityPeriodInSeconds;
    }

    public long getTimeStampSkewInSeconds() {
        return timeStampSkewInSeconds;
    }

    /**
     * @deprecated  From v5.1.3 use @{@link BaseCache#isEnabled()} to check whether a cache is enabled or not instead
     * of relying on <EnableOAuthCache> global Cache config
     */
    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public boolean isRefreshTokenRenewalEnabled() {
        return isRefreshTokenRenewalEnabled;
    }

    public Map<String, AuthorizationGrantHandler> getSupportedGrantTypes() {
        if (supportedGrantTypes == null) {
            synchronized (this) {
                if (supportedGrantTypes == null) {
                    Map<String, AuthorizationGrantHandler> supportedGrantTypesTemp = new HashMap<>();
                    for (Map.Entry<String, String> entry : supportedGrantTypeClassNames.entrySet()) {
                        AuthorizationGrantHandler authzGrantHandler = null;
                        try {
                            authzGrantHandler = (AuthorizationGrantHandler) Class.forName(entry.getValue()).newInstance();
                            authzGrantHandler.init();
                        } catch (InstantiationException e) {
                            log.error("Error instantiating " + entry.getValue(), e);
                        } catch (IllegalAccessException e) {
                            log.error("Illegal access to " + entry.getValue(), e);
                        } catch (ClassNotFoundException e) {
                            log.error("Cannot find class: " + entry.getValue(), e);
                        } catch (IdentityOAuth2Exception e) {
                            log.error("Error while initializing " + entry.getValue(), e);
                        }

                        if (authzGrantHandler != null) {
                            supportedGrantTypesTemp.put(entry.getKey(), authzGrantHandler);
                        } else {
                            log.warn("Grant type : " + entry.getKey() + ", is not added as a supported grant type. "
                                    + "Relevant grant handler failed to initiate properly.");
                        }
                    }
                    supportedGrantTypes = supportedGrantTypesTemp;
                }
            }
        }
        return supportedGrantTypes;
    }

    /**
     * Returns a map of supported grant type validators that are configured in identity.xml.
     * This method loads default grant type validator classes for PASSWORD, CLIENT_CREDENTIALS, AUTHORIZATION_CODE,
     * REFRESH_TOKEN and SAML20_BEARER grant types and also loads validator classes configured in identity.xml for
     * custom grant types under /Server/OAuth/SupportedGrantTypes/GrantTypeValidatorImplClass element.
     * A validator class defined under this element should be an implementation of org.apache.amber.oauth2.common
     * .validators.OAuthValidator
     *
     * @return a map of <Grant type, Oauth validator class>
     */
    public Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> getSupportedGrantTypeValidators() {

        if (supportedGrantTypeValidators == null) {
            synchronized (this) {
                if (supportedGrantTypeValidators == null) {
                    Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> supportedGrantTypeValidatorsTemp =
                            new Hashtable<>();
                    // Load default grant type validators
                    supportedGrantTypeValidatorsTemp
                            .put(GrantType.PASSWORD.toString(), PasswordValidator.class);
                    supportedGrantTypeValidatorsTemp.put(GrantType.CLIENT_CREDENTIALS.toString(),
                            ClientCredentialValidator.class);
                    supportedGrantTypeValidatorsTemp.put(GrantType.AUTHORIZATION_CODE.toString(),
                            AuthorizationCodeValidator.class);
                    supportedGrantTypeValidatorsTemp.put(GrantType.REFRESH_TOKEN.toString(),
                            RefreshTokenValidator.class);
                    supportedGrantTypeValidatorsTemp.put(
                            org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER
                                    .toString(), SAML2GrantValidator.class);

                    if (supportedGrantTypeValidatorNames != null) {
                        // Load configured grant type validators
                        for (Map.Entry<String, String> entry : supportedGrantTypeValidatorNames.entrySet()) {
                            try {
                                @SuppressWarnings("unchecked")
                                Class<? extends OAuthValidator<HttpServletRequest>>
                                        oauthValidatorClass =
                                        (Class<? extends OAuthValidator<HttpServletRequest>>) Class
                                                .forName(entry.getValue());
                                supportedGrantTypeValidatorsTemp
                                        .put(entry.getKey(), oauthValidatorClass);
                            } catch (ClassNotFoundException e) {
                                log.error("Cannot find class: " + entry.getValue(), e);
                            } catch (ClassCastException e) {
                                log.error("Cannot cast class: " + entry.getValue(), e);
                            }
                        }
                    }
                    supportedGrantTypeValidators = supportedGrantTypeValidatorsTemp;
                }
            }
        }

        return supportedGrantTypeValidators;
    }

    public Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> getSupportedResponseTypeValidators() {

        if (supportedResponseTypeValidators == null) {
            synchronized (this) {
                if (supportedResponseTypeValidators == null) {
                    Map<String, Class<? extends OAuthValidator<HttpServletRequest>>>
                            supportedResponseTypeValidatorsTemp = new Hashtable<>();
                    // Load default grant type validators
                    supportedResponseTypeValidatorsTemp
                            .put(ResponseType.CODE.toString(), CodeValidator.class);
                    supportedResponseTypeValidatorsTemp.put(ResponseType.TOKEN.toString(),
                            TokenValidator.class);
                    supportedResponseTypeValidatorsTemp.put("id_token", IDTokenResponseValidator.class);
                    supportedResponseTypeValidatorsTemp.put("id_token token", IDTokenTokenResponseValidator.class);


                    if (supportedResponseTypeValidatorNames != null) {
                        // Load configured grant type validators
                        for (Map.Entry<String, String> entry : supportedResponseTypeValidatorNames
                                .entrySet()) {
                            try {
                                @SuppressWarnings("unchecked")
                                Class<? extends OAuthValidator<HttpServletRequest>>
                                        oauthValidatorClass =
                                        (Class<? extends OAuthValidator<HttpServletRequest>>) Class
                                                .forName(entry.getValue());
                                supportedResponseTypeValidatorsTemp
                                        .put(entry.getKey(), oauthValidatorClass);
                            } catch (ClassNotFoundException e) {
                                log.error("Cannot find class: " + entry.getValue(), e);
                            } catch (ClassCastException e) {
                                log.error("Cannot cast class: " + entry.getValue(), e);
                            }
                        }
                        supportedResponseTypeValidators = supportedResponseTypeValidatorsTemp;
                    }
                }
            }
        }

        return supportedResponseTypeValidators;
    }

    public Map<String, ResponseTypeHandler> getSupportedResponseTypes() {
        if (supportedResponseTypes == null) {
            synchronized (this) {
                if (supportedResponseTypes == null) {
                    Map<String, ResponseTypeHandler> supportedResponseTypesTemp = new Hashtable<>();
                    for (Map.Entry<String, String> entry : supportedResponseTypeClassNames.entrySet()) {
                        ResponseTypeHandler responseTypeHandler = null;
                        try {
                            responseTypeHandler = (ResponseTypeHandler) Class.forName(entry.getValue()).newInstance();
                            responseTypeHandler.init();
                        } catch (InstantiationException e) {
                            log.error("Error instantiating " + entry.getValue(), e);
                        } catch (IllegalAccessException e) {
                            log.error("Illegal access to " + entry.getValue(), e);
                        } catch (ClassNotFoundException e) {
                            log.error("Cannot find class: " + entry.getValue(), e);
                        } catch (IdentityOAuth2Exception e) {
                            log.error("Error while initializing " + entry.getValue(), e);
                        }
                        supportedResponseTypesTemp.put(entry.getKey(), responseTypeHandler);
                    }
                    supportedResponseTypes = supportedResponseTypesTemp;
                }
            }
        }
        return supportedResponseTypes;
    }

    public Set<String> getSupportedResponseTypeNames() {
        return supportedResponseTypeClassNames.keySet();
    }

    public String[] getSupportedClaims() {
        return supportedClaims;
    }

    public List<ClientAuthenticationHandler> getSupportedClientAuthHandlers() {
        if (supportedClientAuthHandlers == null) {
            synchronized (this) {
                if (supportedClientAuthHandlers == null) {
                    List<ClientAuthenticationHandler> supportedClientAuthHandlersTemp = new ArrayList<>();

                    for (Map.Entry<String, Properties> entry : supportedClientAuthHandlerData.entrySet()) {
                        ClientAuthenticationHandler clientAuthenticationHandler = null;
                        try {
                            clientAuthenticationHandler = (ClientAuthenticationHandler)
                                    Class.forName(entry.getKey()).newInstance();
                            clientAuthenticationHandler.init(entry.getValue());
                            supportedClientAuthHandlersTemp.add(clientAuthenticationHandler);

                            //Exceptions necessarily don't have to break the flow since there are cases
                            //runnable without client auth handlers
                        } catch (InstantiationException e) {
                            log.error("Error instantiating " + entry, e);
                        } catch (IllegalAccessException e) {
                            log.error("Illegal access to " + entry, e);
                        } catch (ClassNotFoundException e) {
                            log.error("Cannot find class: " + entry, e);
                        } catch (IdentityOAuth2Exception e) {
                            log.error("Error while initializing " + entry, e);
                        }
                        supportedClientAuthHandlers = supportedClientAuthHandlersTemp;
                    }
                }
            }
        }
        return supportedClientAuthHandlers;
    }

    public SAML2TokenCallbackHandler getSAML2TokenCallbackHandler() {

        if (StringUtils.isBlank(saml2TokenCallbackHandlerName)) {
            return null;
        }
        if (saml2TokenCallbackHandler == null) {
            synchronized (SAML2TokenCallbackHandler.class) {
                if (saml2TokenCallbackHandler == null) {
                    try {
                        Class clazz =
                                Thread.currentThread().getContextClassLoader()
                                        .loadClass(saml2TokenCallbackHandlerName);
                        saml2TokenCallbackHandler = (SAML2TokenCallbackHandler) clazz.newInstance();
                    } catch (ClassNotFoundException e) {
                        log.error("Error while instantiating the SAML2TokenCallbackHandler ", e);
                    } catch (InstantiationException e) {
                        log.error("Error while instantiating the SAML2TokenCallbackHandler ", e);
                    } catch (IllegalAccessException e) {
                        log.error("Error while instantiating the SAML2TokenCallbackHandler ", e);
                    }
                }
            }
        }
        return saml2TokenCallbackHandler;
    }

    public Map<String, String> getTokenValidatorClassNames() {
        return tokenValidatorClassNames;
    }

    public boolean isAccessTokenPartitioningEnabled() {
        return accessTokenPartitioningEnabled;
    }

    public Map<String, String> getIdTokenAllowedForGrantTypesMap() {
        return idTokenAllowedForGrantTypesMap;
    }

    public Set<String> getIdTokenNotAllowedGrantTypesSet() {
        return idTokenNotAllowedGrantTypesSet;
    }

    public boolean isUserNameAssertionEnabled() {
        return assertionsUserNameEnabled;
    }

    public String getAccessTokenPartitioningDomains() {
        return accessTokenPartitioningDomains;
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    public boolean isAuthContextTokGenEnabled() {
        return isAuthContextTokGenEnabled;
    }

    public String getTokenGeneratorImplClass() {
        return tokenGeneratorImplClass;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getIdTokenSignatureAlgorithm() {
        return idTokenSignatureAlgorithm;
    }

    public String getUserInfoJWTSignatureAlgorithm() {
        return userInfoJWTSignatureAlgorithm;
    }

    public String getConsumerDialectURI() {
        return consumerDialectURI;
    }

    public String getClaimsRetrieverImplClass() {
        return claimsRetrieverImplClass;
    }

    public String getAuthorizationContextTTL() {
        return authContextTTL;
    }

    public boolean isUseMultiValueSeparatorForAuthContextToken() {
        return useMultiValueSeparatorForAuthContextToken;
    }

    public TokenPersistenceProcessor getPersistenceProcessor() throws IdentityOAuth2Exception {
        if (persistenceProcessor == null) {
            synchronized (this) {
                if (persistenceProcessor == null) {
                    try {
                        Class clazz =
                                this.getClass().getClassLoader()
                                        .loadClass(tokenPersistenceProcessorClassName);
                        persistenceProcessor = (TokenPersistenceProcessor) clazz.newInstance();

                        if (log.isDebugEnabled()) {
                            log.debug("An instance of " + tokenPersistenceProcessorClassName +
                                    " is created for OAuthServerConfiguration.");
                        }

                    } catch (Exception e) {
                        String errorMsg =
                                "Error when instantiating the TokenPersistenceProcessor : " +
                                        tokenPersistenceProcessorClassName + ". Defaulting to PlainTextPersistenceProcessor";
                        log.error(errorMsg, e);
                        persistenceProcessor = new PlainTextPersistenceProcessor();
                    }
                }
            }
        }
        return persistenceProcessor;
    }

    /**
     * Return an instance of the IDToken builder
     *
     * @return
     */
    public IDTokenBuilder getOpenIDConnectIDTokenBuilder() {
        if (openIDConnectIDTokenBuilder == null) {
            synchronized (IDTokenBuilder.class) {
                if (openIDConnectIDTokenBuilder == null) {
                    try {
                        Class clazz =
                                Thread.currentThread().getContextClassLoader()
                                        .loadClass(openIDConnectIDTokenBuilderClassName);
                        openIDConnectIDTokenBuilder = (IDTokenBuilder) clazz.newInstance();
                    } catch (ClassNotFoundException e) {
                        log.error("Error while instantiating the IDTokenBuilder ", e);
                    } catch (InstantiationException e) {
                        log.error("Error while instantiating the IDTokenBuilder ", e);
                    } catch (IllegalAccessException e) {
                        log.error("Error while instantiating the IDTokenBuilder ", e);
                    }
                }
            }
        }
        return openIDConnectIDTokenBuilder;
    }

    /**
     * Returns the custom claims builder for the IDToken
     *
     * @return
     */
    public CustomClaimsCallbackHandler getOpenIDConnectCustomClaimsCallbackHandler() {
        if (openidConnectIDTokenCustomClaimsCallbackHandler == null) {
            synchronized (CustomClaimsCallbackHandler.class) {
                if (openidConnectIDTokenCustomClaimsCallbackHandler == null) {
                    try {
                        Class clazz =
                                Thread.currentThread().getContextClassLoader()
                                        .loadClass(openIDConnectIDTokenCustomClaimsHanlderClassName);
                        openidConnectIDTokenCustomClaimsCallbackHandler = (CustomClaimsCallbackHandler) clazz.newInstance();
                    } catch (ClassNotFoundException e) {
                        log.error("Error while instantiating the IDTokenBuilder ", e);
                    } catch (InstantiationException e) {
                        log.error("Error while instantiating the IDTokenBuilder ", e);
                    } catch (IllegalAccessException e) {
                        log.error("Error while instantiating the IDTokenBuilder ", e);
                    }
                }
            }
        }
        return openidConnectIDTokenCustomClaimsCallbackHandler;
    }

    /**
     * @return the openIDConnectIDTokenIssuer
     */
    public String getOpenIDConnectIDTokenIssuerIdentifier() {
        return openIDConnectIDTokenIssuerIdentifier;
    }

    public String getOpenIDConnectIDTokenSubjectClaim() {
        return openIDConnectIDTokenSubClaim;
    }

    /**
     * Returns if skip user consent enabled or not
     *
     * @return
     */
    public boolean getOpenIDConnectSkipeUserConsentConfig() {
        return "true".equalsIgnoreCase(openIDConnectSkipUserConsent);
    }

    /**
     * @return the openIDConnectIDTokenExpiration
     */
    public String getOpenIDConnectIDTokenExpiration() {
        return openIDConnectIDTokenExpiration;
    }

    public String getOpenIDConnectUserInfoEndpointClaimDialect() {
        return openIDConnectUserInfoEndpointClaimDialect;
    }

    public String getOpenIDConnectUserInfoEndpointClaimRetriever() {
        return openIDConnectUserInfoEndpointClaimRetriever;
    }

    public String getOpenIDConnectUserInfoEndpointRequestValidator() {
        return openIDConnectUserInfoEndpointRequestValidator;
    }

    public String getOpenIDConnectUserInfoEndpointAccessTokenValidator() {
        return openIDConnectUserInfoEndpointAccessTokenValidator;
    }

    public String getOpenIDConnectUserInfoEndpointResponseBuilder() {
        return openIDConnectUserInfoEndpointResponseBuilder;
    }

    public boolean isJWTSignedWithSPKey() {
        return isJWTSignedWithSPKey;
    }

    public boolean isImplicitErrorFragment() {
        return isImplicitErrorFragment;
    }

    public boolean isRevokeResponseHeadersEnabled() {
        return isRevokeResponseHeadersEnabled;
    }

    /**
     * Return the value of whether the refresh token is allowed for this grant type. Null will be returned if there is
     * no tag or empty tag.
     *
     * @param grantType Name of the Grant type.
     * @return True or False if there is a value. Null otherwise.
     */
    public boolean getValueForIsRefreshTokenAllowed(String grantType) {

        Boolean isRefreshTokenAllowed = refreshTokenAllowedGrantTypes.get(grantType);

        // If this element is not present in the XML, we will send true to maintain the backward compatibility.
        return isRefreshTokenAllowed == null ? true : isRefreshTokenAllowed;
    }

    /**
     * Get the value of the property "UseSPTenantDomain". This property is used to decide whether to use SP tenant
     * domain or user tenant domain.
     *
     * @return value of the "UseSPTenantDomain".
     */
    public boolean getUseSPTenantDomainValue() {

        return useSPTenantDomainValue;
    }

    public String getSaml2BearerTokenUserType() {
        return saml2BearerTokenUserType;
    }

    public boolean isMapFederatedUsersToLocal() {
        return mapFederatedUsersToLocal;
    }

    private void parseOAuthCallbackHandlers(OMElement callbackHandlersElem) {
        if (callbackHandlersElem == null) {
            warnOnFaultyConfiguration("OAuthCallbackHandlers element is not available.");
            return;
        }

        Iterator callbackHandlers =
                callbackHandlersElem.getChildrenWithLocalName(ConfigElements.OAUTH_CALLBACK_HANDLER);
        int callbackHandlerCount = 0;
        if (callbackHandlers != null) {
            for (; callbackHandlers.hasNext(); ) {
                OAuthCallbackHandlerMetaData cbHandlerMetadata =
                        buildAuthzCallbackHandlerMetadata((OMElement) callbackHandlers.next());
                if (cbHandlerMetadata != null) {
                    callbackHandlerMetaData.add(cbHandlerMetadata);
                    if (log.isDebugEnabled()) {
                        log.debug("OAuthCallbackHandlerMetadata was added. Class : " +
                                cbHandlerMetadata.getClassName());
                    }
                    callbackHandlerCount++;
                }
            }
        }
        // if no callback handlers are registered, print a WARN
        if (!(callbackHandlerCount > 0)) {
            warnOnFaultyConfiguration("No OAuthCallbackHandler elements were found.");
        }
    }

    private void parseTokenValidators(OMElement tokenValidators) {
        if (tokenValidators == null) {
            return;
        }

        Iterator validators = tokenValidators.getChildrenWithLocalName(ConfigElements.TOKEN_VALIDATOR);
        if (validators != null) {
            for (; validators.hasNext(); ) {
                OMElement validator = (OMElement) validators.next();
                if (validator != null) {
                    String clazzName = validator.getAttributeValue(new QName(ConfigElements.TOKEN_CLASS_ATTR));
                    String type = validator.getAttributeValue(new QName(ConfigElements.TOKEN_TYPE_ATTR));
                    tokenValidatorClassNames.put(type, clazzName);
                }
            }
        }
    }

    private void parseScopeValidator(OMElement scopeValidatorElem) {

        Set<OAuth2ScopeValidator> scopeValidators = new HashSet<>();

        if (ConfigElements.SCOPE_VALIDATORS.equals(scopeValidatorElem.getLocalName())) {
            Iterator scopeIterator = scopeValidatorElem
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SCOPE_VALIDATOR_ELEM));

            while (scopeIterator.hasNext()) {
                OMElement scopeValidatorElement = (OMElement) scopeIterator.next();
                String validatorClazz = scopeValidatorElement.getAttributeValue(new QName(ConfigElements
                        .SCOPE_CLASS_ATTR));
                if (validatorClazz != null) {
                    OAuth2ScopeValidator scopeValidator = getClassInstance(validatorClazz, OAuth2ScopeValidator.class);
                    if (scopeValidator == null) {
                        continue;
                    }
                    String scopesToSkipAttr = scopeValidatorElement.getAttributeValue(new QName(ConfigElements
                            .SKIP_SCOPE_ATTR));
                    scopeValidator.setScopesToSkip(getScopesToSkipSet(scopesToSkipAttr));

                    Iterator propertyIterator = scopeValidatorElement.getChildrenWithName
                            (getQNameWithIdentityNS(ConfigElements.SCOPE_VALIDATOR_PROPERTY));
                    Map<String, String> properties = new HashMap<>();

                    while (propertyIterator.hasNext()) {
                        OMElement propertyElement = (OMElement) propertyIterator.next();
                        String paramName = propertyElement.getAttributeValue(new QName(ConfigElements
                                .SCOPE_VALIDATOR_PROPERTY_NAME_ATTR));
                        String paramValue = propertyElement.getText();
                        properties.put(paramName, paramValue);
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Property: %s with value: %s is set to ScopeValidator: %s.",
                                    paramName, paramValue, validatorClazz));
                        }
                    }
                    scopeValidator.setProperties(properties);
                    scopeValidators.add(scopeValidator);

                    if (log.isDebugEnabled()) {
                        log.debug(String.format("ScopeValidator: %s is added to ScopeValidators list.", scopeValidator
                                .getClass().getCanonicalName()));
                    }
                }
            }
        } else {
            String scopeValidatorClazz = scopeValidatorElem.getAttributeValue(new QName
                    (ConfigElements.SCOPE_CLASS_ATTR));
            String scopesToSkipAttr = scopeValidatorElem.getAttributeValue(new QName(ConfigElements.SKIP_SCOPE_ATTR));

            if (scopeValidatorClazz != null) {
                OAuth2ScopeValidator scopeValidator = getClassInstance(scopeValidatorClazz, OAuth2ScopeValidator.class);
                if (scopeValidator != null) {
                    scopeValidator.setScopesToSkip(getScopesToSkipSet(scopesToSkipAttr));
                }
                scopeValidators.add(scopeValidator);
            }
        }
        setOAuth2ScopeValidators(scopeValidators);
    }

    private void parseScopeHandlers(OMElement scopeHandlersElem) {

        Set<OAuth2ScopeHandler> scopeHandlers = new HashSet<>();

        Iterator scopeHandlerIterator = scopeHandlersElem
                .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SCOPE_HANDLER));

        if (scopeHandlerIterator == null) {
            return;
        }

        while (scopeHandlerIterator.hasNext()) {
            OMElement scopeHandlerElem = (OMElement) scopeHandlerIterator.next();
            String scopeHandlerClazz = scopeHandlerElem.getAttributeValue(new QName(ConfigElements
                    .SCOPE_HANDLER_CLASS_ATTR));

            if (scopeHandlerClazz != null) {
                OAuth2ScopeHandler scopeHandler = getClassInstance(scopeHandlerClazz, OAuth2ScopeHandler.class);

                if (scopeHandler == null) {
                    continue;
                }
                Iterator propertyIterator = scopeHandlerElem.getChildrenWithName
                        (getQNameWithIdentityNS(ConfigElements.SCOPE_HANDLER_PROPERTY));
                Map<String, String> properties = new HashMap<>();

                while (propertyIterator.hasNext()) {
                    OMElement propertyElement = (OMElement) propertyIterator.next();
                    String paramName = propertyElement.getAttributeValue(new QName(ConfigElements
                            .SCOPE_HANDLER_PROPERTY_NAME_ATTR));
                    String paramValue = propertyElement.getText();
                    properties.put(paramName, paramValue);
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Property: %s with value: %s is set to ScopeHandler: %s.", paramName,
                                paramValue, scopeHandlerClazz));
                    }
                }
                scopeHandler.setProperties(properties);
                scopeHandlers.add(scopeHandler);

                if (log.isDebugEnabled()) {
                    log.debug(String.format("ScopeHandler: %s is added to ScopeHandler list.", scopeHandler
                            .getClass().getCanonicalName()));
                }
            }
        }
        setOAuth2ScopeHandlers(scopeHandlers);
    }

    /**
     * Create an instance of a OAuth2ScopeValidator type class for a given class name.
     *
     * @param scopeValidatorClazz Canonical name of the OAuth2ScopeValidator class
     * @return OAuth2ScopeValidator type class instance.
     */
    private <T> T getClassInstance(String scopeValidatorClazz, Class<T> type) {

        try {

            Class clazz = Thread.currentThread().getContextClassLoader().loadClass(scopeValidatorClazz);
            return type.cast(clazz.newInstance());
        } catch (ClassNotFoundException e) {
            log.error("Class not found in build path " + scopeValidatorClazz, e);
        } catch (InstantiationException e) {
            log.error("Class initialization error " + scopeValidatorClazz, e);
        } catch (IllegalAccessException e) {
            log.error("Class access error " + scopeValidatorClazz, e);
        } catch (ClassCastException e) {
            log.error("Cannot cast the class: " + scopeValidatorClazz + " to type: " + type.getCanonicalName(), e);
        }
        return null;
    }

    /**
     * Parse space delimited scopes to a Set.
     *
     * @param scopesToSkip Space delimited scopes.
     * @return
     */
    private Set<String> getScopesToSkipSet(String scopesToSkip) {

        Set<String> scopes = new HashSet<>();
        if (StringUtils.isNotEmpty(scopesToSkip)) {
            // Split the scopes attr by a -space- character and create the set (avoid duplicates).
            scopes = new HashSet<>(Arrays.asList(scopesToSkip.trim().split("\\s+")));
        }
        return scopes;
    }

    private void warnOnFaultyConfiguration(String logMsg) {
        log.warn("Error in OAuth Configuration. " + logMsg);
    }

    private OAuthCallbackHandlerMetaData buildAuthzCallbackHandlerMetadata(OMElement omElement) {
        // read the class attribute which is mandatory
        String className = omElement.getAttributeValue(new QName(ConfigElements.CALLBACK_CLASS));

        if (className == null) {
            log.error("Mandatory attribute \"Class\" is not present in the "
                    + "AuthorizationCallbackHandler element. "
                    + "AuthorizationCallbackHandler will not be registered.");
            return null;
        }

        // read the priority element, if it is not there, use the default
        // priority of 1
        int priority = OAuthConstants.OAUTH_AUTHZ_CB_HANDLER_DEFAULT_PRIORITY;
        OMElement priorityElem =
                omElement.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CALLBACK_PRIORITY));
        if (priorityElem != null) {
            priority = Integer.parseInt(priorityElem.getText());
        }

        if (log.isDebugEnabled()) {
            log.debug("Priority level of : " + priority + " is set for the " +
                    "AuthorizationCallbackHandler with the class : " + className);
        }

        // read the additional properties.
        OMElement paramsElem =
                omElement.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CALLBACK_PROPERTIES));
        Properties properties = null;
        if (paramsElem != null) {
            Iterator paramItr = paramsElem.getChildrenWithLocalName(ConfigElements.CALLBACK_PROPERTY);
            properties = new Properties();
            if (log.isDebugEnabled()) {
                log.debug("Registering Properties for AuthorizationCallbackHandler class : " + className);
            }
            for (; paramItr.hasNext(); ) {
                OMElement paramElem = (OMElement) paramItr.next();
                String paramName = paramElem.getAttributeValue(new QName(ConfigElements.CALLBACK_ATTR_NAME));
                String paramValue = paramElem.getText();
                properties.put(paramName, paramValue);
                if (log.isDebugEnabled()) {
                    log.debug("Property name : " + paramName + ", Property Value : " + paramValue);
                }
            }
        }
        return new OAuthCallbackHandlerMetaData(className, properties, priority);
    }

    private void parseDefaultValidityPeriods(OMElement oauthConfigElem) {

        // set the authorization code default timeout
        OMElement authzCodeTimeoutElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD));

        if (authzCodeTimeoutElem != null) {
            authorizationCodeValidityPeriodInSeconds = Long.parseLong(authzCodeTimeoutElem.getText());
        }

        // set the access token default timeout
        OMElement accessTokTimeoutElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD));
        if (accessTokTimeoutElem != null) {
            userAccessTokenValidityPeriodInSeconds = Long.parseLong(accessTokTimeoutElem.getText());
        }

        // set the application access token default timeout
        OMElement applicationAccessTokTimeoutElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.APPLICATION_ACCESS_TOKEN_VALIDATION_PERIOD));
        if (applicationAccessTokTimeoutElem != null) {
            applicationAccessTokenValidityPeriodInSeconds = Long.parseLong(applicationAccessTokTimeoutElem.getText());
        }

        // set the application access token default timeout
        OMElement refreshTokenTimeoutElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.REFRESH_TOKEN_VALIDITY_PERIOD));
        if (refreshTokenTimeoutElem != null) {
            refreshTokenValidityPeriodInSeconds = Long.parseLong(refreshTokenTimeoutElem.getText().trim());
        }

        OMElement timeStampSkewElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.TIMESTAMP_SKEW));
        if (timeStampSkewElem != null) {
            timeStampSkewInSeconds = Long.parseLong(timeStampSkewElem.getText());
        }

        if (log.isDebugEnabled()) {
            if (authzCodeTimeoutElem == null) {
                log.debug("\"Authorization Code Default Timeout\" element was not available "
                        + "in identity.xml. Continuing with the default value.");
            }
            if (accessTokTimeoutElem == null) {
                log.debug("\"Access Token Default Timeout\" element was not available "
                        + "in from identity.xml. Continuing with the default value.");
            }
            if (refreshTokenTimeoutElem == null) {
                log.debug("\"Refresh Token Default Timeout\" element was not available " +
                        "in from identity.xml. Continuing with the default value.");
            }
            if (timeStampSkewElem == null) {
                log.debug("\"Default Timestamp Skew\" element was not available "
                        + "in from identity.xml. Continuing with the default value.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Authorization Code Default Timeout is set to : " +
                        authorizationCodeValidityPeriodInSeconds + "ms.");
                log.debug("User Access Token Default Timeout is set to " + userAccessTokenValidityPeriodInSeconds +
                        "ms.");
                log.debug("Application Access Token Default Timeout is set to " +
                        applicationAccessTokenValidityPeriodInSeconds + "ms.");
                log.debug("Refresh Token validity period is set to " + refreshTokenValidityPeriodInSeconds + "s.");
                log.debug("Default TimestampSkew is set to " + timeStampSkewInSeconds + "ms.");
            }
        }
    }

    private void parseOAuthURLs(OMElement oauthConfigElem) {

        OMElement elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH1_REQUEST_TOKEN_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth1RequestTokenUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH1_AUTHORIZE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth1AuthorizeUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH1_ACCESS_TOKEN_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth1AccessTokenUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_AUTHZ_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2AuthzEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_TOKEN_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2TokenEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_USERINFO_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2UserInfoEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_CONSENT_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2ConsentPageUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_DCR_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2DCREPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_JWKS_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2JWKSPageUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OIDC_DISCOVERY_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oidcDiscoveryUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OIDC_WEB_FINGER_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oidcWebFingerEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OIDC_CONSENT_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oidcConsentPageUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_ERROR_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2ErrorPageUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
    }

    private void parseRefreshTokenRenewalConfiguration(OMElement oauthConfigElem) {

        OMElement enableRefreshTokenRenewalElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.RENEW_REFRESH_TOKEN_FOR_REFRESH_GRANT));
        if (enableRefreshTokenRenewalElem != null) {
            isRefreshTokenRenewalEnabled = Boolean.parseBoolean(enableRefreshTokenRenewalElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("RenewRefreshTokenForRefreshGrant was set to : " + isRefreshTokenRenewalEnabled);
        }
    }

    private void parseMapFederatedUsersToLocalConfiguration(OMElement oauthConfigElem) {

        OMElement mapFederatedUsersToLocalConfigElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.MAP_FED_USERS_TO_LOCAL));
        if (mapFederatedUsersToLocalConfigElem != null) {
            mapFederatedUsersToLocal = Boolean.parseBoolean(mapFederatedUsersToLocalConfigElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("MapFederatedUsersToLocal was set to : " + mapFederatedUsersToLocal);
        }
    }

    private void parseAccessTokenPartitioningConfig(OMElement oauthConfigElem) {
        OMElement enableAccessTokenPartitioningElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_ACCESS_TOKEN_PARTITIONING));
        if (enableAccessTokenPartitioningElem != null) {
            accessTokenPartitioningEnabled =
                    Boolean.parseBoolean(enableAccessTokenPartitioningElem.getText());
        }

        if (log.isDebugEnabled()) {
            log.debug("Enable OAuth Access Token Partitioning was set to : " + accessTokenPartitioningEnabled);
        }
    }

    private void parseAccessTokenPartitioningDomainsConfig(OMElement oauthConfigElem) {
        OMElement enableAccessTokenPartitioningElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ACCESS_TOKEN_PARTITIONING_DOMAINS));
        if (enableAccessTokenPartitioningElem != null) {
            accessTokenPartitioningDomains = enableAccessTokenPartitioningElem.getText();
        }

        if (log.isDebugEnabled()) {
            log.debug("Enable OAuth Access Token Partitioning Domains was set to : " +
                    accessTokenPartitioningDomains);
        }
    }

    private void parseEnableAssertionsUserNameConfig(OMElement oauthConfigElem) {
        OMElement enableAssertionsElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_ASSERTIONS));
        if (enableAssertionsElem != null) {
            OMElement enableAssertionsUserNameElem =
                    enableAssertionsElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_ASSERTIONS_USERNAME));
            if (enableAssertionsUserNameElem != null) {
                assertionsUserNameEnabled = Boolean.parseBoolean(enableAssertionsUserNameElem.getText());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Enable Assertions-UserName was set to : " + assertionsUserNameEnabled);
        }
    }

    private void parseTokenPersistenceProcessorConfig(OMElement oauthConfigElem) {

        OMElement persistenceprocessorConfigElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_PERSISTENCE_PROCESSOR));
        if (persistenceprocessorConfigElem != null &&
                StringUtils.isNotBlank(persistenceprocessorConfigElem.getText())) {
            tokenPersistenceProcessorClassName = persistenceprocessorConfigElem.getText().trim();
        }

        if (log.isDebugEnabled()) {
            log.debug("Token Persistence Processor was set to : " + tokenPersistenceProcessorClassName);
        }

    }

    /**
     * parse the configuration to load the class name of the OAuth 2.0 token generator.
     * this is a global configuration at the moment.
     *
     * @param oauthConfigElem
     */
    private void parseOAuthTokenGeneratorConfig(OMElement oauthConfigElem) {

        OMElement tokenGeneratorClassConfigElem = oauthConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH_TOKEN_GENERATOR));
        if (tokenGeneratorClassConfigElem != null && !"".equals(tokenGeneratorClassConfigElem.getText().trim())) {
            oauthTokenGeneratorClassName = tokenGeneratorClassConfigElem.getText().trim();
            if (log.isDebugEnabled()) {
                log.debug("OAuth token generator is set to : " + oauthTokenGeneratorClassName);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The default OAuth token issuer will be used. No custom token generator is set.");
            }
        }
    }

    private void parseOAuthTokenIssuerConfig(OMElement oauthConfigElem) {

        OMElement tokenIssuerClassConfigElem = oauthConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.IDENTITY_OAUTH_TOKEN_GENERATOR));
        if (tokenIssuerClassConfigElem != null && !"".equals(tokenIssuerClassConfigElem.getText().trim())) {
            oauthIdentityTokenGeneratorClassName = tokenIssuerClassConfigElem.getText().trim();
            if (log.isDebugEnabled()) {
                log.debug("Identity OAuth token generator is set to : " + oauthIdentityTokenGeneratorClassName);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The default Identity OAuth token issuer will be used. No custom token generator is set.");
            }
        }
    }

    private void parseSupportedGrantTypesConfig(OMElement oauthConfigElem) {

        OMElement supportedGrantTypesElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_GRANT_TYPES));

        if (supportedGrantTypesElem != null) {
            Iterator<OMElement> iterator = supportedGrantTypesElem
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_GRANT_TYPE));
            while (iterator.hasNext()) {
                OMElement supportedGrantTypeElement = iterator.next();
                OMElement grantTypeNameElement = supportedGrantTypeElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.GRANT_TYPE_NAME));
                String grantTypeName = null;
                if (grantTypeNameElement != null) {
                    grantTypeName = grantTypeNameElement.getText();
                }

                OMElement authzGrantHandlerClassNameElement = supportedGrantTypeElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.GRANT_TYPE_HANDLER_IMPL_CLASS));
                String authzGrantHandlerImplClass = null;
                if (authzGrantHandlerClassNameElement != null) {
                    authzGrantHandlerImplClass = authzGrantHandlerClassNameElement.getText();
                }

                OMElement idTokenAllowedElement = supportedGrantTypeElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ID_TOKEN_ALLOWED));
                String idTokenAllowed = null;
                if (idTokenAllowedElement != null) {
                    idTokenAllowed = idTokenAllowedElement.getText();
                }

                if (StringUtils.isNotEmpty(grantTypeName) && StringUtils.isNotEmpty(idTokenAllowed)) {
                    idTokenAllowedForGrantTypesMap.put(grantTypeName, idTokenAllowed);

                    if (!Boolean.parseBoolean(idTokenAllowed)) {
                        idTokenNotAllowedGrantTypesSet.add(grantTypeName);
                    }
                }


                if (StringUtils.isNotEmpty(grantTypeName) && StringUtils.isNotEmpty(authzGrantHandlerImplClass)) {
                    supportedGrantTypeClassNames.put(grantTypeName, authzGrantHandlerImplClass);

                    OMElement authzGrantValidatorClassNameElement = supportedGrantTypeElement.getFirstChildWithName(
                            getQNameWithIdentityNS(ConfigElements.GRANT_TYPE_VALIDATOR_IMPL_CLASS));

                    String authzGrantValidatorImplClass = null;
                    if (authzGrantValidatorClassNameElement != null) {
                        authzGrantValidatorImplClass = authzGrantValidatorClassNameElement.getText();
                    }

                    if (StringUtils.isNotEmpty(authzGrantValidatorImplClass)) {
                        supportedGrantTypeValidatorNames.put(grantTypeName, authzGrantValidatorImplClass);
                    }

                    OMElement refreshTokenAllowed = supportedGrantTypeElement
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.REFRESH_TOKEN_ALLOWED));
                    if (refreshTokenAllowed != null && StringUtils.isNotBlank(refreshTokenAllowed.getText())) {
                        boolean isRefreshAllowed = Boolean.parseBoolean(refreshTokenAllowed.getText());
                        refreshTokenAllowedGrantTypes.put(grantTypeName, isRefreshAllowed);
                    }
                }
            }
        } else {
            // if this element is not present, assume the default case.
            log.warn("\'SupportedGrantTypes\' element not configured in identity.xml. " +
                    "Therefore instantiating default grant type handlers");

            Map<String, String> defaultGrantTypes = new HashMap<>(5);
            defaultGrantTypes.put(GrantType.AUTHORIZATION_CODE.toString(), AUTHORIZATION_CODE_GRANT_HANDLER_CLASS);
            defaultGrantTypes.put(GrantType.CLIENT_CREDENTIALS.toString(), CLIENT_CREDENTIALS_GRANT_HANDLER_CLASS);
            defaultGrantTypes.put(GrantType.PASSWORD.toString(), PASSWORD_GRANT_HANDLER_CLASS);
            defaultGrantTypes.put(GrantType.REFRESH_TOKEN.toString(), REFRESH_TOKEN_GRANT_HANDLER_CLASS);
            defaultGrantTypes.put(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString(),
                    SAML20_BEARER_GRANT_HANDLER_CLASS);
            defaultGrantTypes.put(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString(),
                    IWA_NTLM_BEARER_GRANT_HANDLER_CLASS);
            supportedGrantTypeClassNames.putAll(defaultGrantTypes);
        }

        if (log.isDebugEnabled()) {
            for (Map.Entry entry : supportedGrantTypeClassNames.entrySet()) {
                String grantTypeName = entry.getKey().toString();
                String authzGrantHandlerImplClass = entry.getValue().toString();
                log.debug(grantTypeName + "supported by" + authzGrantHandlerImplClass);
            }
        }
    }

    private void parseSupportedResponseTypesConfig(OMElement oauthConfigElem) {
        OMElement supportedRespTypesElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_RESP_TYPES));

        if (supportedRespTypesElem != null) {
            Iterator<OMElement> iterator = supportedRespTypesElem.getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_RESP_TYPE));
            while (iterator.hasNext()) {
                OMElement supportedResponseTypeElement = iterator.next();
                OMElement responseTypeNameElement = supportedResponseTypeElement.
                        getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.RESP_TYPE_NAME));
                String responseTypeName = null;
                if (responseTypeNameElement != null) {
                    responseTypeName = responseTypeNameElement.getText();
                }
                OMElement responseTypeHandlerImplClassElement =
                        supportedResponseTypeElement.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.RESP_TYPE_HANDLER_IMPL_CLASS));
                String responseTypeHandlerImplClass = null;
                if (responseTypeHandlerImplClassElement != null) {
                    responseTypeHandlerImplClass = responseTypeHandlerImplClassElement.getText();
                }
                if (responseTypeName != null && !"".equals(responseTypeName) &&
                        responseTypeHandlerImplClass != null && !"".equals(responseTypeHandlerImplClass)) {
                    supportedResponseTypeClassNames.put(responseTypeName, responseTypeHandlerImplClass);
                    OMElement responseTypeValidatorClassNameElement = supportedResponseTypeElement
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.RESPONSE_TYPE_VALIDATOR_IMPL_CLASS));

                    String responseTypeValidatorImplClass = null;
                    if (responseTypeValidatorClassNameElement != null) {
                        responseTypeValidatorImplClass = responseTypeValidatorClassNameElement.getText();
                    }

                    if (!StringUtils.isEmpty(responseTypeValidatorImplClass)) {
                        supportedResponseTypeValidatorNames.put(responseTypeName, responseTypeValidatorImplClass);
                    }
                }
            }
        } else {
            // if this element is not present, assume the default case.
            log.warn("\'SupportedResponseTypes\' element not configured in identity.xml. " +
                    "Therefore instantiating default response type handlers");

            Map<String, String> defaultResponseTypes = new HashMap<>(4);
            defaultResponseTypes.put(ResponseType.CODE.toString(), "org.wso2.carbon.identity.oauth2.authz.handlers.CodeResponseTypeHandler");
            defaultResponseTypes.put(ResponseType.TOKEN.toString(), "org.wso2.carbon.identity.oauth2.authz.handlers.TokenResponseTypeHandler");
            defaultResponseTypes.put("id_token", "org.wso2.carbon.identity.oauth2.authz.handlers.TokenResponseTypeHandler");
            defaultResponseTypes.put("id_token token", "org.wso2.carbon.identity.oauth2.authz.handlers.TokenResponseTypeHandler");
            supportedResponseTypeClassNames.putAll(defaultResponseTypes);
        }

        if (log.isDebugEnabled()) {
            for (Map.Entry entry : supportedResponseTypeClassNames.entrySet()) {
                String responseTypeName = entry.getKey().toString();
                String authzHandlerImplClass = entry.getValue().toString();
                log.debug(responseTypeName + "supported by" + authzHandlerImplClass);
            }
        }
    }

    private void parseSupportedClientAuthHandlersConfig(OMElement clientAuthElement) {

        if (clientAuthElement != null) {
            Iterator<OMElement> iterator = clientAuthElement.getChildrenWithLocalName(
                    ConfigElements.CLIENT_AUTH_HANDLER_IMPL_CLASS);
            while (iterator.hasNext()) {
                OMElement supportedClientAuthHandler = iterator.next();
                Iterator<OMElement> confProperties = supportedClientAuthHandler
                        .getChildrenWithLocalName(ConfigElements.CLIENT_AUTH_PROPERTY);
                Properties properties = null;
                while (confProperties.hasNext()) {
                    properties = new Properties();
                    OMElement paramElem = confProperties.next();
                    String paramName = paramElem.getAttributeValue(
                            new QName(ConfigElements.CLIENT_AUTH_NAME));
                    String paramValue = paramElem.getText();
                    properties.put(paramName, paramValue);
                    if (log.isDebugEnabled()) {
                        log.debug("Property name : " + paramName + ", Property Value : " + paramValue);
                    }
                }
                String clientAuthHandlerImplClass = supportedClientAuthHandler.getAttributeValue(
                        new QName(ConfigElements.CLIENT_AUTH_CLASS));

                if (StringUtils.isEmpty(clientAuthHandlerImplClass)) {
                    log.error("Mandatory attribute \"Class\" is not present in the "
                            + "ClientAuthHandler element. ");
                    return;
                }
                if (properties != null) {
                    supportedClientAuthHandlerData.put(clientAuthHandlerImplClass, properties);
                } else {
                    supportedClientAuthHandlerData.put(clientAuthHandlerImplClass, new Properties());
                }

            }

        } else {
            // if this element is not present, assume the default case.
            log.warn("\'SupportedClientAuthMethods\' element not configured in identity.xml. " +
                    "Therefore instantiating default client authentication handlers");

            Map<String, Properties> defaultClientAuthHandlers = new HashMap<>(1);
            defaultClientAuthHandlers.put(
                    ConfigElements.DEFAULT_CLIENT_AUTHENTICATOR, new Properties());
            supportedClientAuthHandlerData.putAll(defaultClientAuthHandlers);
        }
        if (log.isDebugEnabled()) {
            for (Map.Entry<String, Properties> clazz : supportedClientAuthHandlerData.entrySet()) {
                log.debug("Supported client authentication method " + clazz.getKey());
            }
        }
    }

    private void parseSAML2GrantConfig(OMElement oauthConfigElem) {

        OMElement saml2GrantElement =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SAML2_GRANT));
        OMElement saml2BearerUserTypeElement = null;
        OMElement saml2TokenHandlerElement = null;
        if (saml2GrantElement != null) {
            saml2BearerUserTypeElement = saml2GrantElement.getFirstChildWithName(getQNameWithIdentityNS
                    (ConfigElements.SAML2_BEARER_USER_TYPE));
            saml2TokenHandlerElement = saml2GrantElement.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SAML2_TOKEN_HANDLER));
        }
        if (saml2TokenHandlerElement != null && StringUtils.isNotBlank(saml2TokenHandlerElement.getText())) {
            saml2TokenCallbackHandlerName = saml2TokenHandlerElement.getText().trim();
        }
        if (saml2BearerUserTypeElement != null && StringUtils.isNotBlank(saml2BearerUserTypeElement.getText())) {
            saml2BearerTokenUserType = saml2BearerUserTypeElement.getText().trim();
        }
    }

    private void parseAuthorizationContextTokenGeneratorConfig(OMElement oauthConfigElem) {
        OMElement authContextTokGenConfigElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.AUTHORIZATION_CONTEXT_TOKEN_GENERATION));
        if (authContextTokGenConfigElem != null) {
            OMElement enableJWTGenerationConfigElem =
                    authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLED));
            if (enableJWTGenerationConfigElem != null) {
                String enableJWTGeneration = enableJWTGenerationConfigElem.getText().trim();
                if (enableJWTGeneration != null && JavaUtils.isTrueExplicitly(enableJWTGeneration)) {
                    isAuthContextTokGenEnabled = true;
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_GENERATOR_IMPL_CLASS)) != null) {
                        tokenGeneratorImplClass =
                                authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_GENERATOR_IMPL_CLASS))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CLAIMS_RETRIEVER_IMPL_CLASS)) != null) {
                        claimsRetrieverImplClass =
                                authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CLAIMS_RETRIEVER_IMPL_CLASS))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CONSUMER_DIALECT_URI)) != null) {
                        consumerDialectURI =
                                authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CONSUMER_DIALECT_URI))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM)) != null) {
                        signatureAlgorithm =
                                authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SECURITY_CONTEXT_TTL)) != null) {
                        authContextTTL =
                                authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SECURITY_CONTEXT_TTL))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                            ConfigElements.AUTH_CONTEXT_TOKEN_USE_MULTIVALUE_SEPARATOR)) != null) {
                        useMultiValueSeparatorForAuthContextToken =
                                Boolean.parseBoolean(authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                        ConfigElements.AUTH_CONTEXT_TOKEN_USE_MULTIVALUE_SEPARATOR)).getText().trim());
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            if (isAuthContextTokGenEnabled) {
                log.debug("JWT Generation is enabled");
            } else {
                log.debug("JWT Generation is disabled");
            }
        }
    }

    private void parseImplicitErrorFragment(OMElement oauthConfigElem) {

        OMElement implicitErrorFragmentElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.IMPLICIT_ERROR_FRAGMENT));
        if (implicitErrorFragmentElem != null) {
            isImplicitErrorFragment =
                    Boolean.parseBoolean(implicitErrorFragmentElem.getText());
        }

        if (log.isDebugEnabled()) {
            log.debug("ImplicitErrorFragment was set to : " + isImplicitErrorFragment);
        }
    }

    private void parseRevokeResponseHeadersEnableConfig(OMElement oauthConfigElem) {
        OMElement enableRevokeResponseHeadersElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_REVOKE_RESPONSE_HEADERS));
        if (enableRevokeResponseHeadersElem != null) {
            isRevokeResponseHeadersEnabled = Boolean.parseBoolean(enableRevokeResponseHeadersElem.getText());
        }

        if (log.isDebugEnabled()) {
            log.debug("Enable revoke response headers : " + isRevokeResponseHeadersEnabled);
        }
    }

    private void parseOAuthTokenValueGenerator(OMElement oauthElem) {

        OMElement oauthTokenValueGeneratorElement = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH_TOKEN_VALUE_GENERATOR));

        if (oauthTokenValueGeneratorElement != null) {
            tokenValueGeneratorClassName = oauthTokenValueGeneratorElement.getText().trim();
        }

        if (log.isDebugEnabled()) {
            log.debug("Oauth token value generator class is set to: " + oauthTokenGeneratorClassName);
        }
    }

    private void parseOpenIDConnectConfig(OMElement oauthConfigElem) {

        OMElement openIDConnectConfigElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT));

        if (openIDConnectConfigElem != null) {
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_BUILDER)) != null) {
                openIDConnectIDTokenBuilderClassName =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_BUILDER))
                                .getText().trim();
            }

            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM)) != null) {
                idTokenSignatureAlgorithm =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM))
                                .getText().trim();
            }

            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_CUSTOM_CLAIM_CALLBACK_HANDLER)) != null) {
                openIDConnectIDTokenCustomClaimsHanlderClassName =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_CUSTOM_CLAIM_CALLBACK_HANDLER))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_SUB_CLAIM)) != null) {
                openIDConnectIDTokenSubClaim =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_SUB_CLAIM))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_USER_CONSENT)) != null) {
                openIDConnectSkipUserConsent =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_USER_CONSENT))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_ISSUER_ID)) != null) {
                openIDConnectIDTokenIssuerIdentifier = IdentityUtil.fillURLPlaceholders(
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_IDTOKEN_ISSUER_ID)).getText().trim());
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_EXPIRATION)) != null) {
                openIDConnectIDTokenExpiration =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_EXPIRATION))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_DIALECT)) != null) {
                openIDConnectUserInfoEndpointClaimDialect =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_DIALECT))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_RETRIEVER)) != null) {
                openIDConnectUserInfoEndpointClaimRetriever =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_RETRIEVER))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_REQUEST_VALIDATOR)) != null) {
                openIDConnectUserInfoEndpointRequestValidator =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_REQUEST_VALIDATOR))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_ACCESS_TOKEN_VALIDATOR)) != null) {
                openIDConnectUserInfoEndpointAccessTokenValidator =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_ACCESS_TOKEN_VALIDATOR))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_RESPONSE_BUILDER)) != null) {
                openIDConnectUserInfoEndpointResponseBuilder =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_RESPONSE_BUILDER))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_JWT_SIGNATURE_ALGORITHM)) != null) {
                userInfoJWTSignatureAlgorithm =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_JWT_SIGNATURE_ALGORITHM))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SIGN_JWT_WITH_SP_KEY)) != null) {
                isJWTSignedWithSPKey =
                        Boolean.parseBoolean(openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SIGN_JWT_WITH_SP_KEY))
                                .getText().trim());
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_CLAIMS)) != null) {
                String supportedClaimStr =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_CLAIMS))
                                .getText().trim();
                if (log.isDebugEnabled()) {
                    log.debug("Supported Claims : " + supportedClaimStr);
                }
                if (StringUtils.isNotEmpty(supportedClaimStr)) {
                    supportedClaims = supportedClaimStr.split(",");
                }
            }
        }
    }

    public OAuth2ScopeValidator getoAuth2ScopeValidator() {
        return oAuth2ScopeValidator;
    }

    public void setoAuth2ScopeValidator(OAuth2ScopeValidator oAuth2ScopeValidator) {
        this.oAuth2ScopeValidator = oAuth2ScopeValidator;
    }

    public Set<OAuth2ScopeValidator> getOAuth2ScopeValidators() {
        return oAuth2ScopeValidators;
    }

    public void setOAuth2ScopeValidators(Set<OAuth2ScopeValidator> oAuth2ScopeValidators) {
        this.oAuth2ScopeValidators = oAuth2ScopeValidators;
    }

    public Set<OAuth2ScopeHandler> getOAuth2ScopeHandlers() {
        return oAuth2ScopeHandlers;
    }

    public void setOAuth2ScopeHandlers(Set<OAuth2ScopeHandler> oAuth2ScopeHandlers) {
        this.oAuth2ScopeHandlers = oAuth2ScopeHandlers;
    }

    private void parseUseSPTenantDomainConfig(OMElement oauthElem) {

        OMElement useSPTenantDomainValueElement = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH_USE_SP_TENANT_DOMAIN));

        if (useSPTenantDomainValueElement != null) {
            useSPTenantDomainValue = Boolean.parseBoolean(useSPTenantDomainValueElement.getText().trim());
        }

        if (log.isDebugEnabled()) {
            log.debug("Use SP tenant domain value is set to: " + useSPTenantDomainValue);
        }
    }

    /**
     * Localpart names for the OAuth configuration in identity.xml.
     */
    private class ConfigElements {

        // URLs
        public static final String OAUTH1_REQUEST_TOKEN_URL = "OAuth1RequestTokenUrl";
        public static final String OAUTH1_AUTHORIZE_URL = "OAuth1AuthorizeUrl";
        public static final String OAUTH1_ACCESS_TOKEN_URL = "OAuth1AccessTokenUrl";
        public static final String OAUTH2_AUTHZ_EP_URL = "OAuth2AuthzEPUrl";
        public static final String OAUTH2_TOKEN_EP_URL = "OAuth2TokenEPUrl";
        public static final String OAUTH2_USERINFO_EP_URL = "OAuth2UserInfoEPUrl";
        public static final String OAUTH2_CONSENT_PAGE_URL = "OAuth2ConsentPage";
        public static final String OAUTH2_DCR_EP_URL = "OAuth2DCREPUrl";
        public static final String OAUTH2_JWKS_PAGE_URL = "OAuth2JWKSPage";
        public static final String OIDC_WEB_FINGER_EP_URL = "OIDCWebFingerEPUrl";
        public static final String OIDC_DISCOVERY_EP_URL = "OIDCDiscoveryEPUrl";
        public static final String OAUTH2_ERROR_PAGE_URL = "OAuth2ErrorPage";
        public static final String OIDC_CONSENT_PAGE_URL = "OIDCConsentPage";

        // JWT Generator
        public static final String AUTHORIZATION_CONTEXT_TOKEN_GENERATION = "AuthorizationContextTokenGeneration";
        public static final String ENABLED = "Enabled";
        public static final String TOKEN_GENERATOR_IMPL_CLASS = "TokenGeneratorImplClass";
        public static final String CLAIMS_RETRIEVER_IMPL_CLASS = "ClaimsRetrieverImplClass";
        public static final String CONSUMER_DIALECT_URI = "ConsumerDialectURI";
        public static final String SIGNATURE_ALGORITHM = "SignatureAlgorithm";
        public static final String SECURITY_CONTEXT_TTL = "AuthorizationContextTTL";
        private static final String AUTH_CONTEXT_TOKEN_USE_MULTIVALUE_SEPARATOR = "UseMultiValueSeparator";

        public static final String ENABLE_ASSERTIONS = "EnableAssertions";
        public static final String ENABLE_ASSERTIONS_USERNAME = "UserName";
        public static final String ENABLE_ACCESS_TOKEN_PARTITIONING = "EnableAccessTokenPartitioning";
        public static final String ACCESS_TOKEN_PARTITIONING_DOMAINS = "AccessTokenPartitioningDomains";
        // OpenIDConnect configurations
        public static final String OPENID_CONNECT = "OpenIDConnect";
        public static final String OPENID_CONNECT_IDTOKEN_BUILDER = "IDTokenBuilder";
        public static final String OPENID_CONNECT_IDTOKEN_SUB_CLAIM = "IDTokenSubjectClaim";
        public static final String OPENID_CONNECT_IDTOKEN_ISSUER_ID = "IDTokenIssuerID";
        public static final String OPENID_CONNECT_IDTOKEN_EXPIRATION = "IDTokenExpiration";
        public static final String OPENID_CONNECT_SKIP_USER_CONSENT = "SkipUserConsent";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_DIALECT = "UserInfoEndpointClaimDialect";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_RETRIEVER = "UserInfoEndpointClaimRetriever";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_REQUEST_VALIDATOR = "UserInfoEndpointRequestValidator";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_ACCESS_TOKEN_VALIDATOR = "UserInfoEndpointAccessTokenValidator";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_RESPONSE_BUILDER = "UserInfoEndpointResponseBuilder";
        public static final String OPENID_CONNECT_USERINFO_JWT_SIGNATURE_ALGORITHM = "UserInfoJWTSignatureAlgorithm";
        public static final String OPENID_CONNECT_SIGN_JWT_WITH_SP_KEY = "SignJWTWithSPKey";
        public static final String OPENID_CONNECT_IDTOKEN_CUSTOM_CLAIM_CALLBACK_HANDLER = "IDTokenCustomClaimsCallBackHandler";
        public static final String SUPPORTED_CLAIMS = "OpenIDConnectClaims";
        // Callback handler related configuration elements
        private static final String OAUTH_CALLBACK_HANDLERS = "OAuthCallbackHandlers";
        private static final String OAUTH_CALLBACK_HANDLER = "OAuthCallbackHandler";
        private static final String CALLBACK_CLASS = "Class";
        private static final String CALLBACK_PRIORITY = "Priority";
        private static final String CALLBACK_PROPERTIES = "Properties";
        private static final String CALLBACK_PROPERTY = "Property";
        private static final String CALLBACK_ATTR_NAME = "Name";
        private static final String TOKEN_VALIDATORS = "TokenValidators";
        private static final String TOKEN_VALIDATOR = "TokenValidator";
        private static final String TOKEN_TYPE_ATTR = "type";
        private static final String TOKEN_CLASS_ATTR = "class";
        private static final String SCOPE_HANDLERS = "ScopeHandlers";
        private static final String SCOPE_HANDLER = "ScopeHandler";
        private static final String SCOPE_HANDLER_CLASS_ATTR = "class";
        private static final String SCOPE_HANDLER_PROPERTY = "Property";
        private static final String SCOPE_HANDLER_PROPERTY_NAME_ATTR = "name";
        private static final String SCOPE_VALIDATOR = "OAuthScopeValidator";
        private static final String SCOPE_VALIDATORS = "ScopeValidators";
        private static final String SCOPE_VALIDATOR_ELEM = "ScopeValidator";
        private static final String SCOPE_VALIDATOR_PROPERTY = "Property";
        private static final String SCOPE_VALIDATOR_PROPERTY_NAME_ATTR = "name";
        private static final String SCOPE_CLASS_ATTR = "class";
        private static final String SKIP_SCOPE_ATTR = "scopesToSkip";
        private static final String IMPLICIT_ERROR_FRAGMENT = "ImplicitErrorFragment";

        // Default timestamp skew
        private static final String TIMESTAMP_SKEW = "TimestampSkew";
        // Default validity periods
        private static final String AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD = "AuthorizationCodeDefaultValidityPeriod";
        private static final String USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD = "UserAccessTokenDefaultValidityPeriod";
        private static final String APPLICATION_ACCESS_TOKEN_VALIDATION_PERIOD = "AccessTokenDefaultValidityPeriod";
        private static final String REFRESH_TOKEN_VALIDITY_PERIOD = "RefreshTokenValidityPeriod";
        // Enable/Disable cache
        private static final String ENABLE_CACHE = "EnableOAuthCache";
        // Enable/Disable refresh token renewal on each refresh_token grant request
        private static final String RENEW_REFRESH_TOKEN_FOR_REFRESH_GRANT = "RenewRefreshTokenForRefreshGrant";
        // TokenPersistenceProcessor
        private static final String TOKEN_PERSISTENCE_PROCESSOR = "TokenPersistenceProcessor";
        // Token issuer generator.
        private static final String OAUTH_TOKEN_GENERATOR = "OAuthTokenGenerator";
        private static final String IDENTITY_OAUTH_TOKEN_GENERATOR = "IdentityOAuthTokenGenerator";

        // Supported Grant Types
        private static final String SUPPORTED_GRANT_TYPES = "SupportedGrantTypes";
        private static final String SUPPORTED_GRANT_TYPE = "SupportedGrantType";
        private static final String GRANT_TYPE_NAME = "GrantTypeName";
        private static final String ID_TOKEN_ALLOWED = "IdTokenAllowed";
        private static final String GRANT_TYPE_HANDLER_IMPL_CLASS = "GrantTypeHandlerImplClass";
        private static final String GRANT_TYPE_VALIDATOR_IMPL_CLASS = "GrantTypeValidatorImplClass";
        private static final String RESPONSE_TYPE_VALIDATOR_IMPL_CLASS = "ResponseTypeValidatorImplClass";
        // Supported Client Authentication Methods
        private static final String CLIENT_AUTH_HANDLERS = "ClientAuthHandlers";
        private static final String CLIENT_AUTH_HANDLER_IMPL_CLASS = "ClientAuthHandler";
        private static final String STRICT_CLIENT_AUTHENTICATION = "StrictClientCredentialValidation";
        private static final String CLIENT_AUTH_CLASS = "Class";
        private static final String DEFAULT_CLIENT_AUTHENTICATOR = "org.wso2.carbon.identity.oauth2.token.handlers.clientauth.BasicAuthClientAuthHandler";
        private static final String CLIENT_AUTH_PROPERTY = "Property";
        private static final String CLIENT_AUTH_NAME = "Name";
        // Supported Response Types
        private static final String SUPPORTED_RESP_TYPES = "SupportedResponseTypes";
        private static final String SUPPORTED_RESP_TYPE = "SupportedResponseType";
        private static final String RESP_TYPE_NAME = "ResponseTypeName";
        private static final String RESP_TYPE_HANDLER_IMPL_CLASS = "ResponseTypeHandlerImplClass";
        // SAML2 assertion profile configurations
        private static final String SAML2_GRANT = "SAML2Grant";
        private static final String SAML2_TOKEN_HANDLER = "SAML2TokenHandler";
        private static final String SAML2_BEARER_USER_TYPE = "UserType";

        // To enable revoke response headers
        private static final String ENABLE_REVOKE_RESPONSE_HEADERS = "EnableRevokeResponseHeaders";
        private static final String REFRESH_TOKEN_ALLOWED = "IsRefreshTokenAllowed";

        // Oauth access token value generator related.
        private static final String OAUTH_TOKEN_VALUE_GENERATOR = "AccessTokenValueGenerator";

        // Property to decide whether to pick the user tenant domain or SP tenant domain.
        private static final String OAUTH_USE_SP_TENANT_DOMAIN = "UseSPTenantDomain";
        private static final String MAP_FED_USERS_TO_LOCAL = "MapFederatedUsersToLocal";
    }

}
