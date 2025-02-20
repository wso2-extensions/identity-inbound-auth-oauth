/*
 * Copyright (c) 2013-2025, WSO2 LLC. (http://www.wso2.com).
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
import org.apache.oltu.oauth2.as.validator.CodeValidator;
import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.CodeTokenResponseValidator;
import org.wso2.carbon.identity.oauth.common.IDTokenResponseValidator;
import org.wso2.carbon.identity.oauth.common.IDTokenTokenResponseValidator;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.SAML2GrantValidator;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.model.CarbonOAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.model.TokenIssuerDO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.DefaultResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.FormPostResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.FragmentResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.QueryResponseModeProvider;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2TokenCallbackHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeHandler;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.grant.AuthorizationCodeGrantValidator;
import org.wso2.carbon.identity.oauth2.validators.grant.ClientCredentialGrantValidator;
import org.wso2.carbon.identity.oauth2.validators.grant.PasswordGrantValidator;
import org.wso2.carbon.identity.oauth2.validators.grant.RefreshTokenGrantValidator;
import org.wso2.carbon.identity.openidconnect.CIBARequestObjectValidatorImpl;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;
import org.wso2.carbon.identity.openidconnect.RequestObjectBuilder;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidator;
import org.wso2.carbon.identity.openidconnect.RequestObjectValidatorImpl;
import org.wso2.carbon.utils.CarbonUtils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
            "org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationCodeGrantHandler";
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
    // Request object builder class.
    private static final String REQUEST_PARAM_VALUE_BUILDER_CLASS =
            "org.wso2.carbon.identity.openidconnect.RequestParamRequestObjectBuilder";
    //token issuer classes
    private static final String DEFAULT_OAUTH_TOKEN_ISSUER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl";
    private static final String JWT_TOKEN_ISSUER_CLASS =
            "org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer";
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";
    private static final Log log = LogFactory.getLog(OAuthServerConfiguration.class);
    private static OAuthServerConfiguration instance;
    private static String oauth1RequestTokenUrl = null;
    private static String oauth1RequestTokenUrlV2 = null;
    private static String oauth1AuthorizeUrl = null;
    private static String oauth1AuthorizeUrlV2 = null;
    private static String oauth1AccessTokenUrl = null;
    private static String oauth1AccessTokenUrlV2 = null;
    private static String oauth2AuthzEPUrl = null;
    private static String oauth2AuthzEPUrlV2 = null;
    private static String oauth2ParEPUrl = null;
    private static String oauth2ParEPUrlV2 = null;
    private static String oauth2TokenEPUrl = null;
    private static String oauth2TokenEPUrlV2 = null;
    private static String oauth2UserInfoEPUrl = null;
    private static String oauth2UserInfoEPUrlV2 = null;
    private static String oauth2RevocationEPUrl = null;
    private static String oauth2RevocationEPUrlV2 = null;
    private static String oauth2IntrospectionEPUrl = null;
    private static String oauth2IntrospectionEPUrlV2 = null;
    private static String oidcConsentPageUrl = null;
    private static String oidcConsentPageUrlV2 = null;
    private static String oauth2DCREPUrl = null;
    private static String oauth2DCREPUrlV2 = null;
    private static String oauth2JWKSPageUrl = null;
    private static String oauth2JWKSPageUrlV2 = null;
    private static String oidcWebFingerEPUrl = null;
    private static String oidcWebFingerEPUrlV2 = null;
    private static String oidcDiscoveryUrl = null;
    private static String oidcDiscoveryUrlV2 = null;
    private static String oauth2ConsentPageUrl = null;
    private static String oauth2ConsentPageUrlV2 = null;
    private static String oauth2ErrorPageUrl = null;
    private static String oauth2ErrorPageUrlV2 = null;
    private static boolean isOAuthResponseJspPageAvailable = false;
    private long authorizationCodeValidityPeriodInSeconds = 300;
    private long userAccessTokenValidityPeriodInSeconds = 3600;
    private long jarmResponseJwtValidityPeriodInSeconds = 3600;
    private long applicationAccessTokenValidityPeriodInSeconds = 3600;
    private long refreshTokenValidityPeriodInSeconds = 24L * 3600;
    private long timeStampSkewInSeconds = 300;
    private boolean enablePasswordFlowEnhancements = false;
    private String tokenPersistenceProcessorClassName =
            "org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor";
    private String oauthTokenGeneratorClassName;
    private OAuthIssuer oauthTokenGenerator;
    private String oauthIdentityTokenGeneratorClassName;
    private String clientIdValidationRegex = "[a-zA-Z0-9_]{15,30}";
    private String persistAccessTokenAlias;
    private String retainOldAccessTokens;
    private String tokenCleanupFeatureEnable;
    private OauthTokenIssuer oauthIdentityTokenGenerator;
    private boolean scopeValidationConfigValue = true;
    private boolean globalRbacScopeIssuerEnabled = false;
    private boolean cacheEnabled = false;
    private boolean isTokenRenewalPerRequestEnabled = false;
    private boolean isRefreshTokenRenewalEnabled = true;
    private boolean isExtendRenewedTokenExpiryTimeEnabled = true;
    private boolean isValidateAuthenticatedUserForRefreshGrantEnabled = false;
    private boolean assertionsUserNameEnabled = false;
    private boolean accessTokenPartitioningEnabled = false;
    private boolean redirectToRequestedRedirectUriEnabled = true;
    private boolean allowCrossTenantIntrospection = true;
    private boolean useClientIdAsSubClaimForAppTokens = true;
    private boolean removeUsernameFromIntrospectionResponseForAppTokens = true;
    private boolean useLegacyScopesAsAliasForNewScopes = false;
    private boolean useLegacyPermissionAccessForUserBasedAuth = false;
    private String accessTokenPartitioningDomains = null;
    private TokenPersistenceProcessor persistenceProcessor = null;
    private Set<OAuthCallbackHandlerMetaData> callbackHandlerMetaData = new HashSet<>();
    private Map<String, String> supportedGrantTypeClassNames = new HashMap<>();
    private Map<String, Boolean> refreshTokenAllowedGrantTypes = new HashMap<>();
    private Map<String, String> idTokenAllowedForGrantTypesMap = new HashMap<>();
    private Set<String> idTokenNotAllowedGrantTypesSet = new HashSet<>();
    private Set<String> userConsentEnabledGrantTypes = new HashSet<>();
    private Map<String, AuthorizationGrantHandler> supportedGrantTypes;
    private Map<String, RequestObjectBuilder> requestObjectBuilder;
    private Map<String, String> supportedGrantTypeValidatorNames = new HashMap<>();
    private Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> supportedGrantTypeValidators;
    private Map<String, String> supportedResponseTypeClassNames = new HashMap<>();
    private Map<String, ResponseTypeHandler> supportedResponseTypes;
    private Map<String, String> supportedResponseTypeValidatorNames = new HashMap<>();
    private Map<String, String> supportedResponseModeProviderClassNames = new HashMap<>();
    private Map<String, ResponseModeProvider> supportedResponseModes;
    private String defaultResponseModeProviderClassName;
    private ResponseModeProvider defaultResponseModeProvider;
    private Map<String, Class<? extends OAuthValidator<HttpServletRequest>>> supportedResponseTypeValidators;
    private Map<String, TokenIssuerDO> supportedTokenIssuers = new HashMap<>();
    private List<String> supportedTokenTypes = new ArrayList<>();
    private List<String> publicClientSupportedGrantTypes = new ArrayList<>();
    private List<String> publicClientNotSupportedGrantTypes = new ArrayList<>();
    private Map<String, OauthTokenIssuer> oauthTokenIssuerMap = new HashMap<>();
    private String[] supportedClaims = null;
    private boolean isFapiCiba = false;
    private boolean isFapiSecurity = false;
    private Map<String, Properties> supportedClientAuthHandlerData = new HashMap<>();
    private String saml2TokenCallbackHandlerName = null;
    private String saml2BearerTokenUserType;
    private boolean saml2UserIdFromClaims = false;
    private boolean mapFederatedUsersToLocal = false;
    private SAML2TokenCallbackHandler saml2TokenCallbackHandler = null;
    private Map<String, String> tokenValidatorClassNames = new HashMap();
    private boolean isAuthContextTokGenEnabled = false;
    private String tokenGeneratorImplClass = "org.wso2.carbon.identity.oauth2.token.JWTTokenGenerator";
    private String claimsRetrieverImplClass = "org.wso2.carbon.identity.oauth2.authcontext.DefaultClaimsRetriever";
    private String consumerDialectURI = "http://wso2.org/claims";
    private String signatureAlgorithm = "SHA256withRSA";
    private String idTokenSignatureAlgorithm = "SHA256withRSA";
    private String defaultIdTokenEncryptionAlgorithm = "RSA-OAEP";
    private List<String> supportedIdTokenEncryptionAlgorithms = new ArrayList<>();
    private String defaultIdTokenEncryptionMethod = "A128GCM";
    private List<String> supportedIdTokenEncryptionMethods = new ArrayList<>();
    private String userInfoJWTSignatureAlgorithm = "SHA256withRSA";
    private boolean userInfoMultiValueSupportEnabled = true;
    private boolean userInfoRemoveInternalPrefixFromRoles = false;

    private String authContextTTL = "15L";
    // property added to fix IDENTITY-4551 in backward compatible manner
    private boolean useMultiValueSeparatorForAuthContextToken = true;
    private boolean addTenantDomainToIdTokenEnabled = false;
    private boolean addUserstoreDomainToIdTokenEnabled = false;
    private boolean requestObjectEnabled = true;

    //default token types
    public static final String DEFAULT_TOKEN_TYPE = "Default";
    public static final String JWT_TOKEN_TYPE = "JWT";

    // OpenID Connect configurations
    private String openIDConnectIDTokenBuilderClassName =
            "org.wso2.carbon.identity.openidconnect.DefaultIDTokenBuilder";
    private String defaultRequestValidatorClassName =
            "org.wso2.carbon.identity.openidconnect.RequestObjectValidatorImpl";
    private String defaultCibaRequestValidatorClassName =
            "org.wso2.carbon.identity.openidconnect.CIBARequestObjectValidatorImpl";
    private String oAuthAuthzRequestClassName;
    public static final String DEFAULT_OAUTH_AUTHZ_REQUEST_CLASSNAME = CarbonOAuthAuthzRequest.class.getName();
    private String openIDConnectIDTokenCustomClaimsHanlderClassName =
            "org.wso2.carbon.identity.openidconnect.SAMLAssertionClaimsCallback";
    private String jwtAccessTokenOIDCClaimsHandlerClassName =
            "org.wso2.carbon.identity.openidconnect.JWTAccessTokenOIDCClaimsHandler";
    private IDTokenBuilder openIDConnectIDTokenBuilder = null;
    private Map<String, String> requestObjectBuilderClassNames = new HashMap<>();
    private volatile RequestObjectValidator requestObjectValidator = null;
    private volatile RequestObjectValidator cibaRequestObjectValidator = null;
    private CustomClaimsCallbackHandler openidConnectIDTokenCustomClaimsCallbackHandler = null;
    private CustomClaimsCallbackHandler jwtAccessTokenOIDCClaimsHandler = null;
    private String openIDConnectIDTokenIssuerIdentifier = null;
    private String openIDConnectIDTokenSubClaim = "http://wso2.org/claims/fullname";
    private Boolean openIDConnectSkipUserConsent = true;
    private Boolean openIDConnectSkipLoginConsent;
    private Boolean openIDConnectSkipLogoutConsent;
    private String openIDConnectIDTokenExpiration = "3600";
    private long openIDConnectIDTokenExpiryTimeInSeconds = 3600;

    private String openIDConnectUserInfoEndpointClaimDialect = "http://wso2.org/claims";

    private String openIDConnectUserInfoEndpointClaimRetriever =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoUserStoreClaimRetriever";
    private String openIDConnectUserInfoEndpointRequestValidator =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInforRequestDefaultValidator";
    private String openIDConnectUserInfoEndpointAccessTokenValidator =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoISAccessTokenValidator";
    private String openIDConnectUserInfoEndpointResponseBuilder =
            "org.wso2.carbon.identity.oauth.endpoint.user.impl.UserInfoJSONResponseBuilder";

    // Property added to preserve the backward compatibility to send the original claim uris comes in the assertion.
    private boolean convertOriginalClaimsFromAssertionsToOIDCDialect = false;
    // This property will decide whether to send only mapped roles received from the federated IdP
    private boolean returnOnlyMappedLocalRoles = false;

    // Property to check whether to add remaining user attributes
    private boolean addUnmappedUserAttributes = false;

    private OAuth2ScopeValidator oAuth2ScopeValidator;
    private Set<OAuth2ScopeValidator> oAuth2ScopeValidators = new HashSet<>();
    private Set<OAuth2ScopeHandler> oAuth2ScopeHandlers = new HashSet<>();
    // property added to fix IDENTITY-4492 in backward compatible manner
    private boolean isJWTSignedWithSPKey = true;
    // property added to fix IDENTITY-4534 in backward compatible manner
    private boolean isImplicitErrorFragment = true;
    // property added to fix IDENTITY-4112 in backward compatible manner
    private boolean isRevokeResponseHeadersEnabled = true;

    // property to make DisplayName property to be used in consent page
    private boolean showDisplayNameInConsentPage = false;
    // Use the SP tenant domain instead of user domain.
    private boolean useSPTenantDomainValue;

    // Property added to customize the token valued generation method. (IDENTITY-6139)
    private ValueGenerator tokenValueGenerator;

    // property to skip OIDC claims retrieval for client credential grant type.
    // By default, this is true because OIDC claims are not required for client credential grant type
    // and CC grant doesn't involve a user.
    private boolean skipOIDCClaimsForClientCredentialGrant = true;

    private String tokenValueGeneratorClassName;
    //property to define hashing algorithm when enabling hashing of tokens and authorization codes.
    private String hashAlgorithm = "SHA-256";
    private boolean isClientSecretHashEnabled = false;


    // Property added to determine the expiration of logout token in oidc back-channel logout.
    private String openIDConnectBCLogoutTokenExpiryInSeconds = "120";

    // Property to determine whether data providers should be executed during token introspection.
    private boolean enableIntrospectionDataProviders = false;
    // Property to define the allowed scopes.
    private List<String> allowedScopes = new ArrayList<>();
    // Property to define the default requested scopes.
    private List<String> defaultRequestedScopes = new ArrayList<>();

    // Property to define the filtered claims.
    private List<String> filteredIntrospectionClaims = new ArrayList<>();

    // Property to check whether to drop unregistered scopes.
    private boolean dropUnregisteredScopes = false;

    // Properties for OAuth2 Device Code Grant type.
    private int deviceCodeKeyLength = 6;
    private long deviceCodeExpiryTime = 600000L;
    private int deviceCodePollingInterval = 5000;
    private String deviceCodeKeySet = "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz23456789";
    private String deviceAuthzEPUrl = null;
    private String deviceAuthzEPUrlV2 = null;
    private List<String> supportedTokenEndpointSigningAlgorithms = new ArrayList<>();
    private Boolean roleBasedScopeIssuerEnabledConfig = false;
    private String scopeMetadataExtensionImpl = null;
    private static final List<String> HYBRID_RESPONSE_TYPES = Arrays.asList("code token",
            "code id_token", "code id_token token");
    private List<String> configuredHybridResponseTypes = new ArrayList<>();

    private final List<String> restrictedQueryParameters = new ArrayList<>();

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

        //Get the configured scopeValidationEnabledConfigValue.
        OMElement scopeValidationElem = oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.SCOPE_VALIDATION_FOR_AUTHZ_CODE_AND_IMPLICIT));

        if (scopeValidationElem != null) {
            scopeValidationConfigValue = Boolean.parseBoolean(scopeValidationElem.getText());
        }

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

        OMElement globalRoleBasedScopeIssuer = oauthElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.ENABLE_GLOBAL_ROLE_BASED_SCOPE_ISSUER)
        );

        if (globalRoleBasedScopeIssuer != null) {
            setGlobalRbacScopeIssuerEnabled(Boolean.parseBoolean(globalRoleBasedScopeIssuer.getText()));
        }

        // read default timeout periods
        parseDefaultValidityPeriods(oauthElem);

        parseEnablePasswordFlowEnhancements(oauthElem);

        // read OAuth URLs
        parseOAuthURLs(oauthElem);

        // Read v2 OAuth URLS
        parseV2OAuthURLs(oauthElem);

        // read token renewal per request config.
        // if enabled access token and refresh token will be renewed for each token endpoint call.
        parseTokenRenewalPerRequestConfiguration(oauthElem);

        // Read map federated users to local config.
        parseMapFederatedUsersToLocalConfiguration(oauthElem);

        // read refresh token renewal config
        parseRefreshTokenRenewalConfiguration(oauthElem);

        // Read the authenticated user validation config for refresh grant.
        parseRefreshTokenGrantValidationConfiguration(oauthElem);

        // read token persistence processor config
        parseTokenPersistenceProcessorConfig(oauthElem);

        // read supported grant types
        parseSupportedGrantTypesConfig(oauthElem);

        // Read <UserConsentEnabledGrantTypes> under <OAuth> tag and populate data.
        parseUserConsentEnabledGrantTypesConfig(oauthElem);

        // read supported response types
        parseSupportedResponseTypesConfig(oauthElem);

        // read supported response modes
        parseSupportedResponseModesConfig(oauthElem);

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

        parseSkipOIDCClaimsForClientCredentialGrantConfig(oauthElem);

        // parse OAuth 2.0 token generator
        parseOAuthTokenGeneratorConfig(oauthElem);

        // parse OAuth2 implicit grant error in fragment property for backward compatibility
        parseImplicitErrorFragment(oauthElem);

        // parse identity OAuth 2.0 token generator
        parseOAuthTokenIssuerConfig(oauthElem);

        // parse client is validation regex pattern
        parseClientIdValidationRegex(oauthElem);

        // Parse Persist Access Token Alias element.
        parsePersistAccessTokenAliasConfig(oauthElem);

        //read supported token types
        parseSupportedTokenTypesConfig(oauthElem);

        // Parse token value generator class name.
        parseOAuthTokenValueGenerator(oauthElem);

        // Parse values of DeviceCodeGrant config.
        parseOAuthDeviceCodeGrantConfig(oauthElem);

        // Read the value of UseSPTenantDomain config.
        parseUseSPTenantDomainConfig(oauthElem);

        parseRevokeResponseHeadersEnableConfig(oauthElem);
        parseShowDisplayNameInConsentPage(oauthElem);
        // read hash algorithm type config
        parseHashAlgorithm(oauthElem);
        // read hash mode config
        parseEnableHashMode(oauthElem);

        // Read the value of retain Access Tokens config. If true old token will be stored in Audit table else drop it.
        parseRetainOldAccessTokensConfig(oauthElem);

        // Read the value of  old  Access Tokens cleanup enable  config. If true cleanup feature will be enable.
        tokenCleanupFeatureConfig(oauthElem);

        // Read token introspection related configurations.
        parseTokenIntrospectionConfig(oauthElem);

        // Read the property for error redirection URI
        parseRedirectToOAuthErrorPageConfig(oauthElem);

        // Read config for allowed scopes.
        parseAllowedScopesConfiguration(oauthElem);

        // Read config for default requested scopes.
        parseDefaultRequestedScopesConfiguration(oauthElem);

        // Read config for filtered claims for introspection response.
        parseFilteredClaimsForIntrospectionConfiguration(oauthElem);

        // Read config for dropping unregistered scopes.
        parseDropUnregisteredScopes(oauthElem);

        // Read config for cross tenant allow.
        parseAllowCrossTenantIntrospection(oauthElem);

        // Read config for using client id as sub claim for application tokens.
        parseUseClientIdAsSubClaimForAppTokens(oauthElem);

        // Read config for remove username from introspection response for application tokens.
        parseRemoveUsernameFromIntrospectionResponseForAppTokens(oauthElem);

        // Set the availability of oauth_response.jsp page.
        setOAuthResponseJspPageAvailable();

        // Read config for RoleBasedScopeIssuer in GlobalScopeValidators enabled.
        parseRoleBasedScopeIssuerEnabled(oauthElem);

        // Read config for using legacy scopes as alias for new scopes.
        parseUseLegacyScopesAsAliasForNewScopes(oauthElem);

        // Read config for using legacy permission access for user based auth.
        parseUseLegacyPermissionAccessForUserBasedAuth(oauthElem);

        // Read config for scope metadata extension implementation.
        parseScopeMetadataExtensionImpl(oauthElem);

        // Read config for restricted query parameters in oauth requests
        parseRestrictedQueryParameters(oauthElem);
    }

    /**
     * Parse role based scope issuer enabled configuration under global scope validators.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseRoleBasedScopeIssuerEnabled(OMElement oauthConfigElem) {

        OMElement globalScopeValidatorsElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.GLOBAL_SCOPE_VALIDATORS));
        if (globalScopeValidatorsElem != null) {
            OMElement roleBasedScopeIssuerEnabledElem = globalScopeValidatorsElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.ROLE_BASED_SCOPE_ISSUER_ENABLED));
            if (roleBasedScopeIssuerEnabledElem != null) {
                OMElement enableElem = roleBasedScopeIssuerEnabledElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.ENABLE));
                roleBasedScopeIssuerEnabledConfig = Boolean.parseBoolean(enableElem.getText().trim());
            }
        }
    }

    /**
     * Parse allowed scopes configuration.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseAllowedScopesConfiguration(OMElement oauthConfigElem) {

        OMElement allowedScopesElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.ALLOWED_SCOPES_ELEMENT));
        if (allowedScopesElem != null) {
            Iterator scopeIterator = allowedScopesElem.getChildrenWithName(getQNameWithIdentityNS(
                    ConfigElements.SCOPES_ELEMENT));
            while (scopeIterator.hasNext()) {
                OMElement scopeElement = (OMElement) scopeIterator.next();
                allowedScopes.add(scopeElement.getText());
            }
        }
    }

    /**
     * Parse default requested scopes configuration.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseDefaultRequestedScopesConfiguration(OMElement oauthConfigElem) {

        OMElement defaultRequestedScopesElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.DEFAULT_REQUESTED_SCOPES_ELEMENT));
        if (defaultRequestedScopesElem != null) {
            Iterator scopeIterator = defaultRequestedScopesElem.getChildrenWithName(getQNameWithIdentityNS(
                    ConfigElements.SCOPES_ELEMENT));
            while (scopeIterator.hasNext()) {
                OMElement scopeElement = (OMElement) scopeIterator.next();
                defaultRequestedScopes.add(scopeElement.getText());
            }
        }
    }

    /**
     * Parse config for skipping OIDC claims for client credentials
     *
     * @param oauthElem OauthConfigElem.
     */
    private void parseSkipOIDCClaimsForClientCredentialGrantConfig(OMElement oauthElem) {

        OMElement skipOIDCClaimsForClientCredentialGrantElement = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                        .SKIP_OIDC_CLAIMS_FOR_CLIENT_CREDENTIAL_GRANT));
        if (skipOIDCClaimsForClientCredentialGrantElement != null) {
            skipOIDCClaimsForClientCredentialGrant = Boolean.parseBoolean(
                    skipOIDCClaimsForClientCredentialGrantElement.getText().trim());
        }
    }

    /**
     * Parse filtered claims for introspection response configuration.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseFilteredClaimsForIntrospectionConfiguration(OMElement oauthConfigElem) {

        OMElement introspectionClaimsElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.INTROSPECTION_CONFIG));
        if (introspectionClaimsElem != null) {
            OMElement filteredClaimsElem = introspectionClaimsElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.FILTERED_CLAIMS));
            if (filteredClaimsElem != null) {
                Iterator claimIterator = filteredClaimsElem.getChildrenWithName(getQNameWithIdentityNS(
                        ConfigElements.FILTERED_CLAIM));
                while (claimIterator.hasNext()) {
                    OMElement claimElement = (OMElement) claimIterator.next();
                    filteredIntrospectionClaims.add(claimElement.getText());
                }
            }
        }
    }

    private void parseTokenIntrospectionConfig(OMElement oauthElem) {

        OMElement introspectionElem = oauthElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.INTROSPECTION_CONFIG));
        if (introspectionElem != null) {
            // Reads 'EnableDataProviders' config.
            OMElement enableDataProvidersElem = introspectionElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.ENABLE_DATA_PROVIDERS_CONFIG));
            if (enableDataProvidersElem != null) {
                enableIntrospectionDataProviders = Boolean.parseBoolean(enableDataProvidersElem.getText().trim());
            }
        }
    }

    private void parseShowDisplayNameInConsentPage(OMElement oauthElem) {
        OMElement showApplicationNameInConsentPageElement = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                        .IDENTITY_OAUTH_SHOW_DISPLAY_NAME_IN_CONSENT_PAGE));
        if (showApplicationNameInConsentPageElement != null) {
            showDisplayNameInConsentPage = Boolean.parseBoolean(showApplicationNameInConsentPageElement.getText());
        }
    }

    private void parseDropUnregisteredScopes(OMElement oauthElem) {

        OMElement dropUnregisteredScopesElement =
                oauthElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DROP_UNREGISTERED_SCOPES));
        if (dropUnregisteredScopesElement != null) {
            dropUnregisteredScopes = Boolean.parseBoolean(dropUnregisteredScopesElement.getText());
        }
    }

    /**
     * This method returns if FAPI is enabled for CIBA in identity.xml.
     */
    public boolean isFapiCiba() {
        return isFapiCiba;
    }

    public Set<OAuthCallbackHandlerMetaData> getCallbackHandlerMetaData() {
        return callbackHandlerMetaData;
    }

    /**
     * Returns the value of ShowDisplayNameInConsentPage configuration.
     *
     * @return
     */
    public boolean isShowDisplayNameInConsentPage() {
        return showDisplayNameInConsentPage;
    }

    /**
     * Returns the value of DropUnregisteredScopes configuration.
     *
     * @return value of DropUnregisteredScopes configuration.
     */
    public boolean isDropUnregisteredScopes() {

        return dropUnregisteredScopes;
    }

    /**
     * Get the list of alloed scopes.
     *
     * @return String returns a list of scope string.
     */
    public List<String> getAllowedScopes() {

        return allowedScopes;
    }

    public List<String> getFilteredIntrospectionClaims() {

        return filteredIntrospectionClaims;
    }

    /**
     * Get the list of default requested scopes.
     *
     * @return String returns a list of default requested scope string.
     */
    public List<String> getDefaultRequestedScopes() {

        return defaultRequestedScopes;
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

    public String getOAuth2ParEPUrl() {

        return oauth2ParEPUrl;
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

    public String getOauth2RevocationEPUrl() {

        return oauth2RevocationEPUrl;
    }

    public String getOauth2IntrospectionEPUrl() {

        return oauth2IntrospectionEPUrl;
    }

    public String getDeviceAuthzEPUrl() {

        return deviceAuthzEPUrl;
    }

    public String getOAuth1RequestTokenUrlV2() {

        return oauth1RequestTokenUrlV2;
    }

    public String getOauth1AuthorizeUrlV2() {

        return oauth1AuthorizeUrlV2;
    }

    public String getOauth1AccessTokenUrlV2() {

        return oauth1AccessTokenUrlV2;
    }

    public String getOauth2AuthzEPUrlV2() {

        return oauth2AuthzEPUrlV2;
    }

    public String getOauth2ParEPUrlV2() {

        return oauth2ParEPUrlV2;
    }

    public String getOauth2TokenEPUrlV2() {

        return oauth2TokenEPUrlV2;
    }

    public String getOauth2DCREPUrlV2() {

        return oauth2DCREPUrlV2;
    }

    public String getOauth2JWKSPageUrlV2() {

        return oauth2JWKSPageUrlV2;
    }

    public String getOidcDiscoveryUrlV2() {

        return oidcDiscoveryUrlV2;
    }

    public String getOidcWebFingerEPUrlV2() {

        return oidcWebFingerEPUrlV2;
    }

    public String getOauth2UserInfoEPUrlV2() {

        return oauth2UserInfoEPUrlV2;
    }

    public String getOauth2RevocationEPUrlV2() {

        return oauth2RevocationEPUrlV2;
    }

    public String getOauth2IntrospectionEPUrlV2() {

        return oauth2IntrospectionEPUrlV2;
    }

    public String getDeviceAuthzEPUrlV2() {

        return deviceAuthzEPUrlV2;
    }

    public boolean isRoleBasedScopeIssuerEnabled() {

        return roleBasedScopeIssuerEnabledConfig;
    }

    public boolean isSkipOIDCClaimsForClientCredentialGrant() {

        return skipOIDCClaimsForClientCredentialGrant;
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

    /**
     * Returns server level default identity oauth token issuer
     *
     * @return instance of default identity oauth token issuer
     */
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
                            log.info("The default Identity OAuth token issuer will be used. No custom token " +
                                            "generator is set.");
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

    public boolean usePersistedAccessTokenAlias() {

        if (persistAccessTokenAlias != null) {
            return Boolean.TRUE.toString().equalsIgnoreCase(persistAccessTokenAlias);
        } else {
            return true;
        }
    }

    public boolean useRetainOldAccessTokens() {

        return Boolean.TRUE.toString().equalsIgnoreCase(retainOldAccessTokens);
    }

    public List<String> getConfiguredHybridResponseTypes() {

        return configuredHybridResponseTypes;
    }

    public boolean isTokenCleanupEnabled() {

        return Boolean.TRUE.toString().equalsIgnoreCase(tokenCleanupFeatureEnable);
    }

    public String getOIDCConsentPageUrl() {
        return oidcConsentPageUrl;
    }

    public String getOIDCConsentPageUrlV2() {

        return oidcConsentPageUrlV2;
    }

    public String getOauth2ConsentPageUrl() {
        return oauth2ConsentPageUrl;
    }

    public String getOauth2ConsentPageUrlV2() {

        return oauth2ConsentPageUrlV2;
    }

    public String getOauth2ErrorPageUrl() {
        return oauth2ErrorPageUrl;
    }

    public String getOauth2ErrorPageUrlV2() {

        return oauth2ErrorPageUrlV2;
    }

    public boolean isPasswordFlowEnhancementsEnabled() {
        return enablePasswordFlowEnhancements;
    }

    public long getAuthorizationCodeValidityPeriodInSeconds() {
        return authorizationCodeValidityPeriodInSeconds;
    }

    public long getUserAccessTokenValidityPeriodInSeconds() {
        return userAccessTokenValidityPeriodInSeconds;
    }

    public long getJarmResponseJwtValidityPeriodInSeconds() {

        return jarmResponseJwtValidityPeriodInSeconds;
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

    public String getClientIdValidationRegex() {
        return clientIdValidationRegex;
    }

    /**
     * @deprecated From v5.1.3 use @{@link BaseCache#isEnabled()} to check whether a cache is enabled or not instead
     * of relying on <EnableOAuthCache> global Cache config
     */
    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public boolean isRefreshTokenRenewalEnabled() {
        return isRefreshTokenRenewalEnabled;
    }

    public boolean isExtendRenewedTokenExpiryTimeEnabled() {
        return isExtendRenewedTokenExpiryTimeEnabled;
    }

    /**
     * Check if the authenticated user validation is enabled for refresh token grant flow.
     *
     * @return Returns true if the config is enabled.
     */
    public boolean isValidateAuthenticatedUserForRefreshGrantEnabled() {

        return isValidateAuthenticatedUserForRefreshGrantEnabled;
    }

    public Map<String, OauthTokenIssuer> getOauthTokenIssuerMap() {
        return oauthTokenIssuerMap;
    }

    /**
     * Check if token renewal is enabled for each call to the token endpoint.
     *
     * @return Returns true if the config is enabled.
     */
    public boolean isTokenRenewalPerRequestEnabled() {

        return isTokenRenewalPerRequestEnabled;
    }

    public Map<String, AuthorizationGrantHandler> getSupportedGrantTypes() {
        if (supportedGrantTypes == null) {
            synchronized (this) {
                if (supportedGrantTypes == null) {
                    Map<String, AuthorizationGrantHandler> supportedGrantTypesTemp = new HashMap<>();
                    for (Map.Entry<String, String> entry : supportedGrantTypeClassNames.entrySet()) {
                        AuthorizationGrantHandler authzGrantHandler = null;
                        try {
                            authzGrantHandler =
                                    (AuthorizationGrantHandler) Class.forName(entry.getValue()).newInstance();
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
                            .put(GrantType.PASSWORD.toString(), PasswordGrantValidator.class);
                    supportedGrantTypeValidatorsTemp.put(GrantType.CLIENT_CREDENTIALS.toString(),
                            ClientCredentialGrantValidator.class);
                    supportedGrantTypeValidatorsTemp.put(GrantType.AUTHORIZATION_CODE.toString(),
                            AuthorizationCodeGrantValidator.class);
                    supportedGrantTypeValidatorsTemp.put(GrantType.REFRESH_TOKEN.toString(),
                            RefreshTokenGrantValidator.class);
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
                    supportedResponseTypeValidatorsTemp.put(OAuthConstants.ID_TOKEN,
                            IDTokenResponseValidator.class);
                    supportedResponseTypeValidatorsTemp.put(OAuthConstants.IDTOKEN_TOKEN,
                            IDTokenTokenResponseValidator.class);
                    supportedResponseTypeValidatorsTemp.put(OAuthConstants.CODE_TOKEN,
                            CodeTokenResponseValidator.class);
                    supportedResponseTypeValidatorsTemp.put(OAuthConstants.CODE_IDTOKEN,
                            CodeTokenResponseValidator.class);
                    supportedResponseTypeValidatorsTemp.put(OAuthConstants.CODE_IDTOKEN_TOKEN,
                            CodeTokenResponseValidator.class);
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

    /**
     * This method create ResponseModeProvider instances and add to supportedResponseModes Map and return
     * supportedResponseModes.
     * called inside OAuth2ServiceComponentHolder --> setResponseModeProviders()
     * @return supportedResponseModes Map<String, ResponseModeProvider>
     */
    public Map<String, ResponseModeProvider> getSupportedResponseModes() {

        if (supportedResponseModes == null) {
            synchronized (this) {
                if (supportedResponseModes == null) {
                    Map<String, ResponseModeProvider> supportedResponseModesTemp = new Hashtable<>();
                    for (Map.Entry<String, String> entry : supportedResponseModeProviderClassNames.entrySet()) {
                        ResponseModeProvider responseModeProvider = null;
                        try {
                            responseModeProvider = (ResponseModeProvider) Class.forName(entry.getValue()).newInstance();
                        } catch (InstantiationException e) {
                            log.error("Error instantiating " + entry.getValue(), e);
                            throw new RuntimeException(e);
                        } catch (IllegalAccessException e) {
                            log.error("Illegal access to " + entry.getValue(), e);
                            throw new RuntimeException(e);
                        } catch (ClassNotFoundException e) {
                            log.error("Cannot find class: " + entry.getValue(), e);
                            throw new RuntimeException(e);
                        }
                        supportedResponseModesTemp.put(entry.getKey(), responseModeProvider);
                    }
                    supportedResponseModes = supportedResponseModesTemp;
                }
            }
        }
        return supportedResponseModes;
    }

    public ResponseModeProvider getDefaultResponseModeProvider() {

        String defaultResponseModeProviderClass = defaultResponseModeProviderClassName;
        try {
            defaultResponseModeProvider = (ResponseModeProvider) Class.forName
                    (defaultResponseModeProviderClass).newInstance();
        } catch (InstantiationException e) {
            log.error("Error instantiating " + defaultResponseModeProviderClass, e);
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            log.error("Illegal access to " + defaultResponseModeProviderClass, e);
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            log.error("Cannot find class: " + defaultResponseModeProviderClass, e);
            throw new RuntimeException(e);
        }

        return defaultResponseModeProvider;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public boolean isClientSecretHashEnabled() {
        return isClientSecretHashEnabled;
    }

    private void parseRequestObjectConfig(OMElement requestObjectBuildersElem) {
        if (requestObjectBuildersElem != null) {
            Iterator<OMElement> iterator = requestObjectBuildersElem
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.REQUEST_OBJECT_BUILDER));

            while (iterator.hasNext()) {
                OMElement requestObjectBuildersElement = iterator.next();
                OMElement builderTypeElement = requestObjectBuildersElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.BUILDER_TYPE));
                OMElement requestObjectImplClassElement = requestObjectBuildersElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.REQUEST_OBJECT_IMPL_CLASS));


                if (builderTypeElement == null) {
                    log.warn("Empty configuration element for <Type> under <RequestObjectBuilder> configuration.");
                    //Empty configuration element for Type, ignore
                    continue;
                }

                if (requestObjectImplClassElement == null) {
                    log.warn("No <ClassName> tag to define RequestObjectBuilder implementation found under " +
                            "<RequestObjectBuilder> configuration.");
                    continue;
                }

                String builderType = builderTypeElement.getText();
                String requestObjectImplClass = requestObjectImplClassElement.getText();
                requestObjectBuilderClassNames.put(builderType, requestObjectImplClass);

            }
        }
        setDefaultRequestObjectBuilderClasses();
        if (log.isDebugEnabled()) {
            for (Map.Entry entry : requestObjectBuilderClassNames.entrySet()) {
                String builderName = entry.getKey().toString();
                String requestObjectBuilderImplClass = entry.getValue().toString();
                log.debug(builderName + " is associated with " + requestObjectBuilderImplClass);
            }
        }
    }

    private void setDefaultRequestObjectBuilderClasses() {
        if (requestObjectBuilderClassNames.get(REQUEST_PARAM_VALUE_BUILDER) == null) {
            // if this element is not present, assume the default case.
            log.info("\'RequestObjectBuilder\' element for Type: " + REQUEST_PARAM_VALUE_BUILDER + "is not " +
                    "configured in identity.xml. Therefore instantiating default request object builder: "
                    + REQUEST_PARAM_VALUE_BUILDER_CLASS);
            requestObjectBuilderClassNames.put(REQUEST_PARAM_VALUE_BUILDER, REQUEST_PARAM_VALUE_BUILDER_CLASS);
        }
    }

    /**
     * Returns an instance of RequestObjectValidator
     *
     * @return instance of RequestObjectValidator
     */
    public RequestObjectValidator getRequestObjectValidator() {

        if (requestObjectValidator == null) {
            synchronized (RequestObjectValidator.class) {
                if (requestObjectValidator == null) {
                    try {
                        Class clazz =
                                Thread.currentThread().getContextClassLoader()
                                        .loadClass(defaultRequestValidatorClassName);
                        requestObjectValidator = (RequestObjectValidator) clazz.newInstance();
                    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                        log.warn("Failed to initiate RequestObjectValidator from identity.xml. " +
                                "Hence initiating the default implementation");
                        requestObjectValidator = new RequestObjectValidatorImpl();
                    }
                }
            }
        }
        return requestObjectValidator;
    }

    /**
     * Returns an instance of CIBARequestObjectValidator
     *
     * @return instance of CIBARequestObjectValidator
     */
    public RequestObjectValidator getCIBARequestObjectValidator() {

        if (cibaRequestObjectValidator == null) {
            synchronized (RequestObjectValidator.class) {
                if (cibaRequestObjectValidator == null) {
                    try {
                        Class clazz = Thread.currentThread().getContextClassLoader()
                                        .loadClass(defaultCibaRequestValidatorClassName);
                        cibaRequestObjectValidator = (RequestObjectValidator) clazz.newInstance();
                    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                        log.warn("Failed to initiate CIBA RequestObjectValidator from identity.xml. " +
                                "Hence initiating the default implementation", e);
                        cibaRequestObjectValidator = new CIBARequestObjectValidatorImpl();
                    }
                }
            }
        }
        return cibaRequestObjectValidator;
    }

    /**
     * Return an instance of the RequestObjectBuilder
     *
     * @return instance of the RequestObjectBuilder
     */
    public Map<String, RequestObjectBuilder> getRequestObjectBuilders() {
        if (requestObjectBuilder == null) {
            synchronized (this) {
                if (requestObjectBuilder == null) {
                    Map<String, RequestObjectBuilder> requestBuilderTemp = new HashMap<>();
                    for (Map.Entry<String, String> entry : requestObjectBuilderClassNames.entrySet()) {
                        RequestObjectBuilder requestObjectBuilder = null;
                        try {
                            requestObjectBuilder = (RequestObjectBuilder) Class.forName(entry.getValue()).newInstance();
                        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
                            log.error("Error instantiating " + entry.getValue(), e);
                        }
                        if (requestObjectBuilder != null) {
                            requestBuilderTemp.put(entry.getKey(), requestObjectBuilder);
                        } else {
                            log.warn("Failed to initiate request object builder class which is associated with " +
                                    "the builder " + entry.getKey());
                        }
                    }
                    requestObjectBuilder = requestBuilderTemp;
                }
            }
        }
        return requestObjectBuilder;
    }

    /**
     * Returns the configured OAuthAuthzRequest class name. If not configured, the default class name will be returned.
     *
     * @return OAuthAuthzRequest implementation class name.
     */
    public String getOAuthAuthzRequestClassName() {

        return oAuthAuthzRequestClassName;
    }

    public Set<String> getSupportedResponseTypeNames() {
        return supportedResponseTypeClassNames.keySet();
    }

    public List<String> getSupportedResponseModeNames() {

        return new ArrayList<>(supportedResponseModeProviderClassNames.keySet());
    }

    public String[] getSupportedClaims() {
        return supportedClaims;
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

    public List<String> getPublicClientSupportedGrantTypesList() {

        return publicClientSupportedGrantTypes;
    }

    public boolean isRedirectToRequestedRedirectUriEnabled() {

        return redirectToRequestedRedirectUriEnabled;
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

    public String getDefaultIdTokenEncryptionAlgorithm() {
        return defaultIdTokenEncryptionAlgorithm;
    }

    public List<String> getSupportedIdTokenEncryptionAlgorithm() {
        return supportedIdTokenEncryptionAlgorithms;
    }

    public String getDefaultIdTokenEncryptionMethod() {
        return defaultIdTokenEncryptionMethod;
    }

    public List<String> getSupportedIdTokenEncryptionMethods() {
        return supportedIdTokenEncryptionMethods;
    }

    public String getUserInfoJWTSignatureAlgorithm() {
        return userInfoJWTSignatureAlgorithm;
    }

    /**
     * Returns whether multi value support is enabled for userinfo response.
     *
     * @return True if multi value support is enabled for userinfo response.
     */
    public boolean getUserInfoMultiValueSupportEnabled() {

        return userInfoMultiValueSupportEnabled;
    }

    /**
     * Returns whether Internal prefix should be removed from the roles claim of the userinfo response.
     *
     * @return True if Internal prefix value should be removed from the role claim of userinfo response.
     */
    public boolean isUserInfoResponseRemoveInternalPrefixFromRoles() {

        return userInfoRemoveInternalPrefixFromRoles;
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

    public List<String> getRestrictedQueryParameters() {
        return restrictedQueryParameters;
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
                                        tokenPersistenceProcessorClassName +
                                        ". Defaulting to PlainTextPersistenceProcessor";
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
                        openidConnectIDTokenCustomClaimsCallbackHandler =
                                (CustomClaimsCallbackHandler) clazz.newInstance();
                    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
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
     * Returns if login consent enabled or not.
     *
     */
    public boolean getOpenIDConnectSkipeUserConsentConfig() {

        if (openIDConnectSkipLoginConsent == null) {
            if (log.isDebugEnabled()) {
                log.debug("The SkipLoginConsent property is not configured. " +
                        "So retrieving the SkipUserConsent value.");
            }
            return openIDConnectSkipUserConsent;
        }
        return openIDConnectSkipLoginConsent;
    }

    /**
     * Returns if skip logout consent enabled or not.
     *
     */
    public boolean getOpenIDConnectSkipLogoutConsentConfig() {

        if (openIDConnectSkipLogoutConsent == null) {
            if (log.isDebugEnabled()) {
                log.debug("The SkipLogoutConsent property is not configured. " +
                        "So retrieving the SkipUserConsent value.");
            }
            return openIDConnectSkipUserConsent;
        }
        return openIDConnectSkipLogoutConsent;
    }

    /**
     * @return the openIDConnectIDTokenExpirationInSeconds
     * @deprecated use {@link #getOpenIDConnectIDTokenExpiryTimeInSeconds()} instead
     */
    public String getOpenIDConnectIDTokenExpiration() {
        return openIDConnectIDTokenExpiration;
    }

    /**
     * @return ID Token expiry time in milliseconds.
     */
    public long getOpenIDConnectIDTokenExpiryTimeInSeconds() {
        return openIDConnectIDTokenExpiryTimeInSeconds;
    }

    /**
     * Returns expiration time of logout token in oidc back-channel logout.
     *
     * @return Logout token expiry time in seconds.
     */
    public String getOpenIDConnectBCLogoutTokenExpiration() {
        return openIDConnectBCLogoutTokenExpiryInSeconds;
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
     * Returns whether introspection data providers should be enabled.
     *
     * @return true if introspection data providers should be enabled.
     * @deprecated This configuration is deprecated from IS 5.12.0 onwards. Use EventListener configurations for
     * data providers instead.
     */
    @Deprecated
    public boolean isEnableIntrospectionDataProviders() {

        return enableIntrospectionDataProviders;
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
     * Returns whether user consent is required for the particular grant type.
     *
     * @param grantType
     * @return
     */
    public boolean isUserConsentRequiredForClaims(String grantType) {
        return userConsentEnabledGrantTypes.contains(grantType);
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

    public boolean getSaml2UserIdFromClaims() {

        return saml2UserIdFromClaims;
    }

    public boolean isConvertOriginalClaimsFromAssertionsToOIDCDialect() {
        return convertOriginalClaimsFromAssertionsToOIDCDialect;
    }

    public boolean isReturnOnlyMappedLocalRoles() {
        return returnOnlyMappedLocalRoles;
    }

    /**
     * Check whether addUnmappedUserAttributes is allowed.
     *
     * @return if the server configuration for addUnmappedUserAttributes is set.
     */
    public boolean isAddUnmappedUserAttributes() {
        return addUnmappedUserAttributes;
    }

    public boolean isMapFederatedUsersToLocal() {
        return mapFederatedUsersToLocal;
    }

    public boolean isAddTenantDomainToIdTokenEnabled() {
        return addTenantDomainToIdTokenEnabled;
    }

    public boolean isAddUserstoreDomainToIdTokenEnabled() {
        return addUserstoreDomainToIdTokenEnabled;
    }

    public boolean isRequestObjectEnabled() {
        return requestObjectEnabled;
    }

    public int getDeviceCodeKeyLength() {

        return deviceCodeKeyLength;
    }

    public long getDeviceCodeExpiryTime() {

        return deviceCodeExpiryTime;
    }

    public int getDeviceCodePollingInterval() {

        return deviceCodePollingInterval;
    }

    public String getDeviceCodeKeySet() {

        return deviceCodeKeySet;
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

    private void parseEnablePasswordFlowEnhancements(OMElement oauthConfigElem) {
        OMElement enablePasswordFlowEnhancementsElem =
                oauthConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.ENABLE_PASSWORD_FLOW_ENHANCEMENTS));
        if (enablePasswordFlowEnhancementsElem != null) {
            enablePasswordFlowEnhancements = Boolean.parseBoolean(enablePasswordFlowEnhancementsElem.getText());
        }
    }

    private void parseDefaultValidityPeriods(OMElement oauthConfigElem) {

        // Set the authorization code default timeout
        OMElement authzCodeTimeoutElem =
                oauthConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD));

        if (authzCodeTimeoutElem != null) {
            authorizationCodeValidityPeriodInSeconds = Long.parseLong(authzCodeTimeoutElem.getText());
        }

        // set the access token default timeout
        OMElement accessTokTimeoutElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD));
        if (accessTokTimeoutElem != null) {
            userAccessTokenValidityPeriodInSeconds = Long.parseLong(accessTokTimeoutElem.getText());
        }

        // set the JARM response jwt validity timeout
        OMElement jarmResponseJwtTimeoutElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.JARM_RESPONSE_JWT_DEFAULT_VALIDITY_PERIOD));
        if (jarmResponseJwtTimeoutElem != null) {
            jarmResponseJwtValidityPeriodInSeconds = Long.parseLong(jarmResponseJwtTimeoutElem.getText());
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
                ConfigElements.OAUTH2_PAR_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2ParEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
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
                ConfigElements.OAUTH2_REVOCATION_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2RevocationEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_INTROSPECTION_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2IntrospectionEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
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
        elem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.DEVICE_AUTHZ_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                deviceAuthzEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
    }

    private void parseV2OAuthURLs(OMElement oauthConfigElem) {

        OMElement oauthConfigElemV2 = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.V2));

        if (oauthConfigElemV2 == null) {
            return;
        }

        OMElement elem = oauthConfigElemV2.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.OAUTH1_REQUEST_TOKEN_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth1RequestTokenUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH1_AUTHORIZE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth1AuthorizeUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH1_ACCESS_TOKEN_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth1AccessTokenUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_AUTHZ_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2AuthzEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_PAR_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2ParEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_TOKEN_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2TokenEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_USERINFO_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2UserInfoEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.OAUTH2_REVOCATION_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2RevocationEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.OAUTH2_INTROSPECTION_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2IntrospectionEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_CONSENT_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2ConsentPageUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_DCR_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2DCREPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_JWKS_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2JWKSPageUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OIDC_DISCOVERY_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oidcDiscoveryUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OIDC_WEB_FINGER_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oidcWebFingerEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OIDC_CONSENT_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oidcConsentPageUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_ERROR_PAGE_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                oauth2ErrorPageUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauthConfigElemV2.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_AUTHZ_EP_URL));
        if (elem != null) {
            if (StringUtils.isNotBlank(elem.getText())) {
                deviceAuthzEPUrlV2 = IdentityUtil.fillURLPlaceholders(elem.getText());
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

        OMElement enableExtendRenewedTokenExpTimeElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.EXTEND_RENEWED_REFRESH_TOKEN_EXPIRY_TIME));
        if (enableExtendRenewedTokenExpTimeElem != null) {
            isExtendRenewedTokenExpiryTimeEnabled = Boolean.parseBoolean(enableExtendRenewedTokenExpTimeElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("ExtendRenewedRefreshTokenExpiryTime was set to : " + isExtendRenewedTokenExpiryTimeEnabled);
        }
    }

    private void parseRefreshTokenGrantValidationConfiguration(OMElement oauthConfigElem) {

        OMElement validateAuthenticatedUserForRefreshGrantElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.VALIDATE_AUTHENTICATED_USER_FOR_REFRESH_GRANT));
        if (validateAuthenticatedUserForRefreshGrantElem != null) {
            isValidateAuthenticatedUserForRefreshGrantEnabled =
                    Boolean.parseBoolean(validateAuthenticatedUserForRefreshGrantElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("ValidateAuthenticatedUserForRefreshGrant was set to : " +
                    isValidateAuthenticatedUserForRefreshGrantEnabled);
        }
    }

    private void parseAccessTokenPartitioningConfig(OMElement oauthConfigElem) {

        OMElement enableAccessTokenPartitioningElem =
                oauthConfigElem
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_ACCESS_TOKEN_PARTITIONING));
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
                oauthConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.ACCESS_TOKEN_PARTITIONING_DOMAINS));
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
                    enableAssertionsElem
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_ASSERTIONS_USERNAME));
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
                oauthConfigElem
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_PERSISTENCE_PROCESSOR));
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

    private void parseClientIdValidationRegex(OMElement oauthConfigElem) {

        OMElement clientIdValidationRegexConfigElem = oauthConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CLIENT_ID_VALIDATE_REGEX));
        if (clientIdValidationRegexConfigElem != null &&
                !"".equals(clientIdValidationRegexConfigElem.getText().trim())) {
            clientIdValidationRegex = clientIdValidationRegexConfigElem.getText().trim();
        }
        if (log.isDebugEnabled()) {
            log.debug("Client id validation regex is set to: " + clientIdValidationRegex);
        }
    }

    private void parsePersistAccessTokenAliasConfig(OMElement oauthConfigElem) {

        OMElement tokenIssuerClassConfigElem = oauthConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.IDENTITY_OAUTH_PERSIST_TOKEN_ALIAS));
        if (tokenIssuerClassConfigElem != null && !"".equals(tokenIssuerClassConfigElem.getText().trim())) {
            persistAccessTokenAlias = tokenIssuerClassConfigElem.getText().trim();
            if (log.isDebugEnabled()) {
                log.debug("Identity OAuth persist access token alias is set to : " + persistAccessTokenAlias);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("PersistAccessTokenAlias is not defiled. Default config will be used.");
            }
        }
    }

    private void parseRetainOldAccessTokensConfig(OMElement oauthCleanupConfigElem) {

        OMElement tokenCleanElem = oauthCleanupConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_TOKEN_CLEAN_ELEM));
        if (tokenCleanElem != null) {
            OMElement oldTokenRetainConfigElem = tokenCleanElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.RETAIN_OLD_ACCESS_TOKENS));
            if (oldTokenRetainConfigElem != null && !"".equals(oldTokenRetainConfigElem.getText().trim())) {
                retainOldAccessTokens = oldTokenRetainConfigElem.getText().trim();
                if (log.isDebugEnabled()) {
                    log.debug("Retain old access token is set to : " + retainOldAccessTokens);
                }
            } else {
                retainOldAccessTokens = "false";
                if (log.isDebugEnabled()) {
                    log.debug("Retain old access token  is not defined.Default config will be used");
                }
            }
        } else {
            tokenCleanupFeatureEnable = "false";
        }
    }

    private void tokenCleanupFeatureConfig(OMElement oauthCleanupConfigElem) {

        OMElement tokenCleanElem = oauthCleanupConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OAUTH2_TOKEN_CLEAN_ELEM));
        if (tokenCleanElem != null) {
            OMElement tokenCleanupConfigElem =
                    tokenCleanElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_CLEANUP_FEATURE));
            if (tokenCleanupConfigElem != null && StringUtils.isNotBlank(tokenCleanupConfigElem.getText())) {
                tokenCleanupFeatureEnable = tokenCleanupConfigElem.getText().trim();
                if (log.isDebugEnabled()) {
                    log.debug("Old token cleanup process enable is set to : " + tokenCleanupFeatureEnable);
                }
            } else {
                tokenCleanupFeatureEnable = "false";
                if (log.isDebugEnabled()) {
                    log.debug("Old token cleanup process enable  is not defined. Default config will be used");
                }
            }
        } else {
            tokenCleanupFeatureEnable = "false";
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

                /* Read the public client allowed grant types for all grant types.
                 * Grant types added with PublicClientAllowed property and value set to true will be added to
                 * publicClientSupportedGrantTypes list and value set to false will be added to
                 * publicClientNotSupportedGrantTypes. All default grant types will have the property set to either the
                 * value.
                 * If the property is not mentioned in the custom grant type configuration, the grant type will not be
                 * added to either lists. So, if the custom grant type is added to the array configuration of allowed,
                 * grant types, it will get added to the publicClientSupportedGrantTypes list.
                 */
                OMElement publicClientAllowedElement = supportedGrantTypeElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.PUBLIC_CLIENT_ALLOWED));
                String publicClientAllowed = null;
                if (publicClientAllowedElement != null) {
                    publicClientAllowed = publicClientAllowedElement.getText();
                }
                if (StringUtils.isNotEmpty(publicClientAllowed)) {
                    if (Boolean.parseBoolean(publicClientAllowed)) {
                        publicClientSupportedGrantTypes.add(grantTypeName);
                    } else {
                        publicClientNotSupportedGrantTypes.add(grantTypeName);
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

    private void parseSupportedTokenTypesConfig(OMElement oauthConfigElem) {

        OMElement supportedTokenTypesElem = oauthConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_TOKEN_TYPES));

        if (supportedTokenTypesElem != null) {
            Iterator<OMElement> iterator = supportedTokenTypesElem
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_TOKEN_TYPE));

            while (iterator.hasNext()) {
                OMElement supportedTokenTypeElement = iterator.next();
                OMElement tokenTypeNameElement = supportedTokenTypeElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_TYPE_NAME));

                String tokenTypeName = null;
                if (tokenTypeNameElement != null) {
                    tokenTypeName = tokenTypeNameElement.getText();
                }

                OMElement tokenTypeImplClassElement = supportedTokenTypeElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_TYPE_IMPL_CLASS));

                String tokenTypeImplClass = null;
                if (tokenTypeImplClassElement != null) {
                    tokenTypeImplClass = tokenTypeImplClassElement.getText();
                }

                OMElement persistAccessTokenAliasElement = supportedTokenTypeElement.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.IDENTITY_OAUTH_PERSIST_TOKEN_ALIAS));

                String persistAccessTokenAlias = null;
                if (persistAccessTokenAliasElement != null) {
                    persistAccessTokenAlias = persistAccessTokenAliasElement.getText();
                }

                if (StringUtils.isNotEmpty(tokenTypeName)) {
                    TokenIssuerDO tokenIssuerDO = new TokenIssuerDO();
                    if (StringUtils.isNotEmpty(tokenTypeImplClass)) {
                        tokenIssuerDO.setTokenType(tokenTypeName);
                        tokenIssuerDO.setTokenImplClass(tokenTypeImplClass);
                    }

                    if (StringUtils.isNotEmpty(persistAccessTokenAlias)) {
                        tokenIssuerDO.setPersistAccessTokenAlias(Boolean.valueOf(persistAccessTokenAlias));
                    } else {
                        tokenIssuerDO.setPersistAccessTokenAlias(true);
                    }
                    supportedTokenIssuers.put(tokenTypeName, tokenIssuerDO);
                }
            }
        }

        boolean isRegistered = false;
        //Adding global token issuer configured in the identity xml as a supported token issuer
        for (Map.Entry<String, TokenIssuerDO> entry : supportedTokenIssuers.entrySet()) {
            TokenIssuerDO issuerDO = entry.getValue();
            if (oauthIdentityTokenGeneratorClassName != null && oauthIdentityTokenGeneratorClassName
                    .equals(issuerDO.getTokenImplClass())) {
                isRegistered = true;
                break;
            }
        }

        if (!isRegistered && oauthIdentityTokenGeneratorClassName != null) {
            boolean isPersistTokenAlias = true;
            if (persistAccessTokenAlias != null) {
                isPersistTokenAlias = Boolean.parseBoolean(persistAccessTokenAlias);
            }

            // If a server level <IdentityOAuthTokenGenerator> is defined, that will be our first choice for the
            // "Default" token type issuer implementation.
            supportedTokenIssuers.put(DEFAULT_TOKEN_TYPE,
                    new TokenIssuerDO(DEFAULT_TOKEN_TYPE, oauthIdentityTokenGeneratorClassName,
                            isPersistTokenAlias));
        }

        // Adding default token types if not added in the configuration.
        if (!supportedTokenIssuers.containsKey(DEFAULT_TOKEN_TYPE)) {
            supportedTokenIssuers.put(DEFAULT_TOKEN_TYPE,
                    new TokenIssuerDO(DEFAULT_TOKEN_TYPE, DEFAULT_OAUTH_TOKEN_ISSUER_CLASS, true));
        }
        if (!supportedTokenIssuers.containsKey(JWT_TOKEN_TYPE)) {
            supportedTokenIssuers.put(JWT_TOKEN_TYPE, new TokenIssuerDO(JWT_TOKEN_TYPE, JWT_TOKEN_ISSUER_CLASS, true));
        }

        // Create the token types list.
        supportedTokenTypes.addAll(supportedTokenIssuers.keySet());
    }

    public List<String> getSupportedTokenTypes() {

        return Collections.unmodifiableList(supportedTokenTypes);
    }

    /**
     * Adds oauth token issuer instances used for token generation.
     * @param tokenType registered token type
     * @return token issuer instance
     * @throws IdentityOAuth2Exception
     */
    public OauthTokenIssuer addAndReturnTokenIssuerInstance(String tokenType) throws IdentityOAuth2Exception {

        TokenIssuerDO tokenIssuerDO = supportedTokenIssuers.get(tokenType);
        OauthTokenIssuer oauthTokenIssuer = null;
        if (tokenIssuerDO != null && tokenIssuerDO.getTokenImplClass() != null) {
            try {
                if (oauthTokenIssuerMap.get(tokenType) == null) {
                    Class clazz = this.getClass().getClassLoader().loadClass(tokenIssuerDO.getTokenImplClass());
                    oauthTokenIssuer = (OauthTokenIssuer) clazz.newInstance();
                    oauthTokenIssuer.setPersistAccessTokenAlias(
                            supportedTokenIssuers.get(tokenType).isPersistAccessTokenAlias());
                    oauthTokenIssuerMap.put(tokenType, oauthTokenIssuer);
                    log.info("An instance of " + tokenIssuerDO.getTokenImplClass()
                            + " is created for Identity OAuth token generation.");
                } else {
                    oauthTokenIssuer = oauthTokenIssuerMap.get(tokenType);
                }
            } catch (Exception e) {
                String errorMsg = "Error when instantiating the OAuthIssuer : " + tokenIssuerDO.getTokenImplClass()
                        + ". Defaulting to OAuthIssuerImpl";
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        }
        return oauthTokenIssuer;
    }

    private void parseUserConsentEnabledGrantTypesConfig(OMElement oauthConfigElem) {

        OMElement userConsentEnabledGrantTypesElement =
                oauthConfigElem
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.USER_CONSENT_ENABLED_GRANT_TYPES));

        if (userConsentEnabledGrantTypesElement != null) {
            Iterator iterator = userConsentEnabledGrantTypesElement
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.USER_CONSENT_ENABLED_GRANT_TYPE));

            while (iterator.hasNext()) {
                OMElement supportedGrantTypeElement = (OMElement) iterator.next();
                OMElement grantTypeNameElement = supportedGrantTypeElement
                        .getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.USER_CONSENT_ENABLED_GRANT_TYPE_NAME));
                String grantTypeName = null;
                if (grantTypeNameElement != null) {
                    grantTypeName = grantTypeNameElement.getText();
                }

                if (StringUtils.isNotEmpty(grantTypeName)) {
                    userConsentEnabledGrantTypes.add(grantTypeName);
                } else {
                    log.warn("Grant Type: " + grantTypeName + " is not a supported grant type. Therefore " +
                            "skipping it from user consent enabled grant type list.");
                }
            }

        } else {
            // Assume the default case.
            log.warn("<UserConsentEnabledGrantTypes> element in not found in identity.xml. Adding " +
                    "'authorization_code' and 'implicit' grant types as default user consent enabled grant types.");
            userConsentEnabledGrantTypes.add(OAuthConstants.GrantTypes.AUTHORIZATION_CODE);
            userConsentEnabledGrantTypes.add(OAuthConstants.GrantTypes.IMPLICIT);
        }
    }

    private void parseSupportedResponseTypesConfig(OMElement oauthConfigElem) {
        OMElement supportedRespTypesElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_RESP_TYPES));

        if (supportedRespTypesElem != null) {
            Iterator<OMElement> iterator = supportedRespTypesElem
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_RESP_TYPE));
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

                    // check for the configured hybrid response type
                    if (HYBRID_RESPONSE_TYPES.contains(responseTypeName)) {
                        configuredHybridResponseTypes.add(responseTypeName);
                    }
                    supportedResponseTypeClassNames.put(responseTypeName, responseTypeHandlerImplClass);
                    OMElement responseTypeValidatorClassNameElement = supportedResponseTypeElement
                            .getFirstChildWithName(
                                    getQNameWithIdentityNS(ConfigElements.RESPONSE_TYPE_VALIDATOR_IMPL_CLASS));

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
            log.warn("'SupportedResponseTypes' element not configured in identity.xml. " +
                    "Therefore instantiating default response type handlers");
            Map<String, String> defaultResponseTypes = new HashMap<>();
            defaultResponseTypes.put(ResponseType.CODE.toString(),
                    "org.wso2.carbon.identity.oauth2.authz.handlers.CodeResponseTypeHandler");
            defaultResponseTypes.put(ResponseType.TOKEN.toString(),
                    "org.wso2.carbon.identity.oauth2.authz.handlers.AccessTokenResponseTypeHandler");
            defaultResponseTypes.put(OAuthConstants.ID_TOKEN,
                    "org.wso2.carbon.identity.oauth2.authz.handlers.IDTokenResponseTypeHandler");
            defaultResponseTypes.put(OAuthConstants.IDTOKEN_TOKEN,
                    "org.wso2.carbon.identity.oauth2.authz.handlers.IDTokenTokenResponseTypeHandler");
            defaultResponseTypes.put(OAuthConstants.CODE_TOKEN,
                    "org.wso2.carbon.identity.oauth2.authz.handlers.HybridResponseTypeHandler");
            defaultResponseTypes.put(OAuthConstants.CODE_IDTOKEN,
                    "org.wso2.carbon.identity.oauth2.authz.handlers.HybridResponseTypeHandler");
            defaultResponseTypes.put(OAuthConstants.CODE_IDTOKEN_TOKEN,
                    "org.wso2.carbon.identity.oauth2.authz.handlers.HybridResponseTypeHandler");
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

    /**
     * This method is to read the config file for supported response modes
     * It gets response_mode_name : response_mode_class_name mapping and saves in
     * supportedResponseModeClassNames Map <String,String>
     * @param oauthConfigElem: oauth configs mentioned in identity.xml
     */
    private void parseSupportedResponseModesConfig(OMElement oauthConfigElem) {

        OMElement supportedRespModesElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_RESP_MODES));
        OMElement defaultRespModesElem = oauthConfigElem.getFirstChildWithName
                (getQNameWithIdentityNS(ConfigElements.DEFAULT_RESP_MODE_PROVIDER_CLASS));

        if (defaultRespModesElem != null) {
            defaultResponseModeProviderClassName = defaultRespModesElem.getText();
        } else {
            defaultResponseModeProviderClassName = DefaultResponseModeProvider.class.getCanonicalName();
        }

        if (supportedRespModesElem != null) {
            Iterator<OMElement> iterator = supportedRespModesElem
                    .getChildrenWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_RESP_MODE));
            while (iterator.hasNext()) {
                OMElement supportedResponseModeElement = iterator.next();
                OMElement responseModeNameElement = supportedResponseModeElement.
                        getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.RESP_MODE_NAME));
                String responseModeName = null;
                if (responseModeNameElement != null) {
                    responseModeName = responseModeNameElement.getText();
                }
                OMElement responseModeProviderClassElement =
                        supportedResponseModeElement.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.RESP_MODE_PROVIDER_CLASS));
                String responseModeProviderClass = null;
                if (responseModeProviderClassElement != null) {
                    responseModeProviderClass = responseModeProviderClassElement.getText();
                }
                if (responseModeName != null && !"".equals(responseModeName) &&
                        responseModeProviderClass != null && !"".equals(responseModeProviderClass)) {
                    supportedResponseModeProviderClassNames.put(responseModeName, responseModeProviderClass);

                }
            }
        } else {
            // if this element is not present, add the default response modes.
            log.warn("'SupportedResponseModes' element not configured in identity.xml. " +
                    "Therefore instantiating default response mode providers");
            Map<String, String> supportedResponseModeClassNamesTemp = new HashMap<>();
            supportedResponseModeClassNamesTemp.put(OAuthConstants.ResponseModes.QUERY,
                    QueryResponseModeProvider.class.getCanonicalName());
            supportedResponseModeClassNamesTemp.put(OAuthConstants.ResponseModes.FRAGMENT,
                    FragmentResponseModeProvider.class.getCanonicalName());
            supportedResponseModeClassNamesTemp.put(OAuthConstants.ResponseModes.FORM_POST,
                    FormPostResponseModeProvider.class.getCanonicalName());
            supportedResponseModeProviderClassNames.putAll(supportedResponseModeClassNamesTemp);
        }

        if (log.isDebugEnabled()) {
            for (Map.Entry entry : supportedResponseModeProviderClassNames.entrySet()) {
                String responseModeName = entry.getKey().toString();
                String responseModeProviderClass = entry.getValue().toString();
                log.debug(responseModeName + " supported by " + responseModeProviderClass);
            }
        }
    }

    private void parseSupportedClientAuthHandlersConfig(OMElement clientAuthElement) {

        if (clientAuthElement != null) {

            log.warn(
                    "\'SupportedClientAuthMethods\' is no longer supported (ClientAuthHandler in identity.xml). " +
                            "If you have customized ClientAuthHandler implementations migrate them");

            Iterator<OMElement> iterator = clientAuthElement.getChildrenWithLocalName(
                    ConfigElements.CLIENT_AUTH_HANDLER_IMPL_CLASS);
            while (iterator.hasNext()) {
                OMElement supportedClientAuthHandler = iterator.next();
                Iterator<OMElement> confProperties = supportedClientAuthHandler
                        .getChildrenWithLocalName(ConfigElements.CLIENT_AUTH_PROPERTY);
                Properties properties = new Properties();
                while (confProperties.hasNext()) {
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
                supportedClientAuthHandlerData.put(clientAuthHandlerImplClass, properties);
            }

        } else {

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
        OMElement saml2UserIdFromClaimElement = null;
        if (saml2GrantElement != null) {
            saml2BearerUserTypeElement = saml2GrantElement.getFirstChildWithName(getQNameWithIdentityNS
                    (ConfigElements.SAML2_BEARER_USER_TYPE));
            saml2TokenHandlerElement =
                    saml2GrantElement.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SAML2_TOKEN_HANDLER));
            saml2UserIdFromClaimElement = saml2GrantElement.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.
                    SAML2_USER_ID_FROM_CLAIMS));
        }
        if (saml2TokenHandlerElement != null && StringUtils.isNotBlank(saml2TokenHandlerElement.getText())) {
            saml2TokenCallbackHandlerName = saml2TokenHandlerElement.getText().trim();
        }
        if (saml2BearerUserTypeElement != null && StringUtils.isNotBlank(saml2BearerUserTypeElement.getText())) {
            saml2BearerTokenUserType = saml2BearerUserTypeElement.getText().trim();
        }
        if (saml2UserIdFromClaimElement != null && StringUtils.isNotBlank(saml2UserIdFromClaimElement.getText())) {
            saml2UserIdFromClaims = Boolean.parseBoolean(saml2UserIdFromClaimElement.getText().trim());
        }
    }

    private void parseAuthorizationContextTokenGeneratorConfig(OMElement oauthConfigElem) {
        OMElement authContextTokGenConfigElem =
                oauthConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.AUTHORIZATION_CONTEXT_TOKEN_GENERATION));
        if (authContextTokGenConfigElem != null) {
            OMElement enableJWTGenerationConfigElem =
                    authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLED));
            if (enableJWTGenerationConfigElem != null) {
                String enableJWTGeneration = enableJWTGenerationConfigElem.getText().trim();
                if (enableJWTGeneration != null && JavaUtils.isTrueExplicitly(enableJWTGeneration)) {
                    isAuthContextTokGenEnabled = true;
                    if (authContextTokGenConfigElem
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.TOKEN_GENERATOR_IMPL_CLASS)) !=
                            null) {
                        tokenGeneratorImplClass =
                                authContextTokGenConfigElem.getFirstChildWithName(
                                        getQNameWithIdentityNS(ConfigElements.TOKEN_GENERATOR_IMPL_CLASS))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(
                            getQNameWithIdentityNS(ConfigElements.CLAIMS_RETRIEVER_IMPL_CLASS)) != null) {
                        claimsRetrieverImplClass =
                                authContextTokGenConfigElem.getFirstChildWithName(
                                        getQNameWithIdentityNS(ConfigElements.CLAIMS_RETRIEVER_IMPL_CLASS))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.CONSUMER_DIALECT_URI)) !=
                            null) {
                        consumerDialectURI =
                                authContextTokGenConfigElem.getFirstChildWithName(
                                        getQNameWithIdentityNS(ConfigElements.CONSUMER_DIALECT_URI))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM)) !=
                            null) {
                        signatureAlgorithm =
                                authContextTokGenConfigElem.getFirstChildWithName(
                                        getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem
                            .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SECURITY_CONTEXT_TTL)) !=
                            null) {
                        authContextTTL =
                                authContextTokGenConfigElem.getFirstChildWithName(
                                        getQNameWithIdentityNS(ConfigElements.SECURITY_CONTEXT_TTL))
                                        .getText().trim();
                    }
                    if (authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                            ConfigElements.AUTH_CONTEXT_TOKEN_USE_MULTIVALUE_SEPARATOR)) != null) {
                        useMultiValueSeparatorForAuthContextToken =
                                Boolean.parseBoolean(
                                        authContextTokGenConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
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
                oauthConfigElem
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_REVOKE_RESPONSE_HEADERS));
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

    private void parseOAuthDeviceCodeGrantConfig(OMElement oauthElem) {

        OMElement oauthDeviceCodeGrantElement = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_GRANT));

        if (oauthDeviceCodeGrantElement != null && oauthDeviceCodeGrantElement
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_KEY_LENGTH)) != null) {
            try {
                deviceCodeKeyLength = Integer.parseInt(oauthDeviceCodeGrantElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_KEY_LENGTH)).getText()
                        .trim());
            } catch (NumberFormatException e) {
                log.error("Error while converting user_code length " + oauthDeviceCodeGrantElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_KEY_LENGTH)).getText()
                        .trim() + " to integer. Falling back to the default value.", e);
            }
        }
        if (oauthDeviceCodeGrantElement != null && oauthDeviceCodeGrantElement
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_EXPIRY_TIME)) != null) {
            try {
                deviceCodeExpiryTime = Long.parseLong(oauthDeviceCodeGrantElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_EXPIRY_TIME)).getText()
                        .trim());
            } catch (NumberFormatException e) {
                log.error("Error while converting device code expiry " + oauthDeviceCodeGrantElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_EXPIRY_TIME)).getText()
                        .trim() + " to long. Falling back to the default value.", e);
            }
        }
        if (oauthDeviceCodeGrantElement != null && oauthDeviceCodeGrantElement
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_POLLING_INTERVAL)) != null) {
            try {
                deviceCodePollingInterval =
                        Integer.parseInt(oauthDeviceCodeGrantElement.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_POLLING_INTERVAL)).getText().trim());
            } catch (NumberFormatException e) {
                log.error("Error while converting polling interval " + oauthDeviceCodeGrantElement
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_POLLING_INTERVAL))
                        .getText().trim() + " to integer. Falling back to the default value.", e);
            }
        }
        if (oauthDeviceCodeGrantElement != null && oauthDeviceCodeGrantElement
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_KEY_SET)) != null) {
            deviceCodeKeySet = oauthDeviceCodeGrantElement
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.DEVICE_CODE_KEY_SET)).getText().trim();
        }
    }

    private void parseOpenIDConnectConfig(OMElement oauthConfigElem) {

        OMElement openIDConnectConfigElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT));

        if (openIDConnectConfigElem != null) {

            // Get <RequestObjectBuilders> element defined under <OpenIDConnect> config.
            parseRequestObjectConfig(openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.REQUEST_OBJECT_BUILDERS)));

            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.
                    REQUEST_OBJECT_VALIDATOR)) != null) {
                defaultRequestValidatorClassName =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.
                                REQUEST_OBJECT_VALIDATOR)).getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.
                    CIBA_REQUEST_OBJECT_VALIDATOR)) != null) {
                defaultCibaRequestValidatorClassName =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.
                                CIBA_REQUEST_OBJECT_VALIDATOR)).getText().trim();
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_BUILDER)) !=
                    null) {
                openIDConnectIDTokenBuilderClassName =
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_BUILDER))
                                .getText().trim();
            }

            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM)) != null) {
                idTokenSignatureAlgorithm =
                        openIDConnectConfigElem
                                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SIGNATURE_ALGORITHM))
                                .getText().trim();
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.ID_TOKEN_ENCRYPTION_ALGORITHM)) != null) {
                defaultIdTokenEncryptionAlgorithm = openIDConnectConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.ID_TOKEN_ENCRYPTION_ALGORITHM)).getText().trim();
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.SUPPORTED_ID_TOKEN_ENCRYPTION_ALGORITHMS)) != null) {
                parseSupportedIdTokenEncryptionAlgorithms(openIDConnectConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.SUPPORTED_ID_TOKEN_ENCRYPTION_ALGORITHMS)));
            } else {
                // Hardcoding encryption algorithms due to migration concerns.
                supportedIdTokenEncryptionAlgorithms.add("RSA1_5");
                supportedIdTokenEncryptionAlgorithms.add("RSA-OAEP");
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.ID_TOKEN_ENCRYPTION_METHOD)) != null) {
                defaultIdTokenEncryptionMethod = openIDConnectConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.ID_TOKEN_ENCRYPTION_METHOD)).getText().trim();
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.SUPPORTED_ID_TOKEN_ENCRYPTION_METHODS)) != null) {
                parseSupportedIdTokenEncryptionMethods(openIDConnectConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.SUPPORTED_ID_TOKEN_ENCRYPTION_METHODS)));
            } else {
                // Hardcoding encryption methods due to migration concerns.
                supportedIdTokenEncryptionMethods.add("A128GCM");
                supportedIdTokenEncryptionMethods.add("A192GCM");
                supportedIdTokenEncryptionMethods.add("A256GCM");
                supportedIdTokenEncryptionMethods.add("A128CBC-HS256");
                supportedIdTokenEncryptionMethods.add("A128CBC+HS256");
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_CUSTOM_CLAIM_CALLBACK_HANDLER)) !=
                    null) {
                openIDConnectIDTokenCustomClaimsHanlderClassName =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_IDTOKEN_CUSTOM_CLAIM_CALLBACK_HANDLER))
                                .getText().trim();
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_SUB_CLAIM)) !=
                    null) {
                openIDConnectIDTokenSubClaim =
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_SUB_CLAIM))
                                .getText().trim();
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_USER_CONSENT)) !=
                    null) {
                openIDConnectSkipUserConsent = Boolean.parseBoolean(
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_USER_CONSENT))
                                .getText().trim());
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_LOGIN_CONSENT)) !=
                    null) {
                openIDConnectSkipLoginConsent = Boolean.parseBoolean(
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_LOGIN_CONSENT))
                                .getText().trim());
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_LOGOUT_CONSENT)) != null) {
                openIDConnectSkipLogoutConsent = Boolean.parseBoolean(
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SKIP_LOGOUT_CONSENT))
                                .getText().trim());
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_ISSUER_ID)) !=
                    null) {
                openIDConnectIDTokenIssuerIdentifier = IdentityUtil.fillURLPlaceholders(
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_IDTOKEN_ISSUER_ID)).getText().trim());
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_EXPIRATION)) !=
                    null) {
                openIDConnectIDTokenExpiration =
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_IDTOKEN_EXPIRATION))
                                .getText().trim();

                try {
                    openIDConnectIDTokenExpiryTimeInSeconds = Long.parseLong(openIDConnectIDTokenExpiration);
                } catch (NumberFormatException ex) {
                    log.warn(
                            "Invalid value: '" + openIDConnectIDTokenExpiration + "' set for ID Token Expiry Time in " +
                                    "Seconds. Value should be an integer. Setting expiry time to default value: " +
                                    openIDConnectIDTokenExpiryTimeInSeconds + " seconds.");
                }

            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_DIALECT)) != null) {
                openIDConnectUserInfoEndpointClaimDialect =
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_DIALECT))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_RETRIEVER)) != null) {
                openIDConnectUserInfoEndpointClaimRetriever =
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_RETRIEVER))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_REQUEST_VALIDATOR)) !=
                    null) {
                openIDConnectUserInfoEndpointRequestValidator =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_REQUEST_VALIDATOR))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_ACCESS_TOKEN_VALIDATOR)) !=
                    null) {
                openIDConnectUserInfoEndpointAccessTokenValidator =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_ACCESS_TOKEN_VALIDATOR))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_RESPONSE_BUILDER)) != null) {
                openIDConnectUserInfoEndpointResponseBuilder =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_USERINFO_ENDPOINT_RESPONSE_BUILDER))
                                .getText().trim();
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_JWT_SIGNATURE_ALGORITHM)) != null) {
                userInfoJWTSignatureAlgorithm =
                        openIDConnectConfigElem.getFirstChildWithName(
                                getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_JWT_SIGNATURE_ALGORITHM))
                                .getText().trim();
            }
            OMElement userInfoMultiValueSupportEnabledElem = openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_MULTI_VALUE_SUPPORT_ENABLED));
            if (userInfoMultiValueSupportEnabledElem != null) {
                userInfoMultiValueSupportEnabled = Boolean.parseBoolean(
                        userInfoMultiValueSupportEnabledElem.getText().trim());
            }

            OMElement userInfoResponseRemoveInternalPrefixFromRoles = openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_USERINFO_REMOVE_INTERNAL_PREFIX_FROM_ROLES));
            if (userInfoResponseRemoveInternalPrefixFromRoles != null) {
                userInfoRemoveInternalPrefixFromRoles =
                        Boolean.parseBoolean(userInfoResponseRemoveInternalPrefixFromRoles.getText().trim());
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SIGN_JWT_WITH_SP_KEY)) != null) {
                isJWTSignedWithSPKey = Boolean.parseBoolean(openIDConnectConfigElem.getFirstChildWithName(
                        getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_SIGN_JWT_WITH_SP_KEY)).getText().trim());
            }
            if (openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_CLAIMS)) != null) {
                String supportedClaimStr = openIDConnectConfigElem
                        .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.SUPPORTED_CLAIMS)).getText()
                        .trim();
                if (log.isDebugEnabled()) {
                    log.debug("Supported Claims : " + supportedClaimStr);
                }
                if (StringUtils.isNotEmpty(supportedClaimStr)) {
                    supportedClaims = supportedClaimStr.split(",");
                }
            }
            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_BACK_CHANNEL_LOGOUT_TOKEN_EXPIRATION)) !=
                    null) {

                openIDConnectBCLogoutTokenExpiryInSeconds =
                        openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                                ConfigElements.OPENID_CONNECT_BACK_CHANNEL_LOGOUT_TOKEN_EXPIRATION))
                                .getText().trim();
            }

            OMElement convertOriginalClaimsFromAssertionsToOIDCDialectElement = openIDConnectConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(
                            ConfigElements.OPENID_CONNECT_CONVERT_ORIGINAL_CLAIMS_FROM_ASSERTIONS_TO_OIDCDIALECT));
            if (convertOriginalClaimsFromAssertionsToOIDCDialectElement != null) {
                convertOriginalClaimsFromAssertionsToOIDCDialect = Boolean
                        .parseBoolean(convertOriginalClaimsFromAssertionsToOIDCDialectElement.getText().trim());
            }
            OMElement addUnmappedUserAttributesElement = openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.OPENID_CONNECT_ADD_UN_MAPPED_USER_ATTRIBUTES));
            if (addUnmappedUserAttributesElement != null) {
                addUnmappedUserAttributes = Boolean.parseBoolean(addUnmappedUserAttributesElement.getText().trim());
            }

            if (IdentityUtil.getProperty(ConfigElements.SEND_ONLY_LOCALLY_MAPPED_ROLES_OF_IDP) != null) {
                returnOnlyMappedLocalRoles = Boolean
                        .parseBoolean(IdentityUtil.getProperty(ConfigElements.SEND_ONLY_LOCALLY_MAPPED_ROLES_OF_IDP));
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                    .OPENID_CONNECT_ADD_TENANT_DOMAIN_TO_ID_TOKEN)) != null) {
                addTenantDomainToIdTokenEnabled =
                        Boolean.parseBoolean(openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS
                                (ConfigElements.OPENID_CONNECT_ADD_TENANT_DOMAIN_TO_ID_TOKEN)).getText().trim());
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                    .OPENID_CONNECT_ADD_USERSTORE_DOMAIN_TO_ID_TOKEN)) != null) {
                addUserstoreDomainToIdTokenEnabled =
                        Boolean.parseBoolean(openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS
                                (ConfigElements.OPENID_CONNECT_ADD_USERSTORE_DOMAIN_TO_ID_TOKEN)).getText().trim());
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                    .FAPI)) != null) {
                OMElement fapiElem = openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                        .FAPI));
                if (fapiElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                        .ENABLE_FAPI_CIBA_PROFILE)) != null) {
                    isFapiCiba =
                            Boolean.parseBoolean(fapiElem.getFirstChildWithName(getQNameWithIdentityNS
                                    (ConfigElements.ENABLE_FAPI_CIBA_PROFILE)).getText().trim());

                }
                if (fapiElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                        .ENABLE_FAPI_SECURITY_PROFILE)) != null) {
                    isFapiSecurity =
                            Boolean.parseBoolean(fapiElem.getFirstChildWithName(getQNameWithIdentityNS
                                    (ConfigElements.ENABLE_FAPI_SECURITY_PROFILE)).getText().trim());
                }
            }
            if (openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                    .REQUEST_OBJECT_ENABLED)) != null) {
                if (Boolean.FALSE.toString().equals(openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS
                        (ConfigElements.REQUEST_OBJECT_ENABLED)).getText().trim())) {
                    requestObjectEnabled = false;
                }
            }

            if (openIDConnectConfigElem.getFirstChildWithName(
                    getQNameWithIdentityNS(ConfigElements.SUPPORTED_TOKEN_ENDPOINT_SIGNING_ALGS)) != null) {
                try {
                    parseSupportedTokenEndpointSigningAlgorithms(openIDConnectConfigElem.getFirstChildWithName(
                            getQNameWithIdentityNS(ConfigElements.SUPPORTED_TOKEN_ENDPOINT_SIGNING_ALGS)));
                } catch (ServerConfigurationException e) {
                    log.error("Error while parsing supported token endpoint signing algorithms.", e);
                }
            }

            OMElement oAuthAuthzRequest = openIDConnectConfigElem.getFirstChildWithName(getQNameWithIdentityNS
                    (ConfigElements.OAUTH_AUTHZ_REQUEST_CLASS));
            oAuthAuthzRequestClassName = (oAuthAuthzRequest != null) ? oAuthAuthzRequest.getText().trim() :
                    DEFAULT_OAUTH_AUTHZ_REQUEST_CLASSNAME;
        }
    }

    /**
     * Parse supported encryption algorithms set and add them to supportedIdTokenEncryptionAlgorithms.
     *
     * @param algorithms OMElement of supported algorithms.
     */
    private void parseSupportedIdTokenEncryptionAlgorithms(OMElement algorithms) {

        if (algorithms == null) {
            return;
        }

        Iterator iterator = algorithms.getChildrenWithLocalName(
                ConfigElements.SUPPORTED_ID_TOKEN_ENCRYPTION_ALGORITHM);
        if (iterator != null) {
            while (iterator.hasNext()) {
                OMElement algorithm = (OMElement) iterator.next();
                if (algorithm != null) {
                    supportedIdTokenEncryptionAlgorithms.add(algorithm.getText());
                }
            }
        }
    }

    /**
     * Parse supported encryption methods set and add them to supportedIdTokenEncryptionMethods.
     *
     * @param methods OMElement of supported methods.
     */
    private void parseSupportedIdTokenEncryptionMethods(OMElement methods) {

        if (methods == null) {
            return;
        }

        Iterator iterator = methods.getChildrenWithLocalName(ConfigElements.SUPPORTED_ID_TOKEN_ENCRYPTION_METHOD);
        if (iterator != null) {
            for (; iterator.hasNext(); ) {
                OMElement method = (OMElement) iterator.next();
                if (method != null) {
                    supportedIdTokenEncryptionMethods.add(method.getText());
                }
            }
        }
    }

    private void parseHashAlgorithm(OMElement oauthConfigElem) {

        OMElement hashingAlgorithmElement = oauthConfigElem
                .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.HASH_ALGORITHM));
        if (hashingAlgorithmElement != null) {
            hashAlgorithm = hashingAlgorithmElement.getText();
        }
        if (log.isDebugEnabled()) {
            log.debug("Hash algorithm was set to : " + hashAlgorithm);
        }
    }

    private void parseEnableHashMode(OMElement oauthConfigElem) {

        try {
            persistenceProcessor = getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while getting an instance of TokenPersistenceProcessor.");
        }

        if (persistenceProcessor instanceof HashingPersistenceProcessor) {
            OMElement hashModeElement = oauthConfigElem
                    .getFirstChildWithName(getQNameWithIdentityNS(ConfigElements.ENABLE_CLIENT_SECRET_HASH));
            if (hashModeElement != null) {
                isClientSecretHashEnabled = Boolean.parseBoolean(hashModeElement.getText());
            }
            if (log.isDebugEnabled()) {
                log.debug("Is client secret hashing enabled: " + isClientSecretHashEnabled);
            }
        }
    }

    private void parseRedirectToOAuthErrorPageConfig(OMElement oauthConfigElem) {

        OMElement redirectToOAuthErrorPageElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                        .REDIRECT_TO_REQUESTED_REDIRECT_URI));
        if (redirectToOAuthErrorPageElem != null) {
            redirectToRequestedRedirectUriEnabled =
                    Boolean.parseBoolean(redirectToOAuthErrorPageElem.getText());
        }

        if (log.isDebugEnabled()) {
            log.debug("Redirecting to OAuth2 Error page is set to : " + redirectToOAuthErrorPageElem);
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

    public Map<String, TokenIssuerDO> getSupportedTokenIssuers() {
        return supportedTokenIssuers;
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
     * Parses the token renewal per request configuration.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseTokenRenewalPerRequestConfiguration(OMElement oauthConfigElem) {

        OMElement enableTokenRenewalElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.RENEW_TOKEN_PER_REQUEST));
        if (enableTokenRenewalElem != null) {
            isTokenRenewalPerRequestEnabled = Boolean.parseBoolean(enableTokenRenewalElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("RenewTokenPerRequest was set to : " + isTokenRenewalPerRequestEnabled);
        }
    }

    /**
     * Parses the map federated users to local configuration.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
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

    /**
     * This method populates oauthTokenIssuerMap by reading the supportedTokenIssuers map. Earlier we only
     * populated the oauthTokenIssuerMap when a token is issued but now we use this map for token validation
     * calls as well.
     */
    public void populateOAuthTokenIssuerMap() throws IdentityOAuth2Exception {

        if (supportedTokenIssuers != null) {
            for (Map.Entry<String, TokenIssuerDO> tokenIssuerDO : supportedTokenIssuers.entrySet()) {

                try {
                    Class clazz = Thread.currentThread().getContextClassLoader().loadClass(
                            tokenIssuerDO.getValue().getTokenImplClass());
                    OauthTokenIssuer oauthTokenIssuer = (OauthTokenIssuer) clazz.newInstance();
                    oauthTokenIssuer.setPersistAccessTokenAlias(tokenIssuerDO.getValue().isPersistAccessTokenAlias());
                    oauthTokenIssuerMap.put(tokenIssuerDO.getKey(), oauthTokenIssuer);

                } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                    throw new IdentityOAuth2Exception("Error while populating OAuth Token Issuer Map. Issuer key: " +
                            tokenIssuerDO.getKey() + ", Issuer value: " + tokenIssuerDO.getValue(), e);
                }
            }
        } else {
            throw new IdentityOAuth2Exception("supportedTokenIssuers map returned null when populating the " +
                    "oauthTokenIssuerMap object.");
        }
    }

    /**
     * This method returns the value of the property ScopeValidationEnabledForAuthzCodeAndImplicitGrant  for the OAuth
     * configuration
     * in identity.xml.
     */
    public boolean isScopeValidationEnabledForCodeAndImplicitGrant() {
        return scopeValidationConfigValue;
    }


    /**
     * Parses the AllowCrossTenantTokenIntrospection configuration that used to allow or block token introspection
     * from other tenants.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseAllowCrossTenantIntrospection(OMElement oauthConfigElem) {

        OMElement allowCrossTenantIntrospectionElem = oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.ALLOW_CROSS_TENANT_TOKEN_INTROSPECTION));
        if (allowCrossTenantIntrospectionElem != null) {
            allowCrossTenantIntrospection = Boolean.parseBoolean(allowCrossTenantIntrospectionElem.getText());
        }
    }

    /**
     * This method returns the value of the property AllowCrossTenantTokenIntrospection for the OAuth configuration
     * in identity.xml.
     */
    public boolean isCrossTenantTokenIntrospectionAllowed() {

        return allowCrossTenantIntrospection;
    }

    /**
     * Parses the UseClientIdAsSubClaimForAppTokens configuration that used to make the client id as the subject claim
     * in access tokens issued for authenticated applications.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseUseClientIdAsSubClaimForAppTokens(OMElement oauthConfigElem) {

        OMElement useClientIdAsSubClaimForAppTokensElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.USE_CLIENT_ID_AS_SUB_CLAIM_FOR_APP_TOKENS));
        if (useClientIdAsSubClaimForAppTokensElem != null) {
            useClientIdAsSubClaimForAppTokens =
                    Boolean.parseBoolean(useClientIdAsSubClaimForAppTokensElem.getText());
        }
    }

    /**
     * This method returns the value of the property UseClientIdAsSubClaimForAppTokens for the OAuth configuration
     * in identity.xml.
     */
    public boolean isUseClientIdAsSubClaimForAppTokensEnabled() {

        return useClientIdAsSubClaimForAppTokens;
    }

    /**
     * Parses the RemoveUsernameFromIntrospectionResponseForAppTokens configuration that used to remove username
     * from access tokens issued for authenticated applications.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseRemoveUsernameFromIntrospectionResponseForAppTokens(OMElement oauthConfigElem) {

        OMElement removeUsernameFromIntrospectionResponseForAppTokensElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.REMOVE_USERNAME_FROM_INTROSPECTION_RESPONSE_FOR_APP_TOKENS));
        if (removeUsernameFromIntrospectionResponseForAppTokensElem != null) {
            removeUsernameFromIntrospectionResponseForAppTokens =
                    Boolean.parseBoolean(removeUsernameFromIntrospectionResponseForAppTokensElem.getText());
        }
    }

    /**
     * This method returns the value of the property RemoveUsernameFromIntrospectionResponseForAppTokens for the OAuth
     * configuration in identity.xml.
     */
    public boolean isRemoveUsernameFromIntrospectionResponseForAppTokensEnabled() {

        return removeUsernameFromIntrospectionResponseForAppTokens;
    }

    /**
     * Parse the UseLegacyScopesAsAliasForNewScopes configuration that used to use legacy scopes as alias for
     * new scopes.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseUseLegacyScopesAsAliasForNewScopes(OMElement oauthConfigElem) {

        OMElement useLegacyScopesAsAliasForNewScopesElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.USE_LEGACY_SCOPES_AS_ALIAS_FOR_NEW_SCOPES));
        if (useLegacyScopesAsAliasForNewScopesElem != null) {
            useLegacyScopesAsAliasForNewScopes = Boolean.parseBoolean(useLegacyScopesAsAliasForNewScopesElem.getText());
        }
    }

    /**
     * This method returns the value of the property UseLegacyScopesAsAliasForNewScopes for the OAuth configuration in
     * identity.xml.
     *
     * @return true if the UseLegacyScopesAsAliasForNewScopes is enabled.
     */
    public boolean isUseLegacyScopesAsAliasForNewScopesEnabled() {

        return useLegacyScopesAsAliasForNewScopes;
    }

    /**
     * Parse the UseLegacyPermissionAccessForUserBasedAuth configuration that used to give legacy permission access in
     * user based authentication handlers.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseUseLegacyPermissionAccessForUserBasedAuth(OMElement oauthConfigElem) {

        OMElement useLegacyPermissionAccessForUserBasedAuthElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.USE_LEGACY_PERMISSION_ACCESS_FOR_USER_BASED_AUTH));
        if (useLegacyPermissionAccessForUserBasedAuthElem != null) {
            useLegacyPermissionAccessForUserBasedAuth =
                    Boolean.parseBoolean(useLegacyPermissionAccessForUserBasedAuthElem.getText());
        }
    }

    /**
     * This method returns the value of the property UseLegacyPermissionAccessForUserBasedAuth for the OAuth
     * configuration in identity.xml.
     *
     * @return true if the UseLegacyPermissionAccessForUserBasedAuth is enabled.
     */
    public boolean isUseLegacyPermissionAccessForUserBasedAuth() {

        return useLegacyPermissionAccessForUserBasedAuth;
    }

    private static void setOAuthResponseJspPageAvailable() {

        java.nio.file.Path path = Paths.get(CarbonUtils.getCarbonHome(), "repository", "deployment",
                "server", "webapps", "authenticationendpoint", "oauth_response.jsp");
        isOAuthResponseJspPageAvailable = Files.exists(path);
    }

    /**
     * Check if the oauth_response.jsp page is available.
     *
     * @return true if the oauth_response.jsp page is available.
     */
    public boolean isOAuthResponseJspPageAvailable() {

        return isOAuthResponseJspPageAvailable;
    }

    /**
     * This method returns if FAPI: Security profile is enabled for FAPI in identity.xml.
     */
    public boolean isFapiSecurity() {
        return isFapiSecurity;
    }

    public boolean isGlobalRbacScopeIssuerEnabled() {

        return globalRbacScopeIssuerEnabled;
    }

    public void setGlobalRbacScopeIssuerEnabled(boolean globalRbacScopeIssuerEnabled) {

        this.globalRbacScopeIssuerEnabled = globalRbacScopeIssuerEnabled;
    }

    public List<String> getSupportedTokenEndpointSigningAlgorithms() {

        return supportedTokenEndpointSigningAlgorithms;
    }

    /**
     * Parse supported signing algorithms and add them to the supportedTokenEndpointSigningAlgorithms list.
     *
     * @param algorithms OMElement of supported algorithms.
     */
    private void parseSupportedTokenEndpointSigningAlgorithms(OMElement algorithms)
            throws ServerConfigurationException {

        if (algorithms == null) {
            return;
        }

        Iterator iterator = algorithms.getChildrenWithLocalName(
                ConfigElements.SUPPORTED_TOKEN_ENDPOINT_SIGNING_ALG);
        if (iterator != null) {
            while (iterator.hasNext()) {
                OMElement algorithm = (OMElement) iterator.next();
                if (algorithm != null) {
                    try {
                        supportedTokenEndpointSigningAlgorithms.add(String.valueOf(
                                OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(algorithm.getText())));
                    } catch (IdentityOAuth2Exception e) {
                        throw new ServerConfigurationException("Unsupported signature algorithm configured.", e);
                    }
                }
            }
        }
    }

    /**
     * Parse the OAuth2ScopeMetadataExtensionImpl configuration that used to set the scope metadata extension impl
     * class.
     *
     * @param oauthConfigElem oauthConfigElem.
     */
    private void parseScopeMetadataExtensionImpl(OMElement oauthConfigElem) {

        OMElement scopeMetadataExtensionImplElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.SCOPE_METADATA_EXTENSION_IMPL));
        if (scopeMetadataExtensionImplElem != null) {
            scopeMetadataExtensionImpl = scopeMetadataExtensionImplElem.getText();
        }
    }

    private void parseRestrictedQueryParameters(OMElement oauthConfigElem) {

        OMElement restrictedQueryParametersElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.RESTRICTED_QUERY_PARAMETERS_ELEMENT));
        if (restrictedQueryParametersElem != null) {
            Iterator paramIterator = restrictedQueryParametersElem.getChildrenWithName(getQNameWithIdentityNS(
                    ConfigElements.RESTRICTED_QUERY_PARAMETER_ELEMENT));
            while (paramIterator.hasNext()) {
                OMElement paramElement = (OMElement) paramIterator.next();
                restrictedQueryParameters.add(paramElement.getText());
            }
        }
    }

    /**
     * Get scope metadata service extension impl class.
     *
     * @return ScopeMetadataExtensionImpl class name.
     */
    public String getScopeMetadataExtensionImpl() {

        return scopeMetadataExtensionImpl;
    }

    /**
     * Get JWTAccessTokenOIDCClaimsHandler
     *
     * @return JWTAccessTokenOIDCClaimsHandler
     */
    public CustomClaimsCallbackHandler getJWTAccessTokenOIDCClaimsHandler() {
        if (jwtAccessTokenOIDCClaimsHandler == null) {
            synchronized (CustomClaimsCallbackHandler.class) {
                if (jwtAccessTokenOIDCClaimsHandler == null) {
                    try {
                        Class clazz =
                                Thread.currentThread().getContextClassLoader()
                                        .loadClass(jwtAccessTokenOIDCClaimsHandlerClassName);
                        jwtAccessTokenOIDCClaimsHandler =
                                (CustomClaimsCallbackHandler) clazz.newInstance();
                    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                        log.error("Error while instantiating the JWTAccessTokenOIDCClaimsHandler ", e);
                    }
                }
            }
        }
        return jwtAccessTokenOIDCClaimsHandler;
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
        public static final String OAUTH2_PAR_EP_URL = "OAuth2ParEPUrl";
        public static final String OAUTH2_TOKEN_EP_URL = "OAuth2TokenEPUrl";
        public static final String OAUTH2_USERINFO_EP_URL = "OAuth2UserInfoEPUrl";
        public static final String OAUTH2_REVOCATION_EP_URL = "OAuth2RevokeEPUrl";
        public static final String OAUTH2_INTROSPECTION_EP_URL = "OAuth2IntrospectEPUrl";
        public static final String OAUTH2_CONSENT_PAGE_URL = "OAuth2ConsentPage";
        public static final String OAUTH2_DCR_EP_URL = "OAuth2DCREPUrl";
        public static final String OAUTH2_JWKS_PAGE_URL = "OAuth2JWKSPage";
        public static final String OIDC_WEB_FINGER_EP_URL = "OIDCWebFingerEPUrl";
        public static final String OIDC_DISCOVERY_EP_URL = "OIDCDiscoveryEPUrl";
        public static final String OAUTH2_ERROR_PAGE_URL = "OAuth2ErrorPage";
        public static final String OIDC_CONSENT_PAGE_URL = "OIDCConsentPage";
        public static final String DEVICE_AUTHZ_EP_URL = "OAuth2DeviceAuthzEPUrl";
        public static final String V2 = "V2";

        // JWT Generator
        public static final String AUTHORIZATION_CONTEXT_TOKEN_GENERATION = "AuthorizationContextTokenGeneration";
        public static final String ENABLED = "Enabled";
        public static final String TOKEN_GENERATOR_IMPL_CLASS = "TokenGeneratorImplClass";
        public static final String CLAIMS_RETRIEVER_IMPL_CLASS = "ClaimsRetrieverImplClass";
        public static final String CONSUMER_DIALECT_URI = "ConsumerDialectURI";
        public static final String SIGNATURE_ALGORITHM = "SignatureAlgorithm";
        public static final String ID_TOKEN_ENCRYPTION_ALGORITHM = "IDTokenEncryptionAlgorithm";
        public static final String SUPPORTED_ID_TOKEN_ENCRYPTION_ALGORITHMS = "SupportedIDTokenEncryptionAlgorithms";
        public static final String SUPPORTED_ID_TOKEN_ENCRYPTION_ALGORITHM = "SupportedIDTokenEncryptionAlgorithm";
        public static final String ID_TOKEN_ENCRYPTION_METHOD = "IDTokenEncryptionMethod";
        public static final String SUPPORTED_ID_TOKEN_ENCRYPTION_METHODS = "SupportedIDTokenEncryptionMethods";
        public static final String SUPPORTED_ID_TOKEN_ENCRYPTION_METHOD = "SupportedIDTokenEncryptionMethod";
        public static final String SECURITY_CONTEXT_TTL = "AuthorizationContextTTL";
        private static final String AUTH_CONTEXT_TOKEN_USE_MULTIVALUE_SEPARATOR = "UseMultiValueSeparator";

        public static final String ENABLE_ASSERTIONS = "EnableAssertions";
        public static final String ENABLE_ASSERTIONS_USERNAME = "UserName";
        public static final String ENABLE_ACCESS_TOKEN_PARTITIONING = "EnableAccessTokenPartitioning";
        public static final String REDIRECT_TO_REQUESTED_REDIRECT_URI = "RedirectToRequestedRedirectUri";
        public static final String ACCESS_TOKEN_PARTITIONING_DOMAINS = "AccessTokenPartitioningDomains";
        // OpenIDConnect configurations
        public static final String OPENID_CONNECT = "OpenIDConnect";
        public static final String OPENID_CONNECT_IDTOKEN_BUILDER = "IDTokenBuilder";
        public static final String OPENID_CONNECT_IDTOKEN_SUB_CLAIM = "IDTokenSubjectClaim";
        public static final String OPENID_CONNECT_IDTOKEN_ISSUER_ID = "IDTokenIssuerID";
        public static final String OPENID_CONNECT_IDTOKEN_EXPIRATION = "IDTokenExpiration";
        public static final String OPENID_CONNECT_SKIP_USER_CONSENT = "SkipUserConsent";
        public static final String OPENID_CONNECT_SKIP_LOGIN_CONSENT = "SkipLoginConsent";
        public static final String OPENID_CONNECT_SKIP_LOGOUT_CONSENT = "SkipLogoutConsent";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_DIALECT = "UserInfoEndpointClaimDialect";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_CLAIM_RETRIEVER = "UserInfoEndpointClaimRetriever";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_REQUEST_VALIDATOR =
                "UserInfoEndpointRequestValidator";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_ACCESS_TOKEN_VALIDATOR =
                "UserInfoEndpointAccessTokenValidator";
        public static final String OPENID_CONNECT_USERINFO_ENDPOINT_RESPONSE_BUILDER =
                "UserInfoEndpointResponseBuilder";
        public static final String OPENID_CONNECT_USERINFO_JWT_SIGNATURE_ALGORITHM = "UserInfoJWTSignatureAlgorithm";
        public static final String OPENID_CONNECT_USERINFO_MULTI_VALUE_SUPPORT_ENABLED =
                "UserInfoMultiValueSupportEnabled";
        public static final String OPENID_CONNECT_USERINFO_REMOVE_INTERNAL_PREFIX_FROM_ROLES =
                "UserInfoRemoveInternalPrefixFromRoles";
        public static final String OPENID_CONNECT_SIGN_JWT_WITH_SP_KEY = "SignJWTWithSPKey";
        public static final String OPENID_CONNECT_IDTOKEN_CUSTOM_CLAIM_CALLBACK_HANDLER =
                "IDTokenCustomClaimsCallBackHandler";
        public static final String OPENID_CONNECT_CONVERT_ORIGINAL_CLAIMS_FROM_ASSERTIONS_TO_OIDCDIALECT =
                "ConvertOriginalClaimsFromAssertionsToOIDCDialect";
        // Property to decide whether to add tenant domain to id_token.
        private static final String OPENID_CONNECT_ADD_TENANT_DOMAIN_TO_ID_TOKEN = "AddTenantDomainToIdToken";
        // Property to decide whether to add userstore domain to id_token.
        private static final String OPENID_CONNECT_ADD_USERSTORE_DOMAIN_TO_ID_TOKEN = "AddUserstoreDomainToIdToken";
        private static final String REQUEST_OBJECT_ENABLED = "RequestObjectEnabled";
        private static final String ENABLE_FAPI_CIBA_PROFILE = "EnableCibaProfile";
        private static final String ENABLE_FAPI_SECURITY_PROFILE = "EnableSecurityProfile";
        public static final String SEND_ONLY_LOCALLY_MAPPED_ROLES_OF_IDP = "FederatedRoleManagement"
                + ".ReturnOnlyMappedLocalRoles";
        public static final String OPENID_CONNECT_ADD_UN_MAPPED_USER_ATTRIBUTES = "AddUnmappedUserAttributes";
        public static final String SUPPORTED_CLAIMS = "OpenIDConnectClaims";
        public static final String REQUEST_OBJECT = "RequestObject";
        public static final String REQUEST_OBJECT_VALIDATOR = "RequestObjectValidator";
        public static final String OAUTH_AUTHZ_REQUEST_CLASS = "OAuthAuthzRequestClass";
        public static final String CIBA_REQUEST_OBJECT_VALIDATOR = "CIBARequestObjectValidator";
        public static final String OPENID_CONNECT_BACK_CHANNEL_LOGOUT_TOKEN_EXPIRATION = "LogoutTokenExpiration";
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
        private static final String ENABLE_GLOBAL_ROLE_BASED_SCOPE_ISSUER = "EnableGlobalRBACScopeIssuer";
        private static final String SCOPE_VALIDATOR = "OAuthScopeValidator";
        private static final String SCOPE_VALIDATORS = "ScopeValidators";
        private static final String SCOPE_VALIDATOR_ELEM = "ScopeValidator";
        private static final String SCOPE_VALIDATOR_PROPERTY = "Property";
        private static final String SCOPE_VALIDATOR_PROPERTY_NAME_ATTR = "name";
        private static final String SCOPE_CLASS_ATTR = "class";
        private static final String SKIP_SCOPE_ATTR = "scopesToSkip";
        private static final String IMPLICIT_ERROR_FRAGMENT = "ImplicitErrorFragment";

        // Enable/Disable scope validation for implicit grant and authorization code grant
        private static final String SCOPE_VALIDATION_FOR_AUTHZ_CODE_AND_IMPLICIT =
                "ScopeValidationEnabledForAuthzCodeAndImplicitGrant";

        // Default timestamp skew
        private static final String TIMESTAMP_SKEW = "TimestampSkew";
        // Enable password flow enhancements
        private static final String ENABLE_PASSWORD_FLOW_ENHANCEMENTS = "EnablePasswordFlowEnhancements";
        // Default validity periods
        private static final String AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD =
                "AuthorizationCodeDefaultValidityPeriod";
        private static final String USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD = "UserAccessTokenDefaultValidityPeriod";

        private static final String JARM_RESPONSE_JWT_DEFAULT_VALIDITY_PERIOD =
                "JARMResponseJwtValidityPeriodInSeconds";
        private static final String APPLICATION_ACCESS_TOKEN_VALIDATION_PERIOD = "AccessTokenDefaultValidityPeriod";
        private static final String REFRESH_TOKEN_VALIDITY_PERIOD = "RefreshTokenValidityPeriod";
        // Enable/Disable cache
        private static final String ENABLE_CACHE = "EnableOAuthCache";
        // Enable/Disable refresh token renewal on each refresh_token grant request
        private static final String RENEW_REFRESH_TOKEN_FOR_REFRESH_GRANT = "RenewRefreshTokenForRefreshGrant";
        // Enable/Disable Authenticated user validation on refresh_token grant request.
        private static final String VALIDATE_AUTHENTICATED_USER_FOR_REFRESH_GRANT =
                "ValidateAuthenticatedUserForRefreshGrant";
        // Enable/Disable extend the lifetime of the new refresh token
        private static final String EXTEND_RENEWED_REFRESH_TOKEN_EXPIRY_TIME = "ExtendRenewedRefreshTokenExpiryTime";
        // TokenPersistenceProcessor
        private static final String TOKEN_PERSISTENCE_PROCESSOR = "TokenPersistenceProcessor";
        // Token issuer generator.
        private static final String OAUTH_TOKEN_GENERATOR = "OAuthTokenGenerator";
        private static final String IDENTITY_OAUTH_TOKEN_GENERATOR = "IdentityOAuthTokenGenerator";
        private static final String CLIENT_ID_VALIDATE_REGEX = "ClientIdValidationRegex";

        // Persist token alias
        private static final String IDENTITY_OAUTH_PERSIST_TOKEN_ALIAS = "PersistAccessTokenAlias";
        //Old access token cleanup
        private static final String OAUTH2_TOKEN_CLEAN_ELEM = "TokenCleanup";
        // Enable/Disable old access token cleanup feature
        private static final String TOKEN_CLEANUP_FEATURE = "EnableTokenCleanup";
        // Enable/Disable retain old access token
        private static final String RETAIN_OLD_ACCESS_TOKENS = "RetainOldAccessToken";

        // Supported Grant Types
        private static final String SUPPORTED_GRANT_TYPES = "SupportedGrantTypes";
        private static final String SUPPORTED_GRANT_TYPE = "SupportedGrantType";
        private static final String GRANT_TYPE_NAME = "GrantTypeName";

        // Public client supported Grant Types
        private static final String PUBLIC_CLIENT_SUPPORTED_GRANT_TYPES = "PublicClientSupportedGrantTypes";
        private static final String PUBLIC_CLIENT_ENABLED_GRANT_TYPE_NAME = "GrantTypeName";

        //Supported Token Types
        private static final String SUPPORTED_TOKEN_TYPES = "SupportedTokenTypes";
        private static final String SUPPORTED_TOKEN_TYPE = "SupportedTokenType";
        private static final String TOKEN_TYPE_NAME = "TokenTypeName";

        private static final String USER_CONSENT_ENABLED_GRANT_TYPES = "UserConsentEnabledGrantTypes";
        private static final String USER_CONSENT_ENABLED_GRANT_TYPE = "UserConsentEnabledGrantType";
        private static final String USER_CONSENT_ENABLED_GRANT_TYPE_NAME = "GrantTypeName";

        private static final String ID_TOKEN_ALLOWED = "IdTokenAllowed";
        private static final String GRANT_TYPE_HANDLER_IMPL_CLASS = "GrantTypeHandlerImplClass";
        private static final String GRANT_TYPE_VALIDATOR_IMPL_CLASS = "GrantTypeValidatorImplClass";
        private static final String RESPONSE_TYPE_VALIDATOR_IMPL_CLASS = "ResponseTypeValidatorImplClass";
        private static final String TOKEN_TYPE_IMPL_CLASS = "TokenTypeImplClass";
        private static final String PUBLIC_CLIENT_ALLOWED = "PublicClientAllowed";
        // Supported Client Authentication Methods
        private static final String CLIENT_AUTH_HANDLERS = "ClientAuthHandlers";
        private static final String CLIENT_AUTH_HANDLER_IMPL_CLASS = "ClientAuthHandler";
        private static final String CLIENT_AUTH_CLASS = "Class";
        private static final String DEFAULT_CLIENT_AUTHENTICATOR =
                "org.wso2.carbon.identity.oauth2.token.handlers.clientauth.BasicAuthClientAuthHandler";
        private static final String CLIENT_AUTH_PROPERTY = "Property";
        private static final String CLIENT_AUTH_NAME = "Name";
        // Supported Response Types
        private static final String SUPPORTED_RESP_TYPES = "SupportedResponseTypes";
        private static final String SUPPORTED_RESP_TYPE = "SupportedResponseType";
        private static final String RESP_TYPE_NAME = "ResponseTypeName";
        private static final String RESP_TYPE_HANDLER_IMPL_CLASS = "ResponseTypeHandlerImplClass";
        // Supported Response Modes
        private static final String SUPPORTED_RESP_MODES = "SupportedResponseModes";
        private static final String SUPPORTED_RESP_MODE = "SupportedResponseMode";
        private static final String RESP_MODE_NAME = "ResponseModeName";
        private static final String RESP_MODE_PROVIDER_CLASS = "ResponseModeProviderClass";
        private static final String DEFAULT_RESP_MODE_PROVIDER_CLASS = "DefaultResponseModeProviderClass";
        // SAML2 assertion profile configurations
        private static final String SAML2_GRANT = "SAML2Grant";
        private static final String SAML2_TOKEN_HANDLER = "SAML2TokenHandler";
        private static final String SAML2_BEARER_USER_TYPE = "UserType";
        private static final String SAML2_USER_ID_FROM_CLAIMS = "UseUserIdFromClaims";

        // To enable revoke response headers
        private static final String ENABLE_REVOKE_RESPONSE_HEADERS = "EnableRevokeResponseHeaders";
        private static final String IDENTITY_OAUTH_SHOW_DISPLAY_NAME_IN_CONSENT_PAGE = "ShowDisplayNameInConsentPage";
        private static final String REFRESH_TOKEN_ALLOWED = "IsRefreshTokenAllowed";

        // Oauth access token value generator related.
        private static final String OAUTH_TOKEN_VALUE_GENERATOR = "AccessTokenValueGenerator";

        // Property to decide whether to pick the user tenant domain or SP tenant domain.
        private static final String OAUTH_USE_SP_TENANT_DOMAIN = "UseSPTenantDomain";
        private static final String MAP_FED_USERS_TO_LOCAL = "MapFederatedUsersToLocal";

        // Request Object Configs
        private static final String REQUEST_OBJECT_BUILDERS = "RequestObjectBuilders";
        private static final String REQUEST_OBJECT_BUILDER = "RequestObjectBuilder";
        private static final String BUILDER_TYPE = "Type";
        private static final String REQUEST_OBJECT_IMPL_CLASS = "ClassName";

        //Hash algorithm configs
        private static final String HASH_ALGORITHM = "HashAlgorithm";
        private static final String ENABLE_CLIENT_SECRET_HASH = "EnableClientSecretHash";

        // Token introspection Configs
        private static final String INTROSPECTION_CONFIG = "Introspection";
        private static final String ENABLE_DATA_PROVIDERS_CONFIG = "EnableDataProviders";

        // Enable/Disable token renewal on each request to the token endpoint
        private static final String RENEW_TOKEN_PER_REQUEST = "RenewTokenPerRequest";
        // Allowed Scopes Config.
        private static final String ALLOWED_SCOPES_ELEMENT = "AllowedScopes";
        // Allowed Default Requested Scopes Config.
        private static final String DEFAULT_REQUESTED_SCOPES_ELEMENT = "DefaultRequestedScopes";
        private static final String SCOPES_ELEMENT = "Scope";
        // Filtered Claims For Introspection Response Config.
        private static final String FILTERED_CLAIMS = "FilteredClaims";
        private static final String FILTERED_CLAIM = "FilteredClaim";
        private static final String GLOBAL_SCOPE_VALIDATORS = "GlobalScopeValidators";
        private static final String ROLE_BASED_SCOPE_ISSUER_ENABLED = "RoleBasedScopeIssuer";
        private static final String ENABLE = "Enable";

        private static final String DROP_UNREGISTERED_SCOPES = "DropUnregisteredScopes";

        private static final String DEVICE_CODE_GRANT = "DeviceCodeGrant";
        private static final String DEVICE_CODE_KEY_LENGTH = "KeyLength";
        private static final String DEVICE_CODE_EXPIRY_TIME = "ExpiryTime";
        private static final String DEVICE_CODE_POLLING_INTERVAL = "PollingInterval";
        private static final String PAR = "PAR";
        private static final String PAR_EXPIRY_TIME = "ExpiryTime";
        private static final String DEVICE_CODE_KEY_SET = "KeySet";

        // Allow Cross Tenant Introspection Config.
        private static final String ALLOW_CROSS_TENANT_TOKEN_INTROSPECTION = "AllowCrossTenantTokenIntrospection";

        private static final String USE_CLIENT_ID_AS_SUB_CLAIM_FOR_APP_TOKENS = "UseClientIdAsSubClaimForAppTokens";
        private static final String REMOVE_USERNAME_FROM_INTROSPECTION_RESPONSE_FOR_APP_TOKENS =
                "RemoveUsernameFromIntrospectionResponseForAppTokens";

        // FAPI Configurations
        private static final String FAPI = "FAPI";

        private static final String SKIP_OIDC_CLAIMS_FOR_CLIENT_CREDENTIAL_GRANT =
                "SkipOIDCClaimsForClientCredentialGrant";
        private static final String SUPPORTED_TOKEN_ENDPOINT_SIGNING_ALGS = "SupportedTokenEndpointSigningAlgorithms";
        private static final String SUPPORTED_TOKEN_ENDPOINT_SIGNING_ALG = "SupportedTokenEndpointSigningAlgorithm";
        private static final String USE_LEGACY_SCOPES_AS_ALIAS_FOR_NEW_SCOPES = "UseLegacyScopesAsAliasForNewScopes";
        private static final String USE_LEGACY_PERMISSION_ACCESS_FOR_USER_BASED_AUTH =
                "UseLegacyPermissionAccessForUserBasedAuth";
        private static final String SCOPE_METADATA_EXTENSION_IMPL = "ScopeMetadataService";
        private static final String RESTRICTED_QUERY_PARAMETERS_ELEMENT = "RestrictedQueryParameters";
        private static final String RESTRICTED_QUERY_PARAMETER_ELEMENT = "Parameter";
    }

}
