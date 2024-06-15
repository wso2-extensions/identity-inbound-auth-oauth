package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeClass;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.ResourceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Base test case for UserInfoResponse.
 */
public class UserInfoResponseBaseTest {

    public static final String AUTHORIZED_USER_FULL_QUALIFIED = "JDBC/peter@tenant.com";
    public static final String AUTHORIZED_USER_NAME = "peter";
    public static final String AUTHORIZED_USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff6";
    public static final String AUTHORIZED_USER_WITH_TENANT = "peter@tenant.com";
    public static final String AUTHORIZED_USER_WITH_DOMAIN = "JDBC/peter";
    public static final String TENANT_DOT_COM = "tenant.com";
    public static final String JDBC_DOMAIN = "JDBC";

    public static final String PRIMARY_USER_FULL_QUALIFIED = "PRIMARY/john@carbon.super";
    public static final String PRIMARY_USER_NAME = "john";
    public static final String PRIMARY_USER_WITH_TENANT = "john@carbon.super";
    public static final String PRIMARY_USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff2";

    public static final String SUBJECT_FULL_QUALIFIED = "JDBC/subject@tenant.com";
    public static final String SUBJECT = "subject";
    public static final String SUBJECT_WITH_TENANT = "subject@tenant.com";
    public static final String SUBJECT_WITH_DOMAIN = "JDBC/subject";
    public static final String FIRST_NAME_VALUE = "first_name_value";
    public static final String LAST_NAME_VALUE = "last_name_value";
    public static final String EMAIL_VALUE = "email@email.com";
    public static final String ESSENTIAL_CLAIM_JSON = "ESSENTIAL_CLAIM_JSON";

    protected static final String OIDC_SCOPE = "openid";

    protected static final String CLIENT_ID = "dummy_client_id";
    protected static final String UPDATED_AT = "updated_at";
    protected static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    protected static final String EMAIL_VERIFIED = "email_verified";
    protected static final String ADDRESS = "address";
    protected static final String ADDRESS_PREFIX = "address.";

    protected static final String SCOPE_CLAIM_URI_SEPARATOR = ",";
    public static final String CUSTOM_SCOPE = "customScope";
    public static final String CUSTOM_CLAIM = "custom_claim";

    public static final String CUSTOM_CLAIM_VALUE = "custom_claim_value";
    public static final String[] OIDC_SCOPE_ARRAY = new String[]{OIDC_SCOPE};
    private static final String DEFAULT_TOKEN_TYPE = "Default";
    private static final String JWT_TOKEN_TYPE = "JWT";
    private static final String SUBJECT_TYPE = "subject_type";
    private static final String PAIRWISE = "pairwise";
    private static final String SECTOR_IDENTIFIER_URI_VALUE = "https://mockhost.com/file_of_redirect_uris.json";
    private static final String MOCK_CLIENT_ID = "mock_client_id";

    @Mock
    private OAuthIssuer oAuthIssuer;
    @Mock
    protected RegistryService registryService;
    @Mock
    protected UserRegistry userRegistry;
    @Mock
    protected OAuthServerConfiguration mockOAuthServerConfiguration;
    @Mock
    protected AuthorizationGrantCache mockAuthorizationGrantCache;
    @Mock
    protected AuthorizationGrantCacheEntry authorizationGrantCacheEntry;
    @Mock
    protected UserInfoEndpointConfig mockUserInfoEndpointConfig;
    @Mock
    protected ApplicationManagementService applicationManagementService;
    protected Resource resource;
    protected final String firstName = "first_name";
    protected final String lastName = "last_name";
    protected final String email = "email";
    protected final String sub = "sub";

    protected final String accessToken = "dummyAccessToken";

    @BeforeClass
    public void setUp() {
        // Skipping filtering with user consent.
        // TODO: Remove mocking claims filtering based on consent when fixing
        // TODO: https://github.com/wso2/product-is/issues/2676
        OpenIDConnectClaimFilterImpl openIDConnectClaimFilter = spy(new OpenIDConnectClaimFilterImpl());
        when(openIDConnectClaimFilter
                .getClaimsFilteredByUserConsent(anyMap(), any(AuthenticatedUser.class), anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArguments()[0]);
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters().add(openIDConnectClaimFilter);
        resource = new ResourceImpl();
    }

    protected void startTenantFlow(String tenantDomain) {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
    }

    protected void prepareRegistry(Map<String, List<String>> oidcScopeMap) throws Exception {

        for (Map.Entry<String, List<String>> scopeMapEntry : oidcScopeMap.entrySet()) {
            resource.setProperty(scopeMapEntry.getKey(), scopeMapEntry.getValue());
        }
        OAuth2ServiceComponentHolder.setRegistryService(registryService);
        lenient().when(registryService.getConfigSystemRegistry(anyInt())).thenReturn(userRegistry);
        lenient().when(userRegistry.get(anyString())).thenReturn(resource);
    }

    protected OAuth2TokenValidationResponseDTO getTokenResponseDTO(String authorizedUser) {

        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken authorizationContextToken =
                oAuth2TokenValidationResponseDTO.new AuthorizationContextToken("Bearer", accessToken);

        oAuth2TokenValidationResponseDTO.setAuthorizedUser(authorizedUser);
        oAuth2TokenValidationResponseDTO.setAuthorizationContextToken(authorizationContextToken);
        oAuth2TokenValidationResponseDTO.setScope(new String[]{OIDC_SCOPE});

        return oAuth2TokenValidationResponseDTO;
    }

    protected OAuth2TokenValidationResponseDTO getTokenResponseDTO(String authorizedUser, String[] requestedScopes) {

        OAuth2TokenValidationResponseDTO tokenValidationResponseDTO = getTokenResponseDTO(authorizedUser);
        tokenValidationResponseDTO.setScope(requestedScopes);
        return tokenValidationResponseDTO;
    }

    protected void prepareAuthorizationGrantCache(boolean getClaimsFromCache,
                                                  MockedStatic<AuthorizationGrantCache> authorizationGrantCache) {

        authorizationGrantCache.when(AuthorizationGrantCache::getInstance).thenReturn(mockAuthorizationGrantCache);
        lenient().when(mockAuthorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class)))
                .thenReturn(authorizationGrantCacheEntry);
        Map userAttributes = new HashMap();
        if (getClaimsFromCache) {
            userAttributes.put("cachedClaim1", "cachedClaim1Value1");
            userAttributes.put("cachedClaim2", "cachedClaim1Value2");
        }
        lenient().when(authorizationGrantCacheEntry.getUserAttributes()).thenReturn(userAttributes);
    }

    protected void prepareClaimUtil(Map<String, Object> claims,
                                    MockedStatic<FrameworkUtils> frameworkUtils,
                                    MockedStatic<ClaimUtil> claimUtil) throws Exception {

        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");

        claimUtil.when(() -> ClaimUtil.getUserClaimsUsingTokenResponse(any(OAuth2TokenValidationResponseDTO.class)))
                .thenReturn(claims);
    }

    protected void prepareOAuth2Util(boolean isPairwiseSub, MockedStatic<OAuth2Util> oAuth2Util,
                                     MockedStatic<IdentityTenantUtil> identityTenantUtil) throws Exception {

        oAuth2Util.when(() -> OAuth2Util.getClientIdForAccessToken(anyString())).thenReturn(MOCK_CLIENT_ID);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(any(OAuthAppDO.class))).thenReturn(TENANT_DOT_COM);
        identityTenantUtil.when(()->IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(TENANT_DOT_COM);
        ArrayList<String> userAttributesFromCache = new ArrayList<>();
        userAttributesFromCache.add("cachedClaim1");
        userAttributesFromCache.add("cachedClaim2");
        oAuth2Util.when(() -> OAuth2Util.getEssentialClaims(anyString(), anyString()))
                .thenReturn(userAttributesFromCache);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setCallbackUrl("https://mockhost.com?test=test");
        if (isPairwiseSub) {
            oAuthAppDO.setSubjectType(PAIRWISE);
            oAuthAppDO.setSectorIdentifierURI(SECTOR_IDENTIFIER_URI_VALUE);
        }
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString())).thenReturn(oAuthAppDO);
    }

    protected void prepareApplicationManagementService(boolean appendTenantDomain,
                                                       boolean appendUserStoreDomain) throws Exception {

        ServiceProvider serviceProvider = new ServiceProvider();
        lenient().when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(new LocalAndOutboundAuthenticationConfig());
        serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .setUseTenantDomainInLocalSubjectIdentifier(appendTenantDomain);
        serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .setUseUserstoreDomainInLocalSubjectIdentifier(appendUserStoreDomain);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
    }

    protected void prepareUserInfoEndpointConfig(MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig) {

        UserInfoClaimRetriever claimsRetriever = mock(UserInfoClaimRetriever.class);
        userInfoEndpointConfig.when(UserInfoEndpointConfig::getInstance).thenReturn(mockUserInfoEndpointConfig);
        lenient().when(claimsRetriever.getClaimsMap(any(Map.class))).thenReturn(new HashMap<>());
        lenient().when(mockUserInfoEndpointConfig.getUserInfoClaimRetriever()).thenReturn(claimsRetriever);
    }

    protected Map getClaims(String[] inputClaims) {

        Map claimsMap = new HashMap();
        for (String claim : inputClaims) {
            if (claim.contains(":")) {
                String[] keyValue = claim.split(":");
                claimsMap.put(keyValue[0], keyValue[1]);
            } else if (UPDATED_AT.contains(claim)) {
                claimsMap.put(claim, System.currentTimeMillis());
            } else {
                claimsMap.put(claim, claim + "_value");
            }
        }
        return claimsMap;
    }

    protected Object[][] getSubjectClaimTestData() {
        final Map<String, Object> claimMapWithSubject = new HashMap<>();
        claimMapWithSubject.put(OAuth2Util.SUB, SUBJECT);
        AuthenticatedUser authzUserJDBCDomain = new AuthenticatedUser();
        authzUserJDBCDomain.setUserName(AUTHORIZED_USER_NAME);
        authzUserJDBCDomain.setTenantDomain(TENANT_DOT_COM);
        authzUserJDBCDomain.setUserStoreDomain(JDBC_DOMAIN);
        authzUserJDBCDomain.setUserId(AUTHORIZED_USER_ID);

        AuthenticatedUser authzUserPrimaryDomain = new AuthenticatedUser();
        authzUserPrimaryDomain.setUserName(PRIMARY_USER_NAME);
        authzUserPrimaryDomain.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        authzUserPrimaryDomain.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        authzUserPrimaryDomain.setUserId(PRIMARY_USER_ID);

        return new Object[][]{
                /*User claims, Authz user, Append Tenant Domain, Append User Store Domain,
                Is pairwise sub claim expected, Expected Subject Claim, Expected PPID*/
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), true, true, false,
                        AUTHORIZED_USER_FULL_QUALIFIED, null},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), true, false, false,
                        AUTHORIZED_USER_WITH_TENANT, null},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), false, true, false,
                        AUTHORIZED_USER_WITH_DOMAIN, null},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), false, false, false,
                        AUTHORIZED_USER_NAME, null},

                // Authorized user is from PRIMARY userstore domain
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), true, true, false,
                        PRIMARY_USER_WITH_TENANT, null},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), true, false, false,
                        PRIMARY_USER_WITH_TENANT, null},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), false, true, false,
                        PRIMARY_USER_NAME, null},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), false, false, false,
                        PRIMARY_USER_NAME, null},

                // Subject claim is in user claims
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), true, true, false,
                        SUBJECT_FULL_QUALIFIED, null},
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), true, false, false,
                        SUBJECT_WITH_TENANT, null},
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), false, true, false,
                        SUBJECT_WITH_DOMAIN, null},
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), false, false, false, SUBJECT, null},

                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), true, true, true,
                        AUTHORIZED_USER_FULL_QUALIFIED,
                        getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, AUTHORIZED_USER_FULL_QUALIFIED)},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), true, false, true,
                        AUTHORIZED_USER_WITH_TENANT,
                        getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, AUTHORIZED_USER_WITH_TENANT)},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), false, true, true,
                        AUTHORIZED_USER_WITH_DOMAIN,
                        getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, AUTHORIZED_USER_WITH_DOMAIN)},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserJDBCDomain), false, false, true,
                        AUTHORIZED_USER_NAME, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, AUTHORIZED_USER_NAME)},

                // Pairwise subject claims with subject claim is in user claims
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), true, true, true,
                        SUBJECT_FULL_QUALIFIED, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, SUBJECT_FULL_QUALIFIED)},
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), true, false, true,
                        SUBJECT_WITH_TENANT, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, SUBJECT_WITH_TENANT)},
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), false, true, true,
                        SUBJECT_WITH_DOMAIN, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, SUBJECT_WITH_DOMAIN)},
                {claimMapWithSubject, new AuthenticatedUser(authzUserJDBCDomain), false, false, true, SUBJECT,
                        getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, SUBJECT)},

                // Pairwise subject claims with authorized user is from PRIMARY userstore domain
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), true, true, true,
                        PRIMARY_USER_WITH_TENANT, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, PRIMARY_USER_WITH_TENANT)},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), true, false, true,
                        PRIMARY_USER_WITH_TENANT, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, PRIMARY_USER_WITH_TENANT)},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), false, true, true,
                        PRIMARY_USER_NAME, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, PRIMARY_USER_NAME)},
                {Collections.emptyMap(), new AuthenticatedUser(authzUserPrimaryDomain), false, false, true,
                        PRIMARY_USER_NAME, getNameUUID(SECTOR_IDENTIFIER_URI_VALUE, PRIMARY_USER_NAME)},
        };
    }

    private String getNameUUID(String uri, String subject) {

        return UUID.nameUUIDFromBytes((URI.create(uri).getHost() + subject)
                .getBytes(StandardCharsets.UTF_8)).toString();
    }

    protected void prepareForSubjectClaimTest(AuthenticatedUser authorizedUser,
                                              Map<String, Object> inputClaims,
                                              boolean appendTenantDomain,
                                              boolean appendUserStoreDomain, boolean isPairwiseSub,
                                              MockedStatic<AuthorizationGrantCache> authorizationGrantCache,
                                              MockedStatic<FrameworkUtils> frameworkUtils,
                                              MockedStatic<ClaimUtil> claimUtil,
                                              MockedStatic<OAuth2Util> oAuth2Util,
                                              MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                              MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig)
            throws Exception {

        startTenantFlow(SUPER_TENANT_DOMAIN_NAME);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        spy(OAuth2Util.class);

        prepareOAuth2Util(isPairwiseSub, oAuth2Util, identityTenantUtil);
        // Create an accessTokenDO
        mockAccessTokenDOInOAuth2Util(authorizedUser, oAuth2Util);

        prepareUserInfoEndpointConfig(userInfoEndpointConfig);
        prepareApplicationManagementService(appendTenantDomain, appendUserStoreDomain);

        prepareRegistry(Collections.emptyMap());
        prepareAuthorizationGrantCache(false, authorizationGrantCache);
        prepareClaimUtil(inputClaims, frameworkUtils, claimUtil);
    }

    protected void updateAuthenticatedSubjectIdentifier(AuthenticatedUser user, boolean appendTenantDomain,
                                                        boolean appendUserStoreDomain,
                                                        Map<String, Object> inputClaims) {

        String sub = user.getUserName();
        if (inputClaims.get(OAuth2Util.SUB) != null) {
            sub = (String) inputClaims.get(OAuth2Util.SUB);
        }
        if (appendUserStoreDomain
                && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(user.getUserStoreDomain())) {
            sub = user.getUserStoreDomain() + "/" + sub;
        }
        if (appendTenantDomain) {
            sub = sub + "@" + user.getTenantDomain();
        }
        user.setAuthenticatedSubjectIdentifier(sub);
    }

    protected void mockAccessTokenDOInOAuth2Util(AuthenticatedUser authorizedUser, MockedStatic<OAuth2Util> oAuth2Util)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAuthzUser(authorizedUser);
        accessTokenDO.setConsumerKey(MOCK_CLIENT_ID);
        accessTokenDO.setAccessToken(accessToken);
        oAuth2Util.when(() -> OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessToken)).thenReturn(accessTokenDO);
        oAuth2Util.when(() -> OAuth2Util.getAccessTokenDOFromTokenIdentifier(accessToken, false))
                .thenReturn(accessTokenDO);

        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUser(any(AccessTokenDO.class))).thenCallRealMethod();
        OauthTokenIssuer oauthTokenIssuer = new OauthTokenIssuerImpl();
        oAuth2Util.when(() -> OAuth2Util.getTokenIssuer(accessToken)).thenReturn(oauthTokenIssuer);
    }

    protected void prepareForResponseClaimTest(Map<String, Object> inputClaims,
                                               Map<String, List<String>> oidcScopeMap,
                                               boolean getClaimsFromCache,
                                               MockedStatic<AuthorizationGrantCache> authorizationGrantCache,
                                               MockedStatic<FrameworkUtils> frameworkUtils,
                                               MockedStatic<ClaimUtil> claimUtil,
                                               MockedStatic<OAuth2Util> oAuth2Util,
                                               MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                               MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig)
            throws Exception {

        startTenantFlow(SUPER_TENANT_DOMAIN_NAME);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        prepareOAuth2Util(false, oAuth2Util, identityTenantUtil);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(AUTHORIZED_USER_FULL_QUALIFIED);
        mockAccessTokenDOInOAuth2Util(authenticatedUser, oAuth2Util);

        prepareUserInfoEndpointConfig(userInfoEndpointConfig);
        prepareApplicationManagementService(true, true);

        prepareRegistry(oidcScopeMap);
        prepareAuthorizationGrantCache(getClaimsFromCache, authorizationGrantCache);
        prepareClaimUtil(inputClaims, frameworkUtils, claimUtil);
    }

    protected Object[][] getOidcScopeFilterTestData() {

        final Map<String, String> userClaimsMap = new HashMap<>();
        userClaimsMap.put(firstName, FIRST_NAME_VALUE);
        userClaimsMap.put(lastName, LAST_NAME_VALUE);
        userClaimsMap.put(email, EMAIL_VALUE);
        userClaimsMap.put(CUSTOM_CLAIM, CUSTOM_CLAIM_VALUE);

        // Map<"openid", "username,first_name,last_name">
        final Map<String, List<String>> oidcScopeMap = new HashMap<>();
        oidcScopeMap.put(OIDC_SCOPE, Collections.singletonList(firstName));

        final Map<String, Object> expectedClaimMap = new HashMap<>();
        expectedClaimMap.put(firstName, FIRST_NAME_VALUE);

        final Map<String, List<String>> oidcCustomScopeMap = new HashMap<>();
        oidcCustomScopeMap.put(OIDC_SCOPE, Collections.singletonList(firstName));
        oidcCustomScopeMap.put(CUSTOM_SCOPE, Collections.singletonList(CUSTOM_CLAIM));

        final Map<String, Object> expectedClaimMapForCustomScope = new HashMap<>();
        expectedClaimMapForCustomScope.put(firstName, FIRST_NAME_VALUE);

        return new Object[][]{
                // Input User Claims,
                // Map<"openid", ("first_name","username","last_name")>
                // Retrieve Claims From Cache
                // Expected Returned Claims,
                {
                        userClaimsMap,
                        oidcScopeMap,
                        false,
                        OIDC_SCOPE_ARRAY,
                        expectedClaimMap
                },
                {
                        userClaimsMap,
                        oidcCustomScopeMap,
                        false,
                        new String[]{OIDC_SCOPE, CUSTOM_SCOPE},
                        expectedClaimMapForCustomScope
                }
                ,
                {
                        userClaimsMap,
                        Collections.emptyMap(),
                        false,
                        OIDC_SCOPE_ARRAY,
                        Collections.emptyMap()
                }
        };
    }

    protected void initSingleClaimTest(String claimUri, String claimValue,
                                       MockedStatic<AuthorizationGrantCache> authorizationGrantCache,
                                       MockedStatic<FrameworkUtils> frameworkUtils,
                                       MockedStatic<ClaimUtil> claimUtil,
                                       MockedStatic<OAuth2Util> oAuth2Util,
                                       MockedStatic<IdentityTenantUtil> identityTenantUtil,
                                       MockedStatic<UserInfoEndpointConfig> userInfoEndpointConfig)
            throws Exception {

        final Map<String, Object> inputClaims = new HashMap<>();
        inputClaims.put(claimUri, claimValue);

        final Map<String, List<String>> oidcScopeMap = new HashMap<>();
        oidcScopeMap.put(OIDC_SCOPE, Collections.singletonList(claimUri));

        prepareForResponseClaimTest(inputClaims, oidcScopeMap, false,
                authorizationGrantCache, frameworkUtils, claimUtil, oAuth2Util, identityTenantUtil,
                userInfoEndpointConfig);
    }

    protected void assertSubjectClaimPresent(Map<String, Object> claimsInResponse) {

        assertNotNull(claimsInResponse);
        assertFalse(claimsInResponse.isEmpty());
        assertNotNull(claimsInResponse.get(sub));
    }

    protected void mockObjectsRelatedToTokenValidation(MockedStatic<OAuth2Util> oAuth2Util) throws Exception {

        when(mockOAuthServerConfiguration.getOAuthTokenGenerator()).thenReturn(oAuthIssuer);
        when(mockOAuthServerConfiguration.getSignatureAlgorithm()).thenReturn("SHA256withRSA");
        oAuth2Util.when(() -> OAuth2Util.getAccessTokenIdentifier(any())).thenCallRealMethod();
        oAuth2Util.when(() -> OAuth2Util.findAccessToken(anyString(), anyBoolean())).thenCallRealMethod();
        oAuth2Util.when(() -> OAuth2Util.getAccessTokenDO(any())).thenCallRealMethod();

//        when(OAuth2Util.class, "getAccessTokenDOFromMatchingTokenIssuer", anyString(), anyMap(), anyBoolean()).
//                thenCallRealMethod();

        Map<String, OauthTokenIssuer> oauthTokenIssuerMap = new HashMap<>();
        oauthTokenIssuerMap.put(DEFAULT_TOKEN_TYPE, new OauthTokenIssuerImpl());
        oauthTokenIssuerMap.put(JWT_TOKEN_TYPE, new JWTTokenIssuer());
        when(mockOAuthServerConfiguration.getOauthTokenIssuerMap()).thenReturn(oauthTokenIssuerMap);
    }
}
