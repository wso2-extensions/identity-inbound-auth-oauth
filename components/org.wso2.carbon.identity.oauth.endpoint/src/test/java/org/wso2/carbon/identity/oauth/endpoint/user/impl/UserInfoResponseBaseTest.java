package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoClaimRetriever;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.ResourceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Base test case for UserInfoResponse.
 */
@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class, IdentityTenantUtil.class, RegistryService.class,
        AuthorizationGrantCache.class, ClaimUtil.class, IdentityUtil.class, UserInfoEndpointConfig.class})
public class UserInfoResponseBaseTest extends PowerMockTestCase {

    @Mock
    protected RegistryService registryService;
    @Mock
    protected UserRegistry userRegistry;
    @Mock
    protected OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    protected AuthorizationGrantCache authorizationGrantCache;
    @Mock
    protected AuthorizationGrantCacheEntry authorizationGrantCacheEntry;
    @Mock
    protected UserInfoEndpointConfig userInfoEndpointConfig;
    @Mock
    protected ApplicationManagementService applicationManagementService;
    protected Resource resource;
    protected UserInfoJSONResponseBuilder userInfoJSONResponseBuilder;
    protected final String FIRST_NAME = "first_name";
    protected final String LAST_NAME = "LAST_NAME";
    protected final String OIDC = "oidc";
    protected final String EMAIL = "email";
    protected final String SUB = "sub";
    protected static final String UPDATED_AT = "updated_at";
    protected static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    protected static final String EMAIL_VERIFIED = "email_verified";
    protected static final String ADDRESS = "address";
    protected static final String ADDRESS_PREFIX = "address.";
    protected static final String CLAIM_SEPARATOR = ",";

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @BeforeClass
    public void setUp() {
        userInfoJSONResponseBuilder = new UserInfoJSONResponseBuilder();
        resource = new ResourceImpl();
    }

    protected void mockOAuthServerConfiguration() throws Exception {
        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
    }

    protected void startTenantFlow(String tenantDomain) {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
    }

    protected void prepareRegistry(String[] claims, String[] scopes) throws Exception {
        Properties registryResourceProperties = new Properties();
        for (String scope : scopes) {
            List propertyValues = new ArrayList();
            for (String claim : claims) {
                propertyValues.add(claim);
            }
            registryResourceProperties.put(scope, propertyValues);
        }
        OAuth2ServiceComponentHolder.setRegistryService(registryService);
        when(registryService.getConfigSystemRegistry(anyInt())).thenReturn(userRegistry);
        resource.setProperties(registryResourceProperties);
        when(userRegistry.get(anyString())).thenReturn(resource);
    }

    protected OAuth2TokenValidationResponseDTO prepareTokenResponseDTO() {
        OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken authorizationContextToken =
                oAuth2TokenValidationResponseDTO.new AuthorizationContextToken("JWT", "1234567890");
        oAuth2TokenValidationResponseDTO.setAuthorizationContextToken(authorizationContextToken);
        oAuth2TokenValidationResponseDTO.setScope(new String[]{OIDC});

        return oAuth2TokenValidationResponseDTO;
    }

    protected void prepareAuthorizationGrantCache(boolean getClaimsFromCache) {
        mockStatic(AuthorizationGrantCache.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class))).thenReturn
                (authorizationGrantCacheEntry);
        Map userAttributes = new HashMap();
        if (getClaimsFromCache) {
            userAttributes.put("cachedClaim1", "cachedClaim1Value1");
            userAttributes.put("cachedClaim2", "cachedClaim1Value2");
        }
        when(authorizationGrantCacheEntry.getUserAttributes()).thenReturn(userAttributes);
    }

    protected void prepareClaimUtil(Map claims) throws Exception {
        mockStatic(ClaimUtil.class);
        when(ClaimUtil.getClaimsFromUserStore(any(OAuth2TokenValidationResponseDTO.class))).thenReturn(claims);
    }

    protected void prepareOAuth2Util() throws Exception {
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getClientIdForAccessToken(anyString())).thenReturn("mock_client_id");
        ArrayList userAttributesFromCache = new ArrayList();
        userAttributesFromCache.add("cachedClaim1");
        userAttributesFromCache.add("cachedClaim2");
        when(OAuth2Util.getEssentialClaims(anyString(), anyString())).thenReturn(userAttributesFromCache);
    }

    protected void prepareApplicationManagementService() throws Exception {
        ServiceProvider serviceProvider = new ServiceProvider();
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(new LocalAndOutboundAuthenticationConfig());
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setUseTenantDomainInLocalSubjectIdentifier(true);
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setUseUserstoreDomainInLocalSubjectIdentifier(true);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
    }

    protected void prepareIdentityUtil() {
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.extractDomainFromName(anyString())).thenReturn(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
    }

    protected void prepareUserInfoEndpointConfig() {
        UserInfoClaimRetriever claimsRetriever = mock(UserInfoClaimRetriever.class);
        mockStatic(UserInfoEndpointConfig.class);
        when(UserInfoEndpointConfig.getInstance()).thenReturn(userInfoEndpointConfig);
        when(claimsRetriever.getClaimsMap(any(Map.class))).thenReturn(new HashMap());
        when(userInfoEndpointConfig.getUserInfoClaimRetriever()).thenReturn(claimsRetriever);
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
}

