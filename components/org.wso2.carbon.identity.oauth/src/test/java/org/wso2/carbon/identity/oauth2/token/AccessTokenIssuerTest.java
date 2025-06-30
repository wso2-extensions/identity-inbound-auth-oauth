/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.oauth2.token;

import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidator;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;

/**
 * Unit test for {@link AccessTokenIssuer}.
 */
@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class AccessTokenIssuerTest {

    private AccessTokenIssuer instance;

    @Mock
    private IdentityConfigParser identityConfigParserMock;

    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolderMock;

    private final String jwt = "eyJ4NXQiOiJ4WFJRdkZUOFNtLUpQUEFrY0loNHlUTlhKTkkiLCJraWQiOiJNREExWXpKbU0yWmxZV1E1TldN"
            + "NE9EVXpaRFk1Wm1WaE5UazJOVEE0TURReFltRmlOakE0TkRKbVlqVXdNemd3TldSbE9XVmtZV0UxTUdFMFpU"
            + "ZzFNd19SUzI1NiIsInR5cCI6ImF0K2p3dCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJkRXhMQVNhRDFGbGJf"
            + "eDdaZWNmQUEzbjFIUmthIiwiYXV0IjoiQVBQTElDQVRJT04iLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5"
            + "NDQzL3Qvd3NvMi9vYXV0aDIvdG9rZW4iLCJjbGllbnRfaWQiOiJkRXhMQVNhRDFGbGJfeDdaZWNmQUEzbjFI"
            + "UmthIiwiYXVkIjoiZEV4TEFTYUQxRmxiX3g3WmVjZkFBM24xSFJrYSIsIm5iZiI6MTc1MTIxODUzNiwiYXpw"
            + "IjoiZEV4TEFTYUQxRmxiX3g3WmVjZkFBM24xSFJrYSIsIm9yZ19pZCI6IjA5MDdhNGEyLTZlZDktNDhlNC1h"
            + "YTZjLTc5NDkzNmE3OTgxYSIsInNjb3BlIjoicHJvZmlsZSIsImV4cCI6MTc1MTIyMjEzNiwib3JnX25hbWUi"
            + "OiJ3c28yIiwiaWF0IjoxNzUxMjE4NTM2LCJqdGkiOiI2YTFhOGQ0MS02YzRlLTRiNmYtYjkwNS00MDVhZTA0"
            + "MWVjYjAiLCJvcmdfaGFuZGxlIjoid3NvMiJ9.qiwViNy659M9hdqNWSCXoR7XP0e-1ZTFnuQOK-lbO6qfv-s"
            + "3PTwqwTLIEjFPXCXeFcrHA_UL5_41Klm12YbvodF87TtbLLqa1P50HHUxGUD9az6mLiJgdUHZeGrjrLFcGyf"
            + "HvADa3CmdDyXuKZw91Cos5fSE2DI1XuqfJXMExj3XYV5YNS_PURiLQjueFsZxaQF94qwAgPeIYJeXWLTBMya"
            + "8APTVJa5SIn_vkpepJ-lSBMKaOMphHvotoc1COZg6D8uUI2tvyRuY6U9G8_TuKVJ3sz1Yw7a00pdd1DnpPf4"
            + "QYUodY0IF2AJc0caspZahZnCJBK2YrqP8-P3RsJ1dJA";

    private final String testTenantDomain = "carbon.super";


    @BeforeSuite
    public void setUp() throws Exception {

        identityConfigParserMock = mock(IdentityConfigParser.class);
        oAuthComponentServiceHolderMock = mock(OAuthComponentServiceHolder.class);

        setSystemProperties();
        mockStaticDependencies();
        setupOAuthServerConfiguration();
        setupAuthorizationDetailsServices();
        setupApplicationManagementService();
        setupOAuthAppAndUserMocks();
        setupCacheMocks();
        instance = AccessTokenIssuer.getInstance();
    }

    private void setSystemProperties() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(testTenantDomain);
    }

    private void mockStaticDependencies() {

        mockStatic(LoggerUtils.class).when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        mockStatic(IdentityConfigParser.class).when(IdentityConfigParser::getInstance)
                .thenReturn(identityConfigParserMock);
        mockStatic(OAuthComponentServiceHolder.class).when(OAuthComponentServiceHolder::getInstance)
                .thenReturn(oAuthComponentServiceHolderMock);
    }

    private void setupOAuthServerConfiguration() throws IdentityOAuth2Exception {

        OAuthServerConfiguration mockedOAuthServerConfig = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class).when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockedOAuthServerConfig);

        AuthorizationGrantHandler grantHandler = mockGrantHandler();
        Map<String, AuthorizationGrantHandler> supportedGrantTypes = new HashMap<>();
        supportedGrantTypes.put("client_credentials", grantHandler);
        when(mockedOAuthServerConfig.getSupportedGrantTypes()).thenReturn(supportedGrantTypes);
    }

    private AuthorizationGrantHandler mockGrantHandler() throws IdentityOAuth2Exception {

        AuthorizationGrantHandler handler = mock(AuthorizationGrantHandler.class);
        when(handler.isAuthorizedClient(any())).thenReturn(true);
        when(handler.validateGrant(any())).thenReturn(true);
        when(handler.authorizeAccessDelegation(any())).thenReturn(true);
        when(handler.validateScope(any())).thenReturn(true);

        OAuth2AccessTokenRespDTO tokenResp = mock(OAuth2AccessTokenRespDTO.class);
        when(handler.issue(any())).thenReturn(tokenResp);
        when(tokenResp.getAccessToken()).thenReturn(jwt);
        return handler;
    }

    private void setupAuthorizationDetailsServices() {

        mockStatic(AuthorizationDetailsProcessorFactory.class)
                .when(AuthorizationDetailsProcessorFactory::getInstance)
                .thenReturn(mock(AuthorizationDetailsProcessorFactory.class));

        OAuth2ServiceComponentHolder componentHolder = mock(OAuth2ServiceComponentHolder.class);
        mockStatic(OAuth2ServiceComponentHolder.class)
                .when(OAuth2ServiceComponentHolder::getInstance).thenReturn(componentHolder);
        when(componentHolder.getAuthorizationDetailsService()).thenReturn(mock(AuthorizationDetailsService.class));
        when(componentHolder.getAuthorizationDetailsSchemaValidator())
                .thenReturn(mock(AuthorizationDetailsSchemaValidator.class));
    }

    private void setupApplicationManagementService() throws IdentityApplicationManagementException {

        ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
        ServiceProvider sp = mock(ServiceProvider.class);
        LocalAndOutboundAuthenticationConfig authConfig = mock(LocalAndOutboundAuthenticationConfig.class);
        when(authConfig.getSubjectClaimUri()).thenReturn("test.subject.claim.uri");
        when(sp.getLocalAndOutBoundAuthenticationConfig()).thenReturn(authConfig);
        when(appMgtService.getServiceProviderByClientId(anyString(), anyString(), anyString())).thenReturn(sp);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(appMgtService);
    }

    private void setupOAuthAppAndUserMocks() throws UserStoreException, IdentityException {

        OAuthAppDO appDO = mock(OAuthAppDO.class);
        when(appDO.getState()).thenReturn(APP_STATE_ACTIVE);

        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.getUserId()).thenReturn("12345");
        when(user.getTenantDomain()).thenReturn(testTenantDomain);
        when(user.getUserStoreDomain()).thenReturn("PRIMARY");
        when(user.toFullQualifiedUsername()).thenReturn("PRIMARY/testUser@carbon.super");
        when(appDO.getAppOwner()).thenReturn(user);

        AppInfoCache appInfoCache = mock(AppInfoCache.class);
        mockStatic(AppInfoCache.class).when(AppInfoCache::getInstance).thenReturn(appInfoCache);
        when(appInfoCache.getValueFromCache(any(), any())).thenReturn(appDO);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.isAppVersionAllowed(anyString(), anyString())).thenReturn(true);
        when(OAuth2Util.getAppInformationByClientId(anyString(), anyString())).thenReturn(appDO);

        UserRealm userRealm = mock(UserRealm.class);
        AbstractUserStoreManager userStore = mock(AbstractUserStoreManager.class);
        when(userStore.getUserClaimValueWithID(any(), any(), nullable(String.class)))
                .thenReturn("testUserClaimValue");
        when(userRealm.getUserStoreManager()).thenReturn(userStore);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getRealm(any(), any())).thenReturn(userRealm);

        mockStatic(AuthzUtil.class);
        when(AuthzUtil.isLegacyAuthzRuntime()).thenReturn(false);
    }

    private void setupCacheMocks() {

        AccessTokenDO tokenDO = mock(AccessTokenDO.class);
        when(tokenDO.getAppResidentTenantId()).thenReturn(-1);
        when(tokenDO.getAuthorizedOrganizationId()).thenReturn("wso2");

        OAuthCache cache = mock(OAuthCache.class);
        mockStatic(OAuthCache.class).when(OAuthCache::getInstance).thenReturn(cache);
        when(cache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(tokenDO);

        when(oAuthComponentServiceHolderMock.getOAuthEventInterceptorProxy())
                .thenReturn(mock(OAuthEventInterceptor.class));
    }

    @DataProvider
    public Object[][] oAuth2AccessTokenReqErrorDataProvider() {

        OAuth2AccessTokenReqDTO dto = mock(OAuth2AccessTokenReqDTO.class);
        OAuthClientAuthnContext context = mock(OAuthClientAuthnContext.class);
        when(dto.getoAuthClientAuthnContext()).thenReturn(context);
        when(context.isMultipleAuthenticatorsEngaged()).thenReturn(true);
        return new Object[][]{{dto}};
    }

    @DataProvider
    public Object[][] oAuth2AccessTokenReqDTODataProvider() {

        OAuth2AccessTokenReqDTO dto = mock(OAuth2AccessTokenReqDTO.class);
        OAuthClientAuthnContext context = mock(OAuthClientAuthnContext.class);
        when(dto.getClientId()).thenReturn("testClientId");
        when(dto.getGrantType()).thenReturn("client_credentials");
        when(dto.getScope()).thenReturn(new String[]{"scope1", "scope2"});
        when(dto.getTenantDomain()).thenReturn(testTenantDomain);
        when(dto.getoAuthClientAuthnContext()).thenReturn(context);
        when(context.isMultipleAuthenticatorsEngaged()).thenReturn(false);
        when(context.isAuthenticated()).thenReturn(true);
        return new Object[][]{{dto}};
    }

    @Test(dataProvider = "oAuth2AccessTokenReqErrorDataProvider")
    public void testTriggerPostIssueTokenEventWithError(OAuth2AccessTokenReqDTO dto) throws IdentityException {

        instance.issue(dto);
    }

    @Test(dataProvider = "oAuth2AccessTokenReqDTODataProvider")
    public void testTriggerPostIssueTokenEventWithJWT(OAuth2AccessTokenReqDTO dto) throws IdentityException {

        instance.issue(dto);
    }
}
