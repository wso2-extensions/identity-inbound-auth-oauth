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
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidator;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.lang.reflect.Field;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;

/**
 * Unit test for {@link AccessTokenIssuer}.
 */
@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class AccessTokenIssuerTest {

    private static final String ENABLE_POST_TOKEN_ISSUE_EVENT = "PostTokenIssueEvent.Enable";
    private final int testAppResidentTenantId = 1;
    private final String testAccessingOrganizationId = "dExLASaD1Flb_fx7ZecfAA3n1HRka";
    private final String testTenantDomain = "carbon.super";
    private final String testClientId = "dExLASaD1Flb_fx7ZecfAA3n1HRka";
    private final String testOrganizationId = "exLASaD1Flb_fx7ZecfAA3n1HRkaf";
    private final String testTokenId = "dExLASaD1Flb_fx7ZecfAA3n1HRka12345";
    private final String testApplicationName = "TestApplication";
    private AutoCloseable mocks;
    @Mock
    private IdentityConfigParser identityConfigParserMock;
    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolderMock;
    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfig;
    @Mock
    private OAuthAppDO appDO;

    @AfterClass
    public void cleanUp() throws Exception {

        PrivilegedCarbonContext.endTenantFlow();
        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
        mocks.close();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        setSystemProperties();
        clearAccessTokenIssuerInstance();
        mocks = openMocks(this);
    }

    @AfterMethod
    public void resetTest() throws Exception {

        clearAccessTokenIssuerInstance();
    }

    private void clearAccessTokenIssuerInstance() throws Exception {

        Field instanceField = AccessTokenIssuer.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
        instanceField.setAccessible(false);
    }

    private void setSystemProperties() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(testTenantDomain);
    }

    @DataProvider
    public Object[][] oAuth2AccessTokenReqDTODataProvider() {

        OAuth2AccessTokenReqDTO dto = mock(OAuth2AccessTokenReqDTO.class);
        OAuthClientAuthnContext context = mock(OAuthClientAuthnContext.class);
        when(dto.getClientId()).thenReturn(testClientId);
        when(dto.getGrantType()).thenReturn(OAuthConstants.GrantTypes.CLIENT_CREDENTIALS);
        when(dto.getScope()).thenReturn(new String[]{"scope1", "scope2"});
        when(dto.getTenantDomain()).thenReturn(testTenantDomain);
        when(dto.getoAuthClientAuthnContext()).thenReturn(context);
        when(context.isMultipleAuthenticatorsEngaged()).thenReturn(false);
        when(context.isAuthenticated()).thenReturn(true);
        return new Object[][]{{dto}, {dto}};
    }

    @Test(dataProvider = "oAuth2AccessTokenReqDTODataProvider")
    public void testTriggerPostIssueTokenEvent(OAuth2AccessTokenReqDTO dto) throws IdentityException,
            IdentityApplicationManagementException, UserStoreException, OrganizationManagementException {

        try (
                MockedStatic<LoggerUtils> loggerUtilsMockedStatic = mockStatic(LoggerUtils.class);
                MockedStatic<IdentityConfigParser> identityConfigParserMockedStatic
                        = mockStatic(IdentityConfigParser.class);
                MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic
                        = mockStatic(OAuthComponentServiceHolder.class);
                MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic
                        = mockStatic(OAuthServerConfiguration.class);
                MockedStatic<AuthorizationDetailsProcessorFactory> authorizationDetailsProcessorFactoryMockedStatic
                        = mockStatic(AuthorizationDetailsProcessorFactory.class);
                MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic
                        = mockStatic(OAuth2ServiceComponentHolder.class);
                MockedStatic<AppInfoCache> appInfoCacheMockedStatic = mockStatic(AppInfoCache.class);
                MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                MockedStatic<AuthzUtil> authzUtil = mockStatic(AuthzUtil.class);
                MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
                MockedStatic<OAuth2TokenUtil> oAuth2TokenUtil = mockStatic(OAuth2TokenUtil.class);
                MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)
        ) {
            OAuth2AccessTokenRespDTO tokenResp = mock(OAuth2AccessTokenRespDTO.class);
            when(tokenResp.getTokenId()).thenReturn(testTokenId);

            AuthorizationGrantHandler grantHandler = mock(AuthorizationGrantHandler.class);
            when(grantHandler.isAuthorizedClient(any())).thenReturn(true);
            when(grantHandler.validateGrant(any())).thenReturn(true);
            when(grantHandler.authorizeAccessDelegation(any())).thenReturn(true);
            when(grantHandler.validateScope(any())).thenReturn(true);
            when(grantHandler.issue(any())).thenReturn(tokenResp);

            Map<String, AuthorizationGrantHandler> supportedGrantTypes = new HashMap<>();
            supportedGrantTypes.put(OAuthConstants.GrantTypes.CLIENT_CREDENTIALS, grantHandler);
            when(mockedOAuthServerConfig.getSupportedGrantTypes()).thenReturn(supportedGrantTypes);
            oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockedOAuthServerConfig);
            try (
                    MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                loggerUtilsMockedStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
                identityConfigParserMockedStatic.when(IdentityConfigParser::getInstance)
                        .thenReturn(identityConfigParserMock);
                oAuthComponentServiceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance)
                        .thenReturn(oAuthComponentServiceHolderMock);

                authorizationDetailsProcessorFactoryMockedStatic.when(AuthorizationDetailsProcessorFactory::getInstance)
                        .thenReturn(mock(AuthorizationDetailsProcessorFactory.class));

                OAuthCache cache = mock(OAuthCache.class);
                oAuthCache.when(OAuthCache::getInstance).thenReturn(cache);
                when(oAuthComponentServiceHolderMock.getOAuthEventInterceptorProxy())
                        .thenReturn(mock(OAuthEventInterceptor.class));

                OrganizationManager organizationManager = mock(OrganizationManager.class);
                when(oAuthComponentServiceHolderMock.getOrganizationManager()).thenReturn(organizationManager);
                when(organizationManager.resolveOrganizationId(testTenantDomain)).thenReturn(testOrganizationId);

                OAuth2ServiceComponentHolder componentHolder = mock(OAuth2ServiceComponentHolder.class);
                when(componentHolder.getAuthorizationDetailsService())
                        .thenReturn(mock(AuthorizationDetailsService.class));
                when(componentHolder.getAuthorizationDetailsSchemaValidator())
                        .thenReturn(mock(AuthorizationDetailsSchemaValidator.class));
                oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getInstance)
                        .thenReturn(componentHolder);

                AppInfoCache appInfoCache = mock(AppInfoCache.class);
                appInfoCacheMockedStatic.when(AppInfoCache::getInstance).thenReturn(appInfoCache);

                AuthenticatedUser appOwner = mock(AuthenticatedUser.class);
                when(appOwner.getUserId()).thenReturn("12345");
                when(appOwner.getTenantDomain()).thenReturn(testTenantDomain);
                when(appOwner.getUserStoreDomain()).thenReturn("PRIMARY");
                when(appOwner.toFullQualifiedUsername()).thenReturn("PRIMARY/testUser@carbon.super");
                when(appOwner.getAccessingOrganization()).thenReturn(testAccessingOrganizationId);

                when(appDO.getState()).thenReturn(APP_STATE_ACTIVE);
                when(appDO.getAppOwner()).thenReturn(appOwner);

                ServiceProvider sp = mock(ServiceProvider.class);
                when(sp.getApplicationName()).thenReturn(testApplicationName);

                ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
                LocalAndOutboundAuthenticationConfig authConfig = mock(LocalAndOutboundAuthenticationConfig.class);
                when(authConfig.getSubjectClaimUri()).thenReturn("test.subject.claim.uri");
                when(sp.getLocalAndOutBoundAuthenticationConfig()).thenReturn(authConfig);
                when(appMgtService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                        .thenReturn(sp);
                when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(appMgtService);

                oAuth2Util.when(() -> OAuth2Util.isAppVersionAllowed(anyString(), anyString())).thenReturn(true);
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(appDO);
                oAuth2Util.when(() -> OAuth2Util.getServiceProvider(testClientId, testTenantDomain)).thenReturn(sp);

                UserRealm userRealm = mock(UserRealm.class);
                AbstractUserStoreManager userStore = mock(AbstractUserStoreManager.class);
                when(userStore.getUserClaimValueWithID(any(), any(), nullable(String.class)))
                        .thenReturn("testUserClaimValue");
                when(userRealm.getUserStoreManager()).thenReturn(userStore);

                identityTenantUtil.when(() -> IdentityTenantUtil.getRealm(any(), any())).thenReturn(userRealm);
                identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(testAppResidentTenantId);

                authzUtil.when(AuthzUtil::isLegacyAuthzRuntime).thenReturn(false);
                identityUtil.when(() -> IdentityUtil.getProperty(ENABLE_POST_TOKEN_ISSUE_EVENT)).thenReturn("true");
                AccessTokenIssuer.getInstance().issue(dto);

                oAuth2TokenUtil.verify(() -> OAuth2TokenUtil.postIssueToken(
                                argThat((eventProperties) -> {
                                            Assert.assertEquals(eventProperties.get(OIDCConstants.Event.TOKEN_ID),
                                                    testTokenId);
                                            Assert.assertEquals(eventProperties.get(OIDCConstants.Event.TENANT_DOMAIN),
                                                    testTenantDomain);
                                            Assert.assertEquals(eventProperties.get(OIDCConstants.Event.USER_TYPE),
                                                    OAuthConstants.UserType.APPLICATION);
                                            Assert.assertEquals(eventProperties.get(OIDCConstants.Event.CLIENT_ID),
                                                    testClientId);
                                            Assert.assertEquals(eventProperties.get(OIDCConstants.Event.GRANT_TYPE),
                                                    OAuthConstants.GrantTypes.CLIENT_CREDENTIALS);
                                            Assert.assertEquals(eventProperties.get(
                                                    OIDCConstants.Event.ISSUER_ORGANIZATION_ID), testOrganizationId);
                                            Assert.assertEquals(
                                                    eventProperties.get(OIDCConstants.Event.APP_RESIDENT_TENANT_ID),
                                                    testAppResidentTenantId);
                                            Assert.assertEquals(
                                                    eventProperties.get(OIDCConstants.Event.ACCESSING_ORGANIZATION_ID),
                                                    testAccessingOrganizationId);
                                            Assert.assertEquals(eventProperties.get(
                                                    OIDCConstants.Event.SERVICE_PROVIDER),
                                                    testApplicationName);
                                            return true;
                                        }
                                )),
                        times(1));
            }
        }
    }
}
