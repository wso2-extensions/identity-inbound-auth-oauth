/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.logging.Log;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SHOW_AUTHFAILURE_RESON_CONFIG;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

@WithCarbonHome
public class PasswordGrantHandlerTest {

    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private ApplicationManagementService applicationManagementService;
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    private ServiceProvider serviceProvider;
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;
    private RealmService realmService;
    private UserRealm userRealm;
    private AbstractUserStoreManager userStoreManager;
    private OAuthServerConfiguration serverConfiguration;
    private OauthTokenIssuer oauthIssuer;
    private LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig;

    private static final String CLIENT_ID = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";

    private Log mockLog;

    @BeforeMethod
    public void init() throws Exception {

        tokReqMsgCtx = mock(OAuthTokenReqMessageContext.class);
        oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        applicationManagementService = mock(ApplicationManagementService.class);
        fileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        serviceProvider = mock(ServiceProvider.class);
        oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
        realmService = mock(RealmService.class);
        userRealm = mock(UserRealm.class);
        userStoreManager = mock(AbstractUserStoreManager.class);
        serverConfiguration = mock(OAuthServerConfiguration.class);
        oauthIssuer = mock(OauthTokenIssuer.class);
        localAndOutboundAuthenticationConfig = mock(LocalAndOutboundAuthenticationConfig.class);
        mockLog = mock(Log.class);
        Field logField =
                PasswordGrantHandler.class.getDeclaredField("log");
        logField.setAccessible(true);

        // Remove the 'final' modifier using reflection
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(logField, logField.getModifiers() & ~Modifier.FINAL);

        // Set the static field to the mock object
        logField.set(null, mockLog);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setApplicationResidentOrganizationId(null);
    }

    @AfterMethod
    public void tearDown() {

        PrivilegedCarbonContext.endTenantFlow();
    }

    @DataProvider(name = "ValidateGrantDataProvider")
    public Object[][] buildScopeString() {
        return new Object[][]{
                {"randomUser", true},
                {"DOMAIN/randomUser", true},
                {"randomUser", false},
        };
    }

    @Test(dataProvider = "ValidateGrantDataProvider")
    public void testValidateGrant(String username, boolean isSaas) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class);
             MockedStatic<UserCoreUtil> userCoreUtil = mockStatic(UserCoreUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigBuilder = mockStatic(
                     FileBasedConfigurationBuilder.class)) {

            fileBasedConfigBuilder.when(FileBasedConfigurationBuilder::getInstance)
                    .thenReturn(fileBasedConfigurationBuilder);
            AuthenticatorConfig basicAuthenticatorConfig = new AuthenticatorConfig();
            Map<String, String> parameterMap = new HashMap<>();
            parameterMap.put(SHOW_AUTHFAILURE_RESON_CONFIG, "false");
            basicAuthenticatorConfig.setParameterMap(parameterMap);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(
                    basicAuthenticatorConfig);

            when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
            when(oAuth2AccessTokenReqDTO.getResourceOwnerUsername()).thenReturn(username + "wso2.com");
            when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(CLIENT_ID);
            when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("wso2.com");
            when(oAuth2AccessTokenReqDTO.getResourceOwnerPassword()).thenReturn("randomPassword");

            when(mockLog.isDebugEnabled()).thenReturn(true);

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(serverConfiguration);

            when(serverConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);

            multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn("wso2.com");
            multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(username);

            OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
            ResolvedUserResult resolvedUserResult = new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.FAIL);
            frameworkUtils.when(
                            () -> FrameworkUtils.processMultiAttributeLoginIdentification(anyString(), anyString())).
                    thenReturn(resolvedUserResult);
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(1);

            userCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn("DOMAIN");
            userCoreUtil.when(() -> UserCoreUtil.removeDomainFromName(anyString())).thenReturn("wso2.com");

//            mockStatic(OAuthComponentServiceHolder.class);
//            when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);
//
//            when(oAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);
            OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
            when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

            org.wso2.carbon.user.core.common.User userObj
                    = new org.wso2.carbon.user.core.common.User("c2de9b28-f258-4df0-ba29-f4803e4e821a",
                    username, username);
            userObj.setTenantDomain("dummyTenantDomain");
            resolvedUserResult.setUser(userObj);

            AuthenticationResult authenticationResult =
                    new AuthenticationResult(AuthenticationResult.AuthenticationStatus.SUCCESS);
            authenticationResult.setAuthenticatedUser(userObj);
            when(userStoreManager.authenticateWithID(eq(UserCoreClaimConstants.USERNAME_CLAIM_URI),
                    anyString(), any(), eq(UserCoreConstants.DEFAULT_PROFILE))).thenReturn(authenticationResult);

            when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                    .thenReturn(serviceProvider);
            when(serviceProvider.isSaasApp()).thenReturn(isSaas);
            when(serviceProvider.getLocalAndOutBoundAuthenticationConfig())
                    .thenReturn(localAndOutboundAuthenticationConfig);
            when(serviceProvider.getSpProperties()).thenReturn(new ServiceProviderProperty[0]);
            when(FrameworkUtils.preprocessUsername(anyString(), any(ServiceProvider.class)))
                    .thenReturn("randomUserwso2.com");

            when(localAndOutboundAuthenticationConfig.isUseUserstoreDomainInLocalSubjectIdentifier()).thenReturn(true);
            when(localAndOutboundAuthenticationConfig.isUseTenantDomainInLocalSubjectIdentifier()).thenReturn(true);

            PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();
            boolean isValid = passwordGrantHandler.validateGrant(tokReqMsgCtx);
            verify(mockLog, times(2)).debug(eq("PASSWORD_GRANT_POST_AUTHENTICATION event is triggered"));
            assertTrue(isValid, "Password grant validation should be successful");
        }
    }

    @DataProvider(name = "GetValidateGrantForExceptionDataProvider")
    public Object[][] validateGrantForExceptionDataProvider() {

        return new Object[][]{
                {"carbon.super", true, true, new IdentityApplicationManagementException("Error"),
                        "Error while retrieving service provider", false},
                {"carbon.super", true, true, new UserStoreException(), "Error while retrieving user store", false},
                {"carbon.super", true, true, new UserStoreException(
                        new AccountLockException(
                                "17003:AdminInitiated",
                                "Account is locked by admin for user: a*****r in user store: PRIMARY in tenant: " +
                                        "carbon.super. Cannot login until the account is unlocked.")),
                        "17003:AdminInitiated Account is locked by admin for user: a*****r in user store: PRIMARY in " +
                                "tenant: carbon.super. Cannot login until the account is unlocked.",
                        true},
                {"carbon.super", true, true, new UserStoreException(
                        new AccountLockException(
                                "17003:AdminInitiated",
                                "Account is locked by admin for user: a*****r in user store: PRIMARY in tenant: " +
                                        "carbon.super. Cannot login until the account is unlocked.")),
                        "Authentication failed for username",
                        false},
                {"wso2.com", false, true, null, "Authentication failed for user", false}
        };
    }

    @Test(dataProvider = "GetValidateGrantForExceptionDataProvider", expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantForException(String tenantDomain, boolean authenticated, boolean isSaas, Exception e,
                                              String reasonForError, boolean isShowAuthFailureReason) throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
             MockedStatic<MultitenantUtils> multitenantUtils = mockStatic(MultitenantUtils.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigBuilder = mockStatic(
                     FileBasedConfigurationBuilder.class)) {

            fileBasedConfigBuilder.when(FileBasedConfigurationBuilder::getInstance)
                    .thenReturn(fileBasedConfigurationBuilder);
            AuthenticatorConfig basicAuthenticatorConfig = new AuthenticatorConfig();
            Map<String, String> parameterMap = new HashMap<>();
            if (isShowAuthFailureReason) {
                parameterMap.put(SHOW_AUTHFAILURE_RESON_CONFIG, "true");
            } else {
                parameterMap.put(SHOW_AUTHFAILURE_RESON_CONFIG, "false");
            }
            basicAuthenticatorConfig.setParameterMap(parameterMap);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(
                    basicAuthenticatorConfig);

            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(serverConfiguration);
            when(serverConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);
            multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn(tenantDomain);

            when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
            when(oAuth2AccessTokenReqDTO.getResourceOwnerUsername()).thenReturn("username");
            when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(CLIENT_ID);
            when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("carbon.super");
            when(oAuth2AccessTokenReqDTO.getResourceOwnerPassword()).thenReturn("password");

            identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString()))
                    .thenReturn(PRIMARY_DEFAULT_DOMAIN_NAME);

            multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("username");

            OAuth2ServiceComponentHolder.setApplicationMgtService(applicationManagementService);
            OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
            ResolvedUserResult resolvedUserResult = new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.FAIL);
            frameworkUtils.when(
                            () -> FrameworkUtils.processMultiAttributeLoginIdentification(anyString(), anyString())).
                    thenReturn(resolvedUserResult);
            if (e instanceof IdentityApplicationManagementException) {
                when(applicationManagementService
                        .getServiceProviderByClientId(anyString(), anyString(), anyString())).thenThrow(e);
            } else {
                when(applicationManagementService
                        .getServiceProviderByClientId(anyString(), anyString(), anyString())).thenReturn(
                        serviceProvider);
                when(serviceProvider.isSaasApp()).thenReturn(isSaas);
                when(serviceProvider.getLocalAndOutBoundAuthenticationConfig())
                        .thenReturn(localAndOutboundAuthenticationConfig);
                when(serviceProvider.getSpProperties()).thenReturn(new ServiceProviderProperty[0]);
            }
            when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);

            if (e != null && e.getCause() instanceof AccountLockException) {
                when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
                when(userStoreManager.authenticateWithID(anyString(), anyString(), any(), anyString())).thenThrow(e);
            } else if (e instanceof UserStoreException) {
                when(userRealm.getUserStoreManager()).thenThrow(e);
            } else {
                when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
            }

            AuthenticationResult authenticationResult;

            if (authenticated) {
                org.wso2.carbon.user.core.common.User userObj
                        = new org.wso2.carbon.user.core.common.User("c2de9b28-f258-4df0-ba29-f4803e4e821a",
                        "username", "username");
                userObj.setTenantDomain("dummyTenantDomain");
                resolvedUserResult.setUser(userObj);
                authenticationResult = new AuthenticationResult(AuthenticationResult.AuthenticationStatus.SUCCESS);
                authenticationResult.setAuthenticatedUser(userObj);
            } else {
                authenticationResult = new AuthenticationResult(AuthenticationResult.AuthenticationStatus.FAIL);
            }

            if (e == null || !(e.getCause() instanceof AccountLockException)) {
                when(userStoreManager.authenticateWithID(eq(UserCoreClaimConstants.USERNAME_CLAIM_URI),
                        anyString(), any(), eq(UserCoreConstants.DEFAULT_PROFILE))).thenReturn(authenticationResult);
            }

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(1);
            frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(anyString(), any(ServiceProvider.class)))
                    .thenReturn("randomUserwso2.com");
            PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();

            if (e != null && e.getCause() instanceof AccountLockException) {
                try {
                    passwordGrantHandler.validateGrant(tokReqMsgCtx);
                } catch (IdentityOAuth2Exception ex) {
                    assertEquals(ex.getMessage(), reasonForError, "Error message should contain the " +
                            "account lock exception message");
                    throw ex;
                }
            } else {
                passwordGrantHandler.validateGrant(tokReqMsgCtx);
                fail("Password grant validation should fail with the reason " + reasonForError);
            }
        }
    }

    @Test
    public void testIssueRefreshToken() throws Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(serverConfiguration);
            when(serverConfiguration.getValueForIsRefreshTokenAllowed(anyString())).thenReturn(true);

            PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();
            boolean actual = passwordGrantHandler.issueRefreshToken();
            assertTrue(actual, "Refresh token issuance failed.");
        }
    }

}
