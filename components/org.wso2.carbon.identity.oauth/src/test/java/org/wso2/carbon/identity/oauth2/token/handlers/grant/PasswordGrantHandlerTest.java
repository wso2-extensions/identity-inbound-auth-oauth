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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isNull;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

@PrepareForTest(
        {
                MultitenantUtils.class,
                OAuth2ServiceComponentHolder.class,
                IdentityTenantUtil.class,
                UserCoreUtil.class,
                OAuthComponentServiceHolder.class,
                OAuthServerConfiguration.class
        }
)
public class PasswordGrantHandlerTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuthTokenReqMessageContext tokReqMsgCtx;
    @Mock
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    @Mock
    private ApplicationManagementService applicationManagementService;
    @Mock
    private ServiceProvider serviceProvider;
    @Mock
    private OAuthComponentServiceHolder oAuthComponentServiceHolder;
    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private OAuthServerConfiguration serverConfiguration;
    @Mock
    private OauthTokenIssuer oauthIssuer;
    @Mock
    private LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig;

    static final String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";

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

        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getResourceOwnerUsername()).thenReturn(username + "wso2.com");
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(clientId);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("wso2.com");
        when(oAuth2AccessTokenReqDTO.getResourceOwnerPassword()).thenReturn("randomPassword");

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);

        when(serverConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn("wso2.com");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(username);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(1);

        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.getDomainFromThreadLocal()).thenReturn("DOMAIN");
        when(UserCoreUtil.removeDomainFromName(anyString())).thenReturn("wso2.com");

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);

        when(oAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.authenticate(anyString(), any())).thenReturn(true);

        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(serviceProvider);
        when(serviceProvider.isSaasApp()).thenReturn(isSaas);
        when(serviceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn(localAndOutboundAuthenticationConfig);

        when(localAndOutboundAuthenticationConfig.isUseUserstoreDomainInLocalSubjectIdentifier()).thenReturn(true);
        when(localAndOutboundAuthenticationConfig.isUseTenantDomainInLocalSubjectIdentifier()).thenReturn(true);

        PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();
        boolean isValid = passwordGrantHandler.validateGrant(tokReqMsgCtx);
        assertTrue(isValid, "Password grant validation should be successful");
    }

    @DataProvider(name = "GetValidateGrantForExceptionDataProvider")
    public Object[][] validateGrantForExceptionDataProvider() {

        return new Object[][]{
                {"carbon.super", true, true, new IdentityApplicationManagementException("Error"), "Error while retrieving service provider"},
                {"carbon.super", true, true, new UserStoreException(), "Error while retrieving user store"},
                {"wso2.com", false, true, null, "Authentication failed for user"},
                {"wso2.com", true, false, null, "Cross tenant access of non Saas application"},

        };
    }

    @Test(dataProvider = "GetValidateGrantForExceptionDataProvider", expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantForException(String tenantDomain, boolean authenticated, boolean isSaas, Exception e,
                                              String reasonForError) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
        when(serverConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);
        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn(tenantDomain);

        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getResourceOwnerUsername()).thenReturn("username");
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(clientId);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("carbon.super");
        when(oAuth2AccessTokenReqDTO.getResourceOwnerPassword()).thenReturn("password");

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);
        OAuthComponentServiceHolder.getInstance().setRealmService(realmService);

        if (e instanceof IdentityApplicationManagementException) {
            when(applicationManagementService
                    .getServiceProviderByClientId(anyString(), anyString(), anyString())).thenThrow(e);
        } else {
            when(applicationManagementService
                    .getServiceProviderByClientId(anyString(), anyString(), anyString())).thenReturn(serviceProvider);
            when(serviceProvider.isSaasApp()).thenReturn(isSaas);
            when(serviceProvider.getLocalAndOutBoundAuthenticationConfig())
                    .thenReturn(localAndOutboundAuthenticationConfig);
        }
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userStoreManager.authenticate(anyString(), anyString())).thenReturn(authenticated);
        if (e instanceof UserStoreException) {
            when(userRealm.getUserStoreManager()).thenThrow(e);
        } else {
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        }

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(1);

        PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();
        passwordGrantHandler.validateGrant(tokReqMsgCtx);
        fail("Password grant validation should fail with the reason " + reasonForError);
    }

    @Test
    public void testIssueRefreshToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
        when(serverConfiguration.getValueForIsRefreshTokenAllowed(anyString())).thenReturn(true);

        PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();
        boolean actual = passwordGrantHandler.issueRefreshToken();
        assertTrue(actual, "Refresh token issuance failed.");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}