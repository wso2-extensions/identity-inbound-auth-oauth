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
import org.apache.commons.logging.LogFactory;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

@PrepareForTest({MultitenantUtils.class, OAuth2ServiceComponentHolder.class, IdentityTenantUtil.class, UserCoreUtil
        .class, OAuthComponentServiceHolder.class, OAuthServerConfiguration.class, LogFactory.class})
public class PasswordGrantHandlerTest {

    @Mock
    private Log log;
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
                {"randomUser", "wso2.com", "wso2.com", 1, true, "randomPassword", true, "DOMAIN", true, true},
                {"randomUser", "wso2.com", "wso2.com", 1, true, "randomPassword", true, "DOMAIN", true, false}
        };
    }

    @Test(dataProvider = "ValidateGrantDataProvider")
    public void testValidateGrant(String username, String appTenant, String userTenant, int userTenantId, boolean
            isSaas, String resourceOwnerPassword, boolean authenticate, String domain, boolean result, boolean
            debugEnabled) throws Exception {

        mockStatic(LogFactory.class);
        when(LogFactory.getLog(any(Class.class))).thenReturn(log);

        when(log.isDebugEnabled()).thenReturn(debugEnabled);
        doNothing().when(log).debug(any());
        doNothing().when(log).debug(any(), any(Throwable.class));

        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getResourceOwnerUsername()).thenReturn(username + userTenant);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn(clientId);
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn(appTenant);
        when(oAuth2AccessTokenReqDTO.getResourceOwnerPassword()).thenReturn(resourceOwnerPassword);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);

        when(serverConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthIssuer);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn(userTenant);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(username);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(userTenantId);

        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.getDomainFromThreadLocal()).thenReturn(domain);
        when(UserCoreUtil.removeDomainFromName(anyString())).thenReturn(userTenant);

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(oAuthComponentServiceHolder);

        when(oAuthComponentServiceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.authenticate(anyString(), any())).thenReturn(authenticate);

        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString())).thenReturn
                (serviceProvider);
        when(serviceProvider.isSaasApp()).thenReturn(isSaas);
        when(serviceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn(localAndOutboundAuthenticationConfig);

        when(localAndOutboundAuthenticationConfig.isUseUserstoreDomainInLocalSubjectIdentifier()).thenReturn(true);
        when(localAndOutboundAuthenticationConfig.isUseTenantDomainInLocalSubjectIdentifier()).thenReturn(true);

        PasswordGrantHandler passwordGrantHandler = new PasswordGrantHandler();
        assertTrue(passwordGrantHandler.validateGrant(tokReqMsgCtx));
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}