/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.ciba.api;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationContext;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class CibaAuthServiceImplTest {

    @Mock
    CibaMgtDAO cibaAuthMgtDAO;

    @Mock
    CibaDAOFactory cibaDAOFactory;

    @Mock
    CibaUserResolver cibaUserResolver;

    @Mock
    CibaNotificationChannel cibaNotificationChannel;

    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<CibaDAOFactory> cibaDAOFactoryStatic;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilder;

    private MockedStatic<org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration> oAuthServerConfiguration;

    private CibaAuthServiceImpl cibaAuthService;

    @BeforeMethod
    public void setUp() {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        cibaAuthService = new CibaAuthServiceImpl();

        // Mock Static classes - OAuthServerConfiguration first to prevent OAuth2Util
        // init failure
        oAuthServerConfiguration = mockStatic(org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.class);
        org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration mockOAuthServerConfig = mock(
                org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfig);

        oAuth2Util = mockStatic(OAuth2Util.class);
        cibaDAOFactoryStatic = mockStatic(CibaDAOFactory.class);
        serviceURLBuilder = mockStatic(ServiceURLBuilder.class);

        // Setup CarbonContext via PrivilegedCarbonContext
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");

        // Setup CibaDAOFactory
        cibaDAOFactoryStatic.when(CibaDAOFactory::getInstance).thenReturn(cibaDAOFactory);
        when(cibaDAOFactory.getCibaAuthMgtDAO()).thenReturn(cibaAuthMgtDAO);

        // Setup ServiceComponents
        CibaServiceComponentHolder.getInstance().setCibaUserResolver(cibaUserResolver);
        when(cibaNotificationChannel.getName()).thenReturn("test-channel");
        CibaServiceComponentHolder.getInstance().addNotificationChannel(cibaNotificationChannel);
    }

    @AfterMethod
    public void tearDown() {

        PrivilegedCarbonContext.endTenantFlow();
        oAuthServerConfiguration.close();
        oAuth2Util.close();
        cibaDAOFactoryStatic.close();
        serviceURLBuilder.close();

        // Reset holder
        CibaServiceComponentHolder.getInstance().setCibaUserResolver(null);
        CibaServiceComponentHolder.getInstance().removeNotificationChannel(cibaNotificationChannel);
    }

    @Test
    public void testGenerateAuthCodeResponse_Success() throws Exception {
        CibaAuthCodeRequest request = new CibaAuthCodeRequest();
        request.setIssuer("test-client");
        request.setUserHint("test-user-hint");
        request.setScopes(new String[] { "openid" });
        request.setBindingMessage("test-message");

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setCallbackUrl("http://callback.com");
        appDO.setCibaNotificationChannels("test-channel");
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId("test-client", "carbon.super"))
                .thenReturn(appDO);

        CibaUserResolver.ResolvedUser resolvedUser = new CibaUserResolver.ResolvedUser();
        resolvedUser.setUserId("resolved-user-id");
        resolvedUser.setTenantDomain("carbon.super");
        resolvedUser.setUsername("test-user");
        when(cibaUserResolver.resolveUser("test-user-hint", "carbon.super")).thenReturn(resolvedUser);

        // Mock ServiceURLBuilder chain
        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(anyString())).thenReturn(mockBuilder);
        when(mockBuilder.addParameter(anyString(), anyString())).thenReturn(mockBuilder);
        ServiceURL mockServiceURL = mock(ServiceURL.class);
        when(mockBuilder.build()).thenReturn(mockServiceURL);
        when(mockServiceURL.getAbsolutePublicURL()).thenReturn("http://auth-endpoint");

        when(cibaNotificationChannel.canHandle(any(CibaNotificationContext.class))).thenReturn(true);

        CibaAuthCodeResponse response = cibaAuthService.generateAuthCodeResponse(request);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAuthReqId());
        Assert.assertEquals(response.getClientId(), "test-client");
        verify(cibaAuthMgtDAO).persistCibaAuthCode(any(CibaAuthCodeDO.class));
        verify(cibaNotificationChannel).sendNotification(any(CibaNotificationContext.class));
    }

    @Test(expectedExceptions = CibaClientException.class)
    public void testGenerateAuthCodeResponse_InvalidClient() throws Exception {
        CibaAuthCodeRequest request = new CibaAuthCodeRequest();
        request.setIssuer("invalid-client");

        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId("invalid-client", "carbon.super"))
                .thenThrow(new InvalidOAuthClientException("Invalid client"));

        cibaAuthService.generateAuthCodeResponse(request);
    }

    @Test(expectedExceptions = CibaClientException.class, expectedExceptionsMessageRegExp = ".*public client.*")
    public void testGenerateAuthCodeResponse_PublicClient() throws Exception {

        CibaAuthCodeRequest request = new CibaAuthCodeRequest();
        request.setIssuer("public-client");

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setBypassClientCredentials(true);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId("public-client", "carbon.super"))
                .thenReturn(appDO);

        cibaAuthService.generateAuthCodeResponse(request);
    }

    @Test(expectedExceptions = CibaCoreException.class)
    public void testGenerateAuthCodeResponse_UserResolutionFail() throws Exception {

        CibaAuthCodeRequest request = new CibaAuthCodeRequest();
        request.setIssuer("test-client");
        request.setUserHint("unknown-user");

        OAuthAppDO appDO = new OAuthAppDO();
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId("test-client", "carbon.super"))
                .thenReturn(appDO);

        when(cibaUserResolver.resolveUser("unknown-user", "carbon.super")).thenReturn(null);

        cibaAuthService.generateAuthCodeResponse(request);
    }

    @Test
    public void testGenerateAuthCodeResponse_NotificationException() throws Exception {

        CibaAuthCodeRequest request = new CibaAuthCodeRequest();
        request.setIssuer("test-client");
        request.setUserHint("test-user-hint");

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setCibaNotificationChannels("test-channel");
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId("test-client", "carbon.super"))
                .thenReturn(appDO);

        CibaUserResolver.ResolvedUser resolvedUser = new CibaUserResolver.ResolvedUser();
        resolvedUser.setTenantDomain("carbon.super");
        when(cibaUserResolver.resolveUser("test-user-hint", "carbon.super")).thenReturn(resolvedUser);

        // Mock URL builder.
        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(anyString())).thenReturn(mockBuilder);
        when(mockBuilder.addParameter(anyString(), anyString())).thenReturn(mockBuilder);
        ServiceURL mockServiceURL = mock(ServiceURL.class);
        when(mockBuilder.build()).thenReturn(mockServiceURL);
        when(mockServiceURL.getAbsolutePublicURL()).thenReturn("http://auth-endpoint");

        // Force exception in notification.
        when(cibaNotificationChannel.canHandle(any(CibaNotificationContext.class))).thenReturn(true);
        Mockito.doThrow(new CibaCoreException("Notification failed")).when(cibaNotificationChannel)
                .sendNotification(any(CibaNotificationContext.class));

        // Should not throw exception.
        CibaAuthCodeResponse response = cibaAuthService.generateAuthCodeResponse(request);

        Assert.assertNotNull(response);
        // Persist should still happen.
        verify(cibaAuthMgtDAO).persistCibaAuthCode(any(CibaAuthCodeDO.class));
    }

    @Test(expectedExceptions = CibaClientException.class,
            expectedExceptionsMessageRegExp = ".*No notification channels configured.*")
    public void testGenerateAuthCodeResponse_NoNotificationChannelsConfigured() throws Exception {

        CibaAuthCodeRequest request = new CibaAuthCodeRequest();
        request.setIssuer("test-client");
        request.setUserHint("test-user-hint");

        // App with no notification channels configured.
        OAuthAppDO appDO = new OAuthAppDO();
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId("test-client", "carbon.super"))
                .thenReturn(appDO);

        CibaUserResolver.ResolvedUser resolvedUser = new CibaUserResolver.ResolvedUser();
        resolvedUser.setTenantDomain("carbon.super");
        when(cibaUserResolver.resolveUser("test-user-hint", "carbon.super")).thenReturn(resolvedUser);

        // Mock URL builder.
        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(anyString())).thenReturn(mockBuilder);
        when(mockBuilder.addParameter(anyString(), anyString())).thenReturn(mockBuilder);
        ServiceURL mockServiceURL = mock(ServiceURL.class);
        when(mockBuilder.build()).thenReturn(mockServiceURL);
        when(mockServiceURL.getAbsolutePublicURL()).thenReturn("http://auth-endpoint");

        // Should throw CibaClientException since no channels are configured for the app.
        cibaAuthService.generateAuthCodeResponse(request);
    }
}
