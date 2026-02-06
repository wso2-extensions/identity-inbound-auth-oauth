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

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver.ResolvedUser;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CibaUserNotificationHandlerTest {

    private CibaUserNotificationHandler cibaUserNotificationHandler;

    @Mock
    private CibaNotificationChannel channel1;

    @Mock
    private CibaNotificationChannel channel2;

    @Mock
    private OAuthAppDO oAuthAppDO;

    private MockedStatic<ServiceURLBuilder> serviceURLBuilder;
    private ServiceURLBuilder mockServiceURLBuilder;
    private ServiceURL mockServiceURL;

    private CibaAuthCodeDO cibaAuthCodeDO;
    private ResolvedUser resolvedUser;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        cibaUserNotificationHandler = new CibaUserNotificationHandler();

        cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setCibaAuthCodeKey("auth-code-key");

        resolvedUser = new ResolvedUser();
        resolvedUser.setUsername("testUser");
        resolvedUser.setTenantDomain("carbon.super");

        mockServiceURLBuilder = mock(ServiceURLBuilder.class);
        mockServiceURL = mock(ServiceURL.class);
        serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.addParameter(anyString(), anyString())).thenReturn(mockServiceURLBuilder);
        when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
        when(mockServiceURL.getAbsolutePublicURL())
                .thenReturn("http://localhost:9443/authenticationendpoint/ciba_auth.jsp");

        // Clear existing channels and add mocks
        clearChannels();
    }

    @AfterMethod
    public void tearDown() {
        serviceURLBuilder.close();
        clearChannels();
    }

    private void clearChannels() {
        List<CibaNotificationChannel> channels = new ArrayList<>(
                CibaServiceComponentHolder.getInstance().getNotificationChannels());
        for (CibaNotificationChannel channel : channels) {
            CibaServiceComponentHolder.getInstance().removeNotificationChannel(channel);
        }
    }

    @Test(expectedExceptions = CibaCoreException.class, expectedExceptionsMessageRegExp = "Resolved user cannot " +
            "be null")
    public void testSendNotificationNullUser() throws Exception {

        cibaUserNotificationHandler.sendNotification(null, cibaAuthCodeDO, "message",
                oAuthAppDO);
    }

    @Test(expectedExceptions = CibaCoreException.class, expectedExceptionsMessageRegExp = "CibaAuthCodeDO cannot " +
            "be null")
    public void testSendNotificationNullAuthCodeDO() throws Exception {
        cibaUserNotificationHandler.sendNotification(resolvedUser, null, "message", oAuthAppDO);
    }

    @Test
    public void testSendNotificationNoChannels() throws Exception {
        // No channels added
        cibaUserNotificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, "message", oAuthAppDO);
        // Should confirm no exception and log warning (verified by coverage or spy logs
        // if possible, else logic pass)
    }

    @Test
    public void testSendNotificationSuccess() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        when(channel1.canHandle(any(), any(), anyString())).thenReturn(true);
        when(oAuthAppDO.isCibaSendNotificationToAllChannels()).thenReturn(false);

        cibaUserNotificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, "message", oAuthAppDO);

        verify(channel1).sendNotification(any(), any(), anyString(), anyString(), anyString());
    }

    @Test
    public void testSendNotificationMultipleChannelsPriority() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel2);

        when(channel1.getPriority()).thenReturn(10);
        when(channel2.getPriority()).thenReturn(20);

        when(channel1.canHandle(any(), any(), anyString())).thenReturn(true);
        when(oAuthAppDO.isCibaSendNotificationToAllChannels()).thenReturn(false);

        cibaUserNotificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, "message", oAuthAppDO);

        // Since channel1 has lower priority number (assuming standard WSO2 priority
        // where lower executes first?
        // Or higher? The logic says:
        // notificationChannels.sort(Comparator.comparingInt(CibaNotificationChannel::getPriority));
        // So small numbers first.
        verify(channel1).sendNotification(any(), any(), anyString(), anyString(), anyString());
        verify(channel2, never()).sendNotification(any(), any(), anyString(), anyString(), anyString());
    }

    @Test
    public void testSendNotificationToAllChannels() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel2);

        when(channel1.canHandle(any(), any(), anyString())).thenReturn(true);
        when(channel2.canHandle(any(), any(), anyString())).thenReturn(true);
        when(oAuthAppDO.isCibaSendNotificationToAllChannels()).thenReturn(true);

        cibaUserNotificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, "message", oAuthAppDO);

        verify(channel1).sendNotification(any(), any(), anyString(), anyString(), anyString());
        verify(channel2).sendNotification(any(), any(), anyString(), anyString(), anyString());
    }

    @Test
    public void testSendNotificationFallbackOnError() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel2);

        when(channel1.canHandle(any(), any(), anyString())).thenReturn(true);
        when(channel1.getName()).thenReturn("Channel1");

        // Channel 1 throws exception
        org.mockito.Mockito.doThrow(new CibaCoreException("Error")).when(channel1)
                .sendNotification(any(), any(), anyString(), anyString(), anyString());

        when(channel2.canHandle(any(), any(), anyString())).thenReturn(true);
        when(oAuthAppDO.isCibaSendNotificationToAllChannels()).thenReturn(false);

        cibaUserNotificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, "message", oAuthAppDO);

        verify(channel1).sendNotification(any(), any(), anyString(), anyString(), anyString());
        verify(channel2).sendNotification(any(), any(), anyString(), anyString(), anyString());
    }

    @Test(expectedExceptions = CibaCoreException.class)
    public void testBuildAuthenticationUrlError() throws Exception {
        when(mockServiceURLBuilder.build()).thenThrow(new URLBuilderException("Error"));
        cibaUserNotificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, "message", oAuthAppDO);
    }
}
