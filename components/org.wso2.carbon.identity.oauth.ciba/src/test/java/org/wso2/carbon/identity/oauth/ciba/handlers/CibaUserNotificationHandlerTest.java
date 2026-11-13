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
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver.ResolvedUser;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(null)
                .build();
        cibaUserNotificationHandler.sendNotification(context);
    }

    @Test(expectedExceptions = CibaClientException.class, expectedExceptionsMessageRegExp =
            "No notification channels configured for the application.")
    public void testSendNotificationNoChannelsConfigured() throws Exception {
        // App has no notification channels configured.
        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Collections.emptyList())
                .build();
        cibaUserNotificationHandler.sendNotification(context);
    }

    @Test
    public void testSendNotificationSuccess() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        when(channel1.canHandle(any(CibaNotificationContext.class))).thenReturn(true);
        when(channel1.getName()).thenReturn("channel1");
        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Arrays.asList("channel1"))
                .build();
        String usedChannel = cibaUserNotificationHandler.sendNotification(context);

        verify(channel1).sendNotification(any(CibaNotificationContext.class));
        Assert.assertEquals(usedChannel, "channel1");
    }

    @Test
    public void testSendNotificationSingleSupportedChannel() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        when(channel1.canHandle(any(CibaNotificationContext.class))).thenReturn(true);
        when(channel1.getName()).thenReturn("external");

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Arrays.asList("external"))
                .build();
        String usedChannel = cibaUserNotificationHandler.sendNotification(context);

        verify(channel1).sendNotification(any(CibaNotificationContext.class));
        Assert.assertEquals(usedChannel, "external");
    }

    @Test
    public void testSendNotificationSendsToAllAllowedChannels() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel2);

        when(channel1.getName()).thenReturn("channel1");
        when(channel2.getName()).thenReturn("channel2");
        when(channel1.canHandle(any(CibaNotificationContext.class))).thenReturn(true);
        when(channel2.canHandle(any(CibaNotificationContext.class))).thenReturn(true);

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Arrays.asList("channel1", "channel2"))
                .build();
        cibaUserNotificationHandler.sendNotification(context);

        // Both channels should receive notifications in fallback mode.
        verify(channel1).sendNotification(any(CibaNotificationContext.class));
        verify(channel2).sendNotification(any(CibaNotificationContext.class));
    }



    @Test
    public void testSendNotificationFallbackContinuesOnError() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel2);

        when(channel1.canHandle(any(CibaNotificationContext.class))).thenReturn(true);
        when(channel1.getName()).thenReturn("channel1");
        when(channel2.canHandle(any(CibaNotificationContext.class))).thenReturn(true);
        when(channel2.getName()).thenReturn("channel2");

        // Channel 1 throws exception
        org.mockito.Mockito.doThrow(new CibaCoreException("Error")).when(channel1)
                .sendNotification(any(CibaNotificationContext.class));

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Arrays.asList("channel1", "channel2"))
                .build();
        String usedChannel = cibaUserNotificationHandler.sendNotification(context);

        // Both attempted, channel2 succeeds.
        verify(channel1).sendNotification(any(CibaNotificationContext.class));
        verify(channel2).sendNotification(any(CibaNotificationContext.class));
        Assert.assertEquals(usedChannel, "channel2");
    }

    @Test
    public void testSendNotificationWithRequestedChannel() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel2);

        when(channel1.getName()).thenReturn("channel1");
        when(channel2.getName()).thenReturn("channel2");
        when(channel2.canHandle(any(CibaNotificationContext.class))).thenReturn(true);

        // Request Channel2 specifically
        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Arrays.asList("channel1", "channel2"))
                .setRequestedChannel("channel2")
                .build();
        cibaUserNotificationHandler.sendNotification(context);

        verify(channel2).sendNotification(any(CibaNotificationContext.class));
        verify(channel1, never()).sendNotification(any(CibaNotificationContext.class));
    }

    @Test(expectedExceptions = CibaClientException.class, expectedExceptionsMessageRegExp =
            "Requested notification channel is not allowed for this application.")
    public void testSendNotificationDisallowedChannel() throws Exception {
        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel1);
        when(channel1.getName()).thenReturn("channel1");
        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setAppAllowedChannels(Arrays.asList("channel1"))
                .setRequestedChannel("channel2")
                .build();
        cibaUserNotificationHandler.sendNotification(context);
    }
}
