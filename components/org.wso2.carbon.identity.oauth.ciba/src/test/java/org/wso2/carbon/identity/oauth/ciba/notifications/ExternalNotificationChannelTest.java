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

package org.wso2.carbon.identity.oauth.ciba.notifications;

import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver.ResolvedUser;

import java.util.Arrays;
import java.util.Collections;

public class ExternalNotificationChannelTest {

    private ExternalNotificationChannel externalChannel;
    private ResolvedUser resolvedUser;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        externalChannel = new ExternalNotificationChannel();

        resolvedUser = new ResolvedUser();
        resolvedUser.setUsername("testUser");
        resolvedUser.setTenantDomain("carbon.super");
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(externalChannel.getName(), "external");
    }

    @Test
    public void testGetPriority() {

        Assert.assertEquals(externalChannel.getPriority(), 5);
    }

    @Test
    public void testCanHandleWithRequestedChannelExternal() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setRequestedChannel("external")
                .build();
        Assert.assertTrue(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithAppDefaultChannelExternal() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setAppAllowedChannels(Collections.singletonList("external"))
                .build();
        Assert.assertTrue(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithRequestedChannelEmail() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setRequestedChannel("email")
                .build();
        Assert.assertFalse(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithNoRequestedChannelAndMultipleAllowedChannels() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setAppAllowedChannels(Arrays.asList("email", "external"))
                .build();
        Assert.assertFalse(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithNoRequestedChannelAndEmptyAllowedChannels() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setAppAllowedChannels(Collections.emptyList())
                .build();
        Assert.assertFalse(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithNullRequestedChannel() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setRequestedChannel(null)
                .build();
        Assert.assertFalse(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithRequestedExternalAndMultipleAllowedChannels() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setRequestedChannel("external")
                .setAppAllowedChannels(Arrays.asList("email", "sms", "external"))
                .build();
        Assert.assertTrue(externalChannel.canHandle(context));
    }

    @Test
    public void testCanHandleWithSingleNonExternalAllowedChannel() {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .setAppAllowedChannels(Collections.singletonList("email"))
                .build();
        Assert.assertFalse(externalChannel.canHandle(context));
    }

    @Test
    public void testSendNotification() throws Exception {

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setAuthUrl("http://auth.url")
                .setTenantDomain("carbon.super")
                .build();

        // Should not throw - external channel is a no-op.
        externalChannel.sendNotification(context);
    }
}
