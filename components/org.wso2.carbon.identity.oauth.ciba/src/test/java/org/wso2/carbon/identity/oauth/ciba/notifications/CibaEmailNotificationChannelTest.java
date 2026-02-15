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

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver.ResolvedUser;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

public class CibaEmailNotificationChannelTest {

    private CibaEmailNotificationChannel emailChannel;

    @Mock
    private IdentityEventService identityEventService;

    private CibaAuthCodeDO cibaAuthCodeDO;
    private ResolvedUser resolvedUser;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        emailChannel = new CibaEmailNotificationChannel();
        CibaServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);

        cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setExpiresIn(3600);

        resolvedUser = new ResolvedUser();
        resolvedUser.setUsername("testUser");
        resolvedUser.setTenantDomain("carbon.super");
    }

    @AfterMethod
    public void tearDown() {
        CibaServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(emailChannel.getName(), "email");
    }

    @Test
    public void testGetPriority() {
        Assert.assertEquals(emailChannel.getPriority(), 10);
    }

    @Test
    public void testCanHandle() throws Exception {
        // User with email
        resolvedUser.setEmail("test@example.com");
        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L) // Simplified for test
                .setTenantDomain("carbon.super")
                .build();
        Assert.assertTrue(emailChannel.canHandle(context));

        // User without email
        resolvedUser.setEmail(null);
        context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .build();
        Assert.assertFalse(emailChannel.canHandle(context));

        // Null user
        context = new CibaNotificationContext.Builder()
                .setResolvedUser(null)
                .setExpiryTime(3600L)
                .setTenantDomain("carbon.super")
                .build();
        Assert.assertFalse(emailChannel.canHandle(context));
    }

    @Test
    public void testSendNotificationSuccess() throws Exception {
        ResolvedUser resolvedUser = new ResolvedUser();
        resolvedUser.setUsername("testUser");
        resolvedUser.setTenantDomain("carbon.super");
        resolvedUser.setEmail("test@example.com");

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setAuthUrl("http://auth.url")
                .setBindingMessage("message")
                .setTenantDomain("carbon.super")
                .build();
        
        emailChannel.sendNotification(context);

        verify(identityEventService).handleEvent(any(Event.class));
    }

    @Test(expectedExceptions = CibaCoreException.class)
    public void testSendNotificationNoEmail() throws Exception {
        ResolvedUser resolvedUser = new ResolvedUser();
        resolvedUser.setUsername("testUser");
        resolvedUser.setTenantDomain("carbon.super");
        resolvedUser.setEmail(null);

        CibaNotificationContext context = new CibaNotificationContext.Builder()
                .setResolvedUser(resolvedUser)
                .setExpiryTime(3600L)
                .setAuthUrl("http://auth.url")
                .setBindingMessage("message")
                .setTenantDomain("carbon.super")
                .build();
        
        emailChannel.sendNotification(context);
    }
}
