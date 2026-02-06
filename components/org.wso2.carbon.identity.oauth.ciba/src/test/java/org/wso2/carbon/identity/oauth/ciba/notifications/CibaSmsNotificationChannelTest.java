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

public class CibaSmsNotificationChannelTest {

    private CibaSmsNotificationChannel smsChannel;

    @Mock
    private IdentityEventService identityEventService;

    private CibaAuthCodeDO cibaAuthCodeDO;
    private ResolvedUser resolvedUser;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        smsChannel = new CibaSmsNotificationChannel();
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
        Assert.assertEquals(smsChannel.getName(), "sms");
    }

    @Test
    public void testGetPriority() {
        Assert.assertEquals(smsChannel.getPriority(), 20);
    }

    @Test
    public void testCanHandle() {
        // User with mobile
        resolvedUser.setMobile("1234567890");
        Assert.assertTrue(smsChannel.canHandle(resolvedUser, cibaAuthCodeDO, "carbon.super"));

        // User without mobile
        resolvedUser.setMobile(null);
        Assert.assertFalse(smsChannel.canHandle(resolvedUser, cibaAuthCodeDO, "carbon.super"));

        // Null user
        Assert.assertFalse(smsChannel.canHandle(null, cibaAuthCodeDO, "carbon.super"));
    }

    @Test
    public void testSendNotificationSuccess() throws Exception {
        resolvedUser.setMobile("1234567890");
        smsChannel.sendNotification(resolvedUser, cibaAuthCodeDO, "http://auth.url", "message", "carbon.super");

        verify(identityEventService).handleEvent(any(Event.class));
    }

    @Test(expectedExceptions = CibaCoreException.class)
    public void testSendNotificationNoMobile() throws Exception {
        resolvedUser.setMobile(null);
        smsChannel.sendNotification(resolvedUser, cibaAuthCodeDO, "http://auth.url", "message", "carbon.super");
    }
}
