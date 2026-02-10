/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannelManager;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaUserNotificationContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@Listeners(MockitoTestNGListener.class)
public class CibaUserNotificationHandlerTest {

    @Mock
    private NotificationChannelManager notificationChannelManager;
    @Mock
    private IdentityEventService identityEventService;
    @Mock
    private RealmService mockRealmService;

    @Mock
    private AbstractUserStoreManager mockedUserStoreManager;

    private CibaUserNotificationContext cibaUserNotificationContext = new CibaUserNotificationContext();
    private CibaUserNotificationHandler handler = new CibaUserNotificationHandler();

    @BeforeMethod
    public void setUp() {
        // Static holder mocks
        CibaServiceComponentHolder.setNotificationChannelManager(notificationChannelManager);
        CibaServiceComponentHolder.setRealmService(mockRealmService);
        CibaServiceComponentHolder.setIdentityEventService(identityEventService);

        User user = new User();
        user.setUsername("testuser");
        user.setTenantDomain("carbon.super");
        user.setUserStoreDomain("PRIMARY");
        cibaUserNotificationContext.setUser(user);
        cibaUserNotificationContext.setAuthCodeKey("authCode");
        cibaUserNotificationContext.setBindingMessage("bindMsg");
        cibaUserNotificationContext.setApplicationName("appName");
    }

    @Test
    public void testSendNotificationEmailChannel() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
            MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            ServiceURLBuilder mockServiceURLBuilder = Mockito.mock(ServiceURLBuilder.class);
            serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
            ServiceURL mockServiceURL = Mockito.mock(ServiceURL.class);
            lenient().when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.addParameter(anyString(), anyString()))
                    .thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
            lenient().when(mockServiceURL.getAbsolutePublicURL())
                    .thenReturn("http://localhost:9443/ciba_auth/authCodeKey=authCode");

            when(notificationChannelManager.resolveCommunicationChannel(any(), any(), any()))
                    .thenReturn(NotificationChannels.EMAIL_CHANNEL.getChannelType());
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            UserRealm userRealm = mock(UserRealm.class);
            lenient().when(userRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            lenient().when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
            Map<String, String> claimValues = new HashMap<>();
            claimValues.put("http://wso2.org/claims/emailaddress", "test@mail.com");
            when(mockedUserStoreManager.getUserClaimValues(anyString(), any(), isNull()))
                    .thenReturn(claimValues);

            handler.sendNotification(cibaUserNotificationContext);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            Mockito.verify(identityEventService).handleEvent(eventCaptor.capture());
            Event event = eventCaptor.getValue();
            Assert.assertEquals(event.getEventName(), "TRIGGER_NOTIFICATION");
            Assert.assertEquals(event.getEventProperties().get("send-to"), "test@mail.com");
            Assert.assertEquals(event.getEventProperties().get("user-name"), "testuser");
        }
    }

    @Test
    public void testSendNotificationSMSChannel() throws Exception {

        try (MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            ServiceURLBuilder mockServiceURLBuilder = Mockito.mock(ServiceURLBuilder.class);
            serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
            ServiceURL mockServiceURL = Mockito.mock(ServiceURL.class);
            lenient().when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.addParameter(anyString(), anyString()))
                    .thenReturn(mockServiceURLBuilder);
            lenient().when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
            lenient().when(mockServiceURL.getAbsolutePublicURL())
                    .thenReturn("http://localhost:9443/ciba_auth/authCodeKey=authCode");

            when(notificationChannelManager.resolveCommunicationChannel(any(), any(), any()))
                    .thenReturn(NotificationChannels.SMS_CHANNEL.getChannelType());
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            UserRealm userRealm = mock(UserRealm.class);
            lenient().when(userRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            lenient().when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
            Map<String, String> claimValues = new HashMap<>();
            claimValues.put("http://wso2.org/claims/mobile", "test-mobile");
            when(mockedUserStoreManager.getUserClaimValues(anyString(), any(), isNull()))
                    .thenReturn(claimValues);

            handler.sendNotification(cibaUserNotificationContext);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            Mockito.verify(identityEventService).handleEvent(eventCaptor.capture());
            Event event = eventCaptor.getValue();
            Assert.assertEquals(event.getEventName(), "TRIGGER_SMS_NOTIFICATION_LOCAL");
            Assert.assertEquals(event.getEventProperties().get("send-to"), "test-mobile");
            Assert.assertEquals(event.getEventProperties().get("user-name"), "testuser");
        }
    }
}
