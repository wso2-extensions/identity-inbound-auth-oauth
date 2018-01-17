/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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
package org.wso2.carbon.identity.oidc.session.backChannelLogout;

import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.lang.reflect.Field;
import java.util.HashMap;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;


/**
 * Unit Tests for OIDCLogoutListener.
 */
@PrepareForTest({HttpServletRequest.class, IdentityUtil.class})
public class OIDCLogoutListenerTest extends PowerMockIdentityBaseTest {

    @Mock
    OIDCSessionState oidcSessionState;

    private OIDCSessionManager oidcSessionManager;
    private static final String SESSION_ID = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty("carbon.home", System.getProperty("user.dir"));
        PowerMockito.mockStatic(IdentityUtil.class);
        PowerMockito.when(IdentityUtil.getIdentityConfigDirPath())
                .thenReturn(System.getProperty("user.dir")
                        + File.separator + "src"
                        + File.separator + "test"
                        + File.separator + "resources"
                        + File.separator + "conf");
        Field oAuthServerConfigInstance =
                OAuthServerConfiguration.class.getDeclaredField("instance");
        oAuthServerConfigInstance.setAccessible(true);
        oAuthServerConfigInstance.set(null, null);
        Field instance = IdentityConfigParser.class.getDeclaredField("parser");
        instance.setAccessible(true);
        instance.set(null, null);

        when(IdentityUtil.getCleanUpPeriod("carbon.super")).thenReturn(1140L);
        oidcSessionManager = new OIDCSessionManager();
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        oidcSessionManager.storeOIDCSessionState(SESSION_ID, oidcSessionState);
    }

    @Test
    public void testHandleEvent() throws Exception {
        Event event = setupEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name());
        OIDCLogoutListener oidcLogoutListener = new OIDCLogoutListener();
        oidcLogoutListener.handleEvent(event);
        Assert.assertNotNull(LogoutRequestSender.getInstance());
    }

    @Test
    public void testGetName() {
        Assert.assertNotNull(OAuthServerConfiguration.getInstance(), "Instance is not created");
        OIDCLogoutListener oidcLogoutListener = new OIDCLogoutListener();
        Assert.assertEquals(oidcLogoutListener.getName(), "OIDC_LOGOUT_LISTENER");
    }

    private Event setupEvent(String eventName) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HashMap eventProperties = new HashMap();
        AuthenticationContext context = new AuthenticationContext();
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, request);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, context);
        Cookie[] cookies = new Cookie[1];
        Cookie cookie = new Cookie("opbs", SESSION_ID);
        cookies[0] = cookie;
        when(request.getCookies()).thenReturn(cookies);
        Event event = new Event(eventName, eventProperties);
        return event;
    }
}
