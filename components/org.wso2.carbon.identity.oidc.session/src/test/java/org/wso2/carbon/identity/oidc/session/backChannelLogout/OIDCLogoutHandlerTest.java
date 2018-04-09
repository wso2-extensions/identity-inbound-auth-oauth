/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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


import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.servlet.TestUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;


/**
 * Unit Tests for OIDCLogoutHandler.
 */
@PrepareForTest({HttpServletRequest.class, IdentityUtil.class, IdentityTenantUtil.class, KeyStoreManager.class,
        IdentityProviderManager.class, IdentityApplicationManagementUtil.class, OAuth2Util.class})
public class OIDCLogoutHandlerTest extends PowerMockIdentityBaseTest {

    private static final String SESSION_ID_ONE = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String SESSION_ID_TWO = "090907ce-eab0-40d2-a46d-acd4bb33f0c0";
    private static final int TENANT_ID = -1234;

    private OIDCSessionManager oidcSessionManager;
    private FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = {new FederatedAuthenticatorConfig()};
    private Property[] properties = {new Property()};

    @InjectMocks
    private OIDCSessionState oidcSessionState;
    @Mock
    private AuthenticatedUser authenticatedUser;
    @Mock
    private KeyStoreManager keyStoreManager;
    @Mock
    private IdentityProvider identityProvider;
    @Mock
    private IdentityProviderManager identityProviderManager;
    @Mock
    private FederatedAuthenticatorConfig oidcAuthenticatorConfig;
    @Mock
    private Property property;


    @BeforeMethod
    public void setUp() throws Exception {

        authenticatedUser = new AuthenticatedUser() {
        };
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

        // create oidc sessions
        when(IdentityUtil.getCleanUpPeriod("carbon.super")).thenReturn(1140L);
        oidcSessionManager = new OIDCSessionManager();
        oidcSessionState = new OIDCSessionState();
        oidcSessionState.addSessionParticipant(OIDCLogoutConstants.clientIdOne);
        oidcSessionState.addSessionParticipant(OIDCLogoutConstants.clientIdTwo);
        TestUtil.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        oidcSessionManager.storeOIDCSessionState(SESSION_ID_ONE, oidcSessionState);
        oidcSessionManager.storeOIDCSessionState(SESSION_ID_TWO, oidcSessionState);

        // create application dtos
        authenticatedUser.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        OAuthAppDO oAuthAppDOOne = new OAuthAppDO();
        oAuthAppDOOne.setBackChannelLogoutUrl(OIDCLogoutConstants.backChannelUrlOne);
        oAuthAppDOOne.setUser(authenticatedUser);
        AppInfoCache.getInstance().addToCache(OIDCLogoutConstants.clientIdOne, oAuthAppDOOne);
        OAuthAppDO oAuthAppDOTwo = new OAuthAppDO();
        oAuthAppDOTwo.setBackChannelLogoutUrl(OIDCLogoutConstants.backChannelUrlTwo);
        oAuthAppDOTwo.setUser(authenticatedUser);
        AppInfoCache.getInstance().addToCache(OIDCLogoutConstants.clientIdTwo, oAuthAppDOTwo);


        // creating mocks
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(TENANT_ID);

        KeyStore keyStore = TestUtil.
                loadKeyStoreFromFileSystem(TestUtil.getFilePath("wso2carbon.jks"), "wso2carbon", "JKS");
        PrivateKey privateKey = TestUtil.getPrivateKey(keyStore, "wso2carbon", "wso2carbon");
        PublicKey publicKey = TestUtil.getPublicKey(keyStore, "wso2carbon");
        Certificate certificate = TestUtil.getCertificate(keyStore, "wso2carbon");

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(TENANT_ID)).thenReturn(keyStoreManager);
        when(keyStoreManager.getDefaultPublicKey())
                .thenReturn(publicKey);
        when(keyStoreManager.getDefaultPrivateKey())
                .thenReturn(privateKey);
        when(keyStoreManager.getDefaultPrimaryCertificate())
                .thenReturn((X509Certificate) certificate);

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance())
                .thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);

        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs,
                IdentityApplicationConstants.Authenticator.OIDC.NAME)).thenReturn(oidcAuthenticatorConfig);
        when(oidcAuthenticatorConfig.getProperties()).thenReturn(properties);

        when(IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                "IdPEntityId")).thenReturn(property);
        when(property.getValue()).thenReturn("IDP");

    }

    @Test
    public void testHandleEvent() throws Exception {

        Event eventOne = setupEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name(), OIDCLogoutConstants.idTokenOne);
        OIDCLogoutHandler oidcLogoutHandler = new OIDCLogoutHandler();
        oidcLogoutHandler.handleEvent(eventOne);
        Assert.assertNull(oidcSessionManager.getOIDCSessionState(SESSION_ID_ONE));
        Assert.assertNotNull(oidcSessionManager.getOIDCSessionState(SESSION_ID_TWO));
    }

    @Test
    public void testGetName() {

        Assert.assertNotNull(OAuthServerConfiguration.getInstance(), "Instance is not created");
        OIDCLogoutHandler oidcLogoutHandler = new OIDCLogoutHandler();
        Assert.assertEquals(oidcLogoutHandler.getName(), "OIDCLogoutHandler");
    }

    private Event setupEvent(String eventName, String idToken) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HashMap<String, Object> eventProperties = new HashMap<>();
        AuthenticationContext context = new AuthenticationContext();
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, request);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, context);
        Cookie[] cookies = new Cookie[1];
        Cookie cookie = new Cookie("opbs", SESSION_ID_ONE);
        cookies[0] = cookie;
        when(request.getCookies()).thenReturn(cookies);
        when(request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM))
                .thenReturn(idToken);
        return new Event(eventName, eventProperties);
    }
}
