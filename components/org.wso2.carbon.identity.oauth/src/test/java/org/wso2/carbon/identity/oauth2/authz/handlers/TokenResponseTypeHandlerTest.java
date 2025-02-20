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

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.test.common.testng.utils.MockAuthenticatedUser;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.DEFAULT_BACKCHANNEL_LOGOUT_URL;

/**
 * Unit test covering TokenResponseTypeHandler class
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = OAuthComponentServiceHolder.class)
@WithH2Database(files = { "dbScripts/identity.sql", "dbScripts/insert_local_idp.sql" })
public class TokenResponseTypeHandlerTest {

    private static final String TEST_CLIENT_ID_1 = "SDSDSDS23131231";
    private static final String TEST_CLIENT_ID_2 = "SDSDSDS23131232";
    private static final String TEST_USER_ID = "testUser";
    private AuthenticatedUser authenticatedUser = new MockAuthenticatedUser(TEST_USER_ID);

    @BeforeTest
    public void setUp() throws Exception {
        OAuthEventInterceptor interceptor = Mockito.mock(OAuthEventInterceptor.class);
        OAuthComponentServiceHolder.getInstance().addOauthEventInterceptorProxy(interceptor);
        Mockito.clearAllCaches();
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "CommonDataProvider")
    public Object[][] commonDataProvider() {
        return new Object[][]{
                {true, TEST_CLIENT_ID_1},
                {false, TEST_CLIENT_ID_2}
        };
    }

    @Test(dataProvider = "CommonDataProvider")
    public void testIssue(boolean isIDPIdColumnEnabled, String clientId) throws Exception {

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
        AccessTokenResponseTypeHandler tokenResponseTypeHandler = new AccessTokenResponseTypeHandler();
        tokenResponseTypeHandler.init();

        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();

        authorizationReqDTO.setCallbackUrl("https://localhost:8000/callback");
        authorizationReqDTO.setConsumerKey(clientId);

        authenticatedUser.setUserName(TEST_USER_ID);
        authenticatedUser.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PTEST");
        authenticatedUser.setFederatedIdPName(TestConstants.LOCAL_IDP);
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        OAuthAuthzReqMessageContext authAuthzReqMessageContext = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext.setApprovedScope(new String[] { "scope1", "scope2", OAuthConstants.Scope.OPENID });

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(clientId);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
        oAuthAppDO.setBackChannelLogoutUrl(DEFAULT_BACKCHANNEL_LOGOUT_URL);

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken("abcdefghijklmn");
        accessTokenDO.setAuthzUser(authenticatedUser);

        new OAuthAppDAO().addOAuthApplication(oAuthAppDO);

        try (MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class);
            MockedStatic<AuthzUtil> mockedAuthzUtil = mockStatic(AuthzUtil.class)) {

            mockedAuthzUtil.when(AuthzUtil::isLegacyAuthzRuntime).thenReturn(false);
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            doNothing().when(mockAppInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

            OAuth2AuthorizeRespDTO auth2AuthorizeReqDTO = tokenResponseTypeHandler.
                    issue(authAuthzReqMessageContext);
            Assert.assertNotNull(auth2AuthorizeReqDTO.getAccessToken());
            Assert.assertTrue(auth2AuthorizeReqDTO.getValidityPeriod() > 1,
                    "Access Token should be valid, i.e. not expired.");
        }
    }
}
