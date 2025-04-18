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
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.DEFAULT_BACKCHANNEL_LOGOUT_URL;

/**
 * Test class covering CodeResponseTypeHandler
 */

@WithCarbonHome
@WithH2Database(files = {"dbScripts/identity.sql", "dbScripts/insert_consumer_app.sql",
        "dbScripts/insert_local_idp.sql"})
@WithRealmService(tenantId = TestConstants.TENANT_ID,
        tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true,
        injectToSingletons = {OAuthComponentServiceHolder.class})
public class CodeResponseTypeHandlerTest {

    private static final String TEST_CONSUMER_KEY =  "testconsumenrkey";
    private static final String TEST_CALLBACK_URL = "https://localhost:8000/callback";

    OAuthAuthzReqMessageContext authAuthzReqMessageContext;
    OAuth2AuthorizeReqDTO authorizationReqDTO;
    private MockedStatic<AuthzUtil> mockedAuthzUtil;

    @BeforeClass
    public void init() throws IdentityOAuthAdminException {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
        new OAuthAppDAO().addOAuthApplication(getDefaultOAuthAppDO());
        Mockito.clearAllCaches();
        mockedAuthzUtil = mockStatic(AuthzUtil.class);
        mockedAuthzUtil.when(AuthzUtil::isLegacyAuthzRuntime).thenReturn(false);
    }

    @AfterClass
    public void clear() throws IdentityOAuthAdminException {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
        new OAuthAppDAO().removeConsumerApplication(TEST_CONSUMER_KEY);
        mockedAuthzUtil.close();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        authorizationReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
        authorizationReqDTO.setConsumerKey(TEST_CONSUMER_KEY);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setUserId("1234");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        authAuthzReqMessageContext
                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext
                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "IdpIDColumnAvailabilityDataProvider")
    public Object[][] idpIDColumnAvailabilityDataProvider() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "IdpIDColumnAvailabilityDataProvider")
    public void testIssue(boolean isIDPIdColumnEnabled) throws Exception {

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
        oAuthAppDO.setState("active");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain("PRIMARY");
        user.setUserName("testUser");
        user.setFederatedIdPName(TestConstants.LOCAL_IDP);

        oAuthAppDO.setUser(user);
        oAuthAppDO.setApplicationName("testApp");

        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        appInfoCache.addToCache(TEST_CONSUMER_KEY, oAuthAppDO);

        CodeResponseTypeHandler codeResponseTypeHandler = new CodeResponseTypeHandler();
        codeResponseTypeHandler.init();
        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO =
                codeResponseTypeHandler.issue(authAuthzReqMessageContext);
        Assert.assertNotNull(oAuth2AuthorizeRespDTO.getAuthorizationCode(),
                "Access token not Authorization code");
        Assert.assertEquals(oAuth2AuthorizeRespDTO.getCallbackURI()
                , TEST_CALLBACK_URL, "Callback url not set");
    }

    private OAuthAppDO getDefaultOAuthAppDO() {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("user1");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("USER_STORE_DOMAIN_NAME");

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setApplicationName("CodeResponseTypeHandlerTestApp");
        appDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
        appDO.setOauthConsumerSecret("87n9a540f544777860e44e75f605d435");
        appDO.setUser(authenticatedUser);
        appDO.setCallbackUrl(TEST_CALLBACK_URL);
        appDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
        appDO.setApplicationAccessTokenExpiryTime(3600);
        appDO.setUserAccessTokenExpiryTime(3600);
        appDO.setRefreshTokenExpiryTime(84100);
        appDO.setIdTokenExpiryTime(3600);
        appDO.setBackChannelLogoutUrl(DEFAULT_BACKCHANNEL_LOGOUT_URL);
        return appDO;
    }
}
