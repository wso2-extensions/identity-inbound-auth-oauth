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

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.test.common.testng.utils.MockAuthenticatedUser;

/**
 * Unit test covering TokenResponseTypeHandler class
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = OAuthComponentServiceHolder.class)
@WithH2Database(files = { "dbScripts/token.sql" })
public class TokenResponseTypeHandlerTest {

    private static final String TEST_CLIENT_ID = "SDSDSDS23131231";
    private static final String TEST_USER_ID = "testUser";
    private AuthenticatedUser authenticatedUser = new MockAuthenticatedUser(TEST_USER_ID);

    @BeforeTest
    public void setUp() throws Exception {
        OAuthEventInterceptor interceptor = Mockito.mock(OAuthEventInterceptor.class);
        OAuthComponentServiceHolder.getInstance().addOauthEventInterceptorProxy(interceptor);
    }

    @Test
    public void testIssue() throws Exception {
        TokenResponseTypeHandler tokenResponseTypeHandler = new TokenResponseTypeHandler();
        tokenResponseTypeHandler.init();
        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();

        authorizationReqDTO.setCallbackUrl("https://localhost:8000/callback");
        authorizationReqDTO.setConsumerKey(TEST_CLIENT_ID);

        authenticatedUser.setUserName(TEST_USER_ID);
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PTEST");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        OAuthAuthzReqMessageContext authAuthzReqMessageContext = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext.setApprovedScope(new String[] { "scope1", "scope2", OAuthConstants.Scope.OPENID });

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(TEST_CLIENT_ID);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setAccessToken("abcdefghijklmn");
        accessTokenDO.setAuthzUser(authenticatedUser);

        new OAuthAppDAO().addOAuthApplication(oAuthAppDO);

        //        PowerMockito.when(OAuth2Util
        //                .isOIDCAuthzRequest(new String[]{"scope1", "scope2",
        //                        OAuthConstants.Scope.OPENID})).thenReturn(true);

        OAuth2AuthorizeRespDTO auth2AuthorizeReqDTO = tokenResponseTypeHandler.
                issue(authAuthzReqMessageContext);
        Assert.assertNotNull(auth2AuthorizeReqDTO.getAccessToken());
        Assert.assertTrue(auth2AuthorizeReqDTO.getValidityPeriod() > 1,
                "Access Token should be valid, i.e. not expired.");
    }
}
