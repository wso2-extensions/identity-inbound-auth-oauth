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

import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

import java.io.File;
import java.lang.reflect.Field;

/**
 * Unit test cases covering AbstractResponseTypeHandler
 */
@PrepareForTest({IdentityUtil.class})
@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.crypto.*"})
public class AbstractResponseTypeHandlerTest extends PowerMockTestCase {
    AbstractResponseTypeHandler abstractResponseTypeHandler;

    @BeforeClass
    public void setUp() throws Exception {
        abstractResponseTypeHandler = new AbstractResponseTypeHandler() {
            @Override
            public OAuth2AuthorizeRespDTO
            issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
                    throws IdentityOAuth2Exception {
                return null;
            }
        };
        System.setProperty("carbon.home", System.getProperty("user.dir")
                + File.separator + "target");
        PowerMockito.mockStatic(IdentityUtil.class);
        PowerMockito.when(IdentityUtil.getIdentityConfigDirPath())
                .thenReturn(System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources" + File.separator + "conf");

        Field oAuthCallbackHandlerRegistry =
                OAuthServerConfiguration.class.getDeclaredField("instance");
        oAuthCallbackHandlerRegistry.setAccessible(true);
        oAuthCallbackHandlerRegistry.set(null, null);

        Field oAuthServerConfigInstance =
                OAuthServerConfiguration.class.getDeclaredField("instance");
        oAuthServerConfigInstance.setAccessible(true);
        oAuthServerConfigInstance.set(null, null);

        Field instance = IdentityConfigParser.class.getDeclaredField("parser");
        instance.setAccessible(true);
        instance.set(null, null);
        abstractResponseTypeHandler.init();
    }

    @Test
    public void testInit() throws Exception {
        Field field = abstractResponseTypeHandler
                .getClass().getSuperclass().getDeclaredField("cacheEnabled");
        abstractResponseTypeHandler.init();
        field.setAccessible(true);
        Assert.assertTrue(field.getBoolean(abstractResponseTypeHandler),
                "AbstractResponseTypeHandler not set");
    }

    @Test(dataProvider = "grantTypeProvider")
    public void testValidateAccessDelegation(String grantType, boolean result) throws Exception {
        Assert.assertEquals(abstractResponseTypeHandler.
                        validateAccessDelegation(this.setSampleOAuthReqMessageContext(grantType)),
                result, "Access Delegation not set");
    }

    @Test
    public void testValidateScope() throws Exception {
        Assert.assertTrue(abstractResponseTypeHandler
                        .validateScope(this.setSampleOAuthReqMessageContext(null)),
                "Validate scope returns wrong value");
    }

    @Test(dataProvider = "grantTypeProvider2")
    public void testIsAuthorizedClient(String grantType, boolean result) throws Exception {
        Assert.assertEquals(abstractResponseTypeHandler
                .isAuthorizedClient(this.setSampleOAuthReqMessageContext(grantType)), result);
    }

    @DataProvider(name = "grantTypeProvider")
    public static Object[][] grantTypes() {
        return new Object[][]{{null, true},
                {"authorization_code", true},
                {"dummy_code", false},
                {"implicit", true},
                {"dummy_code_2", false}};
    }

    @DataProvider(name = "grantTypeProvider2")
    public static Object[][] grantTypes2() {
        return new Object[][]{{null, false},
                {"authorization_code", true},
                {"dummy_code", false}};
    }

    private OAuthAuthzReqMessageContext setSampleOAuthReqMessageContext(String grantType) {
        String effectiveGrantType = null;
        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        if (grantType == null) {
            effectiveGrantType = "noValue";
        } else {
            effectiveGrantType = grantType;
        }
        if (!(effectiveGrantType.equals("implicit") || effectiveGrantType.equals("dummy_code_2"))) {
            authorizationReqDTO.setResponseType(ResponseType.CODE.toString());
        } else {
            authorizationReqDTO.setResponseType(ResponseType.TOKEN.toString());
        }
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes(grantType);
        authorizationReqDTO.addProperty("OAuthAppDO", "test");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        authorizationReqDTO.setUser(user);
        authorizationReqDTO.setConsumerKey("AK56897987ASDAAD");
        authorizationReqDTO.setScopes(new String[]{"scope1", "scope2"});

        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext =
                new OAuthAuthzReqMessageContext(authorizationReqDTO);
        oAuthAuthzReqMessageContext.addProperty("OAuthAppDO", oAuthAppDO);
        return oAuthAuthzReqMessageContext;
    }
}
