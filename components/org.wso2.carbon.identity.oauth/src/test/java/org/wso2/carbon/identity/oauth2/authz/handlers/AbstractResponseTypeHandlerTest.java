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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

import java.io.File;
import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Unit test cases covering AbstractResponseTypeHandler
 */
/**
 * Unit test cases covering AbstractResponseTypeHandler
 */
@WithCarbonHome
@WithRealmService
@PrepareForTest({IdentityUtil.class, IdentityTenantUtil.class})
public class AbstractResponseTypeHandlerTest extends PowerMockTestCase {

    private AbstractResponseTypeHandler abstractResponseTypeHandler;
    private static final String oAuth2TokenEPUrl
            = "${carbon.protocol}://${carbon.host}:${carbon.management.port}" +
            "/oauth2/token";
    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityConfigDirPath())
                .thenReturn(System.getProperty("user.dir")
                        + File.separator + "src"
                        + File.separator + "test"
                        + File.separator + "resources"
                        + File.separator + "conf");
        when(IdentityUtil.fillURLPlaceholders(oAuth2TokenEPUrl)).thenReturn(oAuth2TokenEPUrl);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        abstractResponseTypeHandler = new AbstractResponseTypeHandler() {

            @Override
            public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
                    throws IdentityOAuth2Exception {
                return null;
            }
        };
        
        abstractResponseTypeHandler.init();
    }

    @Test
    public void testValidateAccessDelegation() throws Exception {
        Assert.assertEquals(abstractResponseTypeHandler.
                        validateAccessDelegation(this.setSampleOAuthReqMessageContext("authorization_code")),
                true, "Access Delegation not set");
    }

    @Test
    public void testValidateScope() throws Exception {
        Assert.assertTrue(abstractResponseTypeHandler
                        .validateScope(this.setSampleOAuthReqMessageContext(null)),
                "Validate scope returns wrong value");
    }

    @Test(dataProvider = "grantTypeProvider")
    public void testIsAuthorizedClient(String grantType, boolean result) throws Exception {
        Assert.assertEquals(abstractResponseTypeHandler
                .isAuthorizedClient(this.setSampleOAuthReqMessageContext(grantType)), result);
    }

    @DataProvider(name = "grantTypeProvider")
    public static Object[][] grantTypes2() {
        return new Object[][]{{null, false},
                {"authorization_code", true},
                {"implicit", true},
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
