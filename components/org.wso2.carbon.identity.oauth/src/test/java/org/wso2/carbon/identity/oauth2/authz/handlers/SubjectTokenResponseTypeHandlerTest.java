/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.util.ResponseTypeHandlerUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.SubjectTokenDO;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Test class covering SubjectTokenResponseTypeHandler.
 */

@WithCarbonHome
@WithRealmService(tenantId = TestConstants.TENANT_ID,
        tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true,
        injectToSingletons = {OAuthComponentServiceHolder.class})
@Listeners(MockitoTestNGListener.class)
public class SubjectTokenResponseTypeHandlerTest {

    private static final String TEST_CONSUMER_KEY =  "testconsumenrkey";
    private static final String TEST_CALLBACK_URL = "https://localhost:8000/callback";
    OAuthAuthzReqMessageContext authAuthzReqMessageContext;
    OAuth2AuthorizeReqDTO authorizationReqDTO;
    @Mock
    OAuth2Service oAuth2Service;

    @DataProvider(name = "IsAuthorizedDataProvider")
    public Object[][] isAuthorizedDataProvider() {
        return new Object[][]{
                {true, "subject_token", true},
                {false, "subject_token", false},
                {true, "id_token subject_token", true},
                {true, "code id_token", false},
        };
    }

    @Test(dataProvider = "IsAuthorizedDataProvider")
    public void isAuthorizedTest(boolean isSubjectTokenEnabled, String responseType, boolean isAuthorized)
            throws Exception {

        authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        authorizationReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
        authorizationReqDTO.setConsumerKey(TEST_CONSUMER_KEY);
        authorizationReqDTO.setResponseType(responseType);
        authAuthzReqMessageContext = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext.setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("code urn:ietf:params:oauth:grant-type:token-exchange");
        oAuthAppDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
        oAuthAppDO.setState("active");
        oAuthAppDO.setApplicationName("testApp");
        oAuthAppDO.setSubjectTokenEnabled(isSubjectTokenEnabled);
        authAuthzReqMessageContext.addProperty("OAuthAppDO", oAuthAppDO);

        SubjectTokenResponseTypeHandler subjectTokenResponseTypeHandler = new SubjectTokenResponseTypeHandler();
        subjectTokenResponseTypeHandler.init();
        boolean actualResult = subjectTokenResponseTypeHandler.isAuthorizedClient(authAuthzReqMessageContext);
        Assert.assertEquals(actualResult, isAuthorized, " mismatch client authorization " +
                "for impersonation flow");
    }

    @DataProvider(name = "IssueSubjectTokenDataProvider")
    public Object[][] issueSubjectTokenDataProvider() {
        return new Object[][]{
                {"subject_token" , "scope_1 openid"},
                {"subject_token" , "scope_1"},
                {"id_token subject_token", "scope_1 openid"},
                {"id_token subject_token", "scope_1"}
        };
    }

    @Test(dataProvider = "IssueSubjectTokenDataProvider")
    public void issueSubjectTokenTest(String responseType, String scope) throws Exception {

        OAuthComponentServiceHolder.getInstance().setOauth2Service(oAuth2Service);
        try (MockedStatic<ResponseTypeHandlerUtil> responseTypeHandlerUtil =
                mockStatic(ResponseTypeHandlerUtil.class)) {
            OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
            authorizeRespDTO.setIdToken("dummy_id_token");

            responseTypeHandlerUtil.when(
                            () -> ResponseTypeHandlerUtil.buildIDTokenResponseDTO(any(OAuth2AuthorizeRespDTO.class),
                                    nullable(AccessTokenDO.class), any(OAuthAuthzReqMessageContext.class)))
                    .thenAnswer(invocation -> {
                        OAuth2AuthorizeRespDTO respDTO = (OAuth2AuthorizeRespDTO) invocation.getArguments()[0];
                        respDTO.setIdToken("dummy_id_token");
                        return respDTO;
                    });

            AuthenticatedUser user = new AuthenticatedUser();
            user.setUserStoreDomain("PRIMARY");
            user.setUserName("testUser");
            user.setFederatedIdPName(TestConstants.LOCAL_IDP);

            authorizationReqDTO = new OAuth2AuthorizeReqDTO();
            authorizationReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
            authorizationReqDTO.setConsumerKey(TEST_CONSUMER_KEY);
            authorizationReqDTO.setResponseType(responseType);
            authorizationReqDTO.setUser(user);
            authAuthzReqMessageContext = new OAuthAuthzReqMessageContext(authorizationReqDTO);
            authAuthzReqMessageContext.setApprovedScope(scope.split(" "));

            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setGrantTypes("code");
            oAuthAppDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
            oAuthAppDO.setState("active");
            oAuthAppDO.setApplicationName("testApp");
            oAuthAppDO.setSubjectTokenEnabled(true);

            oAuthAppDO.setAppOwner(user);
            authAuthzReqMessageContext.addProperty("OAuthAppDO", oAuthAppDO);

            SubjectTokenDO subjectTokenDO = new SubjectTokenDO();
            subjectTokenDO.setSubjectToken("dummy_subject_token");
            when(oAuth2Service.issueSubjectToken(authAuthzReqMessageContext)).thenReturn(subjectTokenDO);

            SubjectTokenResponseTypeHandler subjectTokenResponseTypeHandler = new SubjectTokenResponseTypeHandler();
            subjectTokenResponseTypeHandler.init();
            OAuth2AuthorizeRespDTO respDTO = subjectTokenResponseTypeHandler.issue(authAuthzReqMessageContext);
            Assert.assertNotNull(respDTO.getSubjectToken(), "Subject token is null");
            if (StringUtils.contains(responseType, "id_token")) {
                Assert.assertNotNull(respDTO.getIdToken(), "Id token is null");
            }
        }
    }
}
