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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
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
import org.wso2.carbon.identity.oauth2.model.SubjectTokenDO;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Test class covering SubjectTokenResponseTypeHandler.
 */

@WithCarbonHome
@WithRealmService(tenantId = TestConstants.TENANT_ID,
        tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true,
        injectToSingletons = {OAuthComponentServiceHolder.class})
@PrepareForTest(ResponseTypeHandlerUtil.class)
public class SubjectTokenResponseTypeHandlerTest extends PowerMockTestCase {

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
        oAuthAppDO.setGrantTypes("code");
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
                {"subject_token"},
                {"id_token subject_token"},
        };
    }

    @Test(dataProvider = "IssueSubjectTokenDataProvider")
    public void issueSubjectTokenTest(String responseType) throws Exception {

        OAuthComponentServiceHolder.getInstance().setOauth2Service(oAuth2Service);
        mockStatic(ResponseTypeHandlerUtil.class);
        OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
        authorizeRespDTO.setIdToken("dummy_id_token");

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                OAuth2AuthorizeRespDTO respDTO = (OAuth2AuthorizeRespDTO) invocation.getArguments()[0];
                respDTO.setIdToken("dummy_id_token");
                return respDTO;
            }
        }).when(ResponseTypeHandlerUtil.class, "buildIDTokenResponseDTO", any(OAuth2AuthorizeRespDTO.class),
                isNull(), any(OAuthAuthzReqMessageContext.class));

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
        authAuthzReqMessageContext.setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});

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
