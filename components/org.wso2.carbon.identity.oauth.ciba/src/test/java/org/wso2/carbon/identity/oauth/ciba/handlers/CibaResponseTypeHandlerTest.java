/* Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaMgtDAOImpl;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuth2Util.class, CibaDAOFactory.class, IdentityDatabaseUtil.class,
        OAuthServerConfiguration.class, CibaDAOFactory.class})
@PowerMockIgnore({"javax.crypto.*"})
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
public class CibaResponseTypeHandlerTest extends PowerMockTestCase {

    private static final String NONCE = "2201e5aa-1c5f-4a17-90c9-1956a3540b19";
    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    private static final String TEST_CALLBACK_URL = "https://localhost:8000/callback";

    OAuthAuthzReqMessageContext authAuthzReqMessageContext;
    OAuth2AuthorizeReqDTO authorizationReqDTO;
    AuthenticatedUser authenticatedUser;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    CibaMgtDAOImpl cibaAuthMgtDAO;

    @Mock
    CibaDAOFactory cibaDAOFactory;

    @Mock
    OAuthErrorDTO oAuthErrorDTO;

    @BeforeMethod
    public void setUp() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        mockStatic(CibaDAOFactory.class);
        when(CibaDAOFactory.getInstance()).thenReturn(cibaDAOFactory);

        authenticatedUser = new AuthenticatedUser();
        authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        authorizationReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
        authorizationReqDTO.setConsumerKey(CONSUMER_KEY);
        authorizationReqDTO.setNonce(NONCE);
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        authAuthzReqMessageContext
                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext
                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});
    }

    @Test
    public void testIssue() throws Exception {

        CibaResponseTypeHandler cibaResponseTypeHandler = new CibaResponseTypeHandler();

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaAuthMgtDAO);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getTenantId(anyString())).thenReturn(1234);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain("PRIMARY");
        user.setUserName("testUser");
        user.setFederatedIdPName("LOCAL");

        Assert.assertEquals(cibaResponseTypeHandler.issue(authAuthzReqMessageContext).getCallbackURI(),
                TEST_CALLBACK_URL + "?authenticationStatus=AUTHENTICATED");
    }

    @DataProvider(name = "provideFailedAuthenticationErrorInfo")
    public Object[][] provideFailedAuthenticationErrorInfo() {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setNonce(NONCE);

        return new Object[][]{
                {oAuth2Parameters, "Authentication failed."},
        };
    }

    @Test(dataProvider = "provideFailedAuthenticationErrorInfo")
    public void testHandleAuthenticationFailure(Object oAuth2ParameterObject, Object expected) throws Exception {

        OAuth2Parameters oAuth2Parameters = (OAuth2Parameters) oAuth2ParameterObject;

        CibaResponseTypeHandler cibaResponseTypeHandler = new CibaResponseTypeHandler();

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaAuthMgtDAO);
        Assert.assertEquals(expected,
                cibaResponseTypeHandler.handleAuthenticationFailure(oAuth2Parameters).getErrorDescription());
    }

    @DataProvider(name = "provideConsentDenialErrorInfo")
    public Object[][] provideConsentDenialErrorInfo() {

        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setNonce(NONCE);

        return new Object[][]{
                {oAuth2Parameters, "User denied the consent."},
        };
    }

    @Test(dataProvider = "provideConsentDenialErrorInfo")
    public void provideConsentDenialErrorInfo(Object oAuth2ParameterObject, Object expected) throws Exception {

        OAuth2Parameters oAuth2Parameters = (OAuth2Parameters) oAuth2ParameterObject;

        CibaResponseTypeHandler cibaResponseTypeHandler = new CibaResponseTypeHandler();

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaAuthMgtDAO);
        Assert.assertEquals(expected,
                cibaResponseTypeHandler.handleUserConsentDenial(oAuth2Parameters).getErrorDescription());
    }
}
