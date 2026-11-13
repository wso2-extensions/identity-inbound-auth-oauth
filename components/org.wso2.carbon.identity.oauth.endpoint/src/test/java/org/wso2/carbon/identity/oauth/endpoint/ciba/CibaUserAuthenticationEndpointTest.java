/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CibaUserAuthenticationEndpoint}.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class CibaUserAuthenticationEndpointTest {

    private static final String AUTH_CODE_KEY = "auth-code-key-1234";
    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";

    @Test
    public void testCibaAuthorizeLoadsScopesFromDatabase() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(CibaConstants.CIBA_AUTH_CODE_KEY)).thenReturn(AUTH_CODE_KEY);

        CibaMgtDAO cibaMgtDAO = mock(CibaMgtDAO.class);
        CibaDAOFactory cibaDAOFactoryInstance = mock(CibaDAOFactory.class);
        when(cibaDAOFactoryInstance.getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        cibaAuthCodeDO.setCibaAuthCodeKey(AUTH_CODE_KEY);
        cibaAuthCodeDO.setConsumerKey(CONSUMER_KEY);
        cibaAuthCodeDO.setAuthReqId("auth-req-id-1");
        cibaAuthCodeDO.setAuthReqStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        cibaAuthCodeDO.setExpiresIn(3600L);

        when(cibaMgtDAO.getCibaAuthCode(AUTH_CODE_KEY)).thenReturn(cibaAuthCodeDO);
        when(cibaMgtDAO.getScopes(AUTH_CODE_KEY)).thenReturn(Arrays.asList("openid", "profile"));

        Response delegatedResponse = Response.ok().build();

        try (MockedStatic<CibaDAOFactory> cibaDAOFactory = mockStatic(CibaDAOFactory.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedConstruction<OAuth2AuthzEndpoint> authzEndpoint = mockConstruction(OAuth2AuthzEndpoint.class,
                     (authzMock, context) -> when(authzMock.authorize(any(), any())).thenReturn(delegatedResponse))) {

            cibaDAOFactory.when(CibaDAOFactory::getInstance).thenReturn(cibaDAOFactoryInstance);
            oAuth2Util.when(() -> OAuth2Util.buildScopeString(any())).thenReturn("openid profile");
            identityUtil.when(IdentityUtil::isAgentIdentityEnabled).thenReturn(false);

            // Construct the endpoint inside the mocked construction so its OAuth2AuthzEndpoint field is a mock.
            CibaUserAuthenticationEndpoint endpoint = new CibaUserAuthenticationEndpoint();
            Response result = endpoint.cibaAuthorize(request, response);

            // Scopes must be loaded from the DB and set on the auth code DO so the consent screen can be shown.
            verify(cibaMgtDAO).getScopes(AUTH_CODE_KEY);
            Assert.assertNotNull(cibaAuthCodeDO.getScopes());
            Assert.assertEquals(cibaAuthCodeDO.getScopes(), new String[]{"openid", "profile"});
            Assert.assertEquals(result, delegatedResponse);
        }
    }
}
