/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.response;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.SQLException;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/identity.sql", "dbScripts/insert_consumer_app.sql",
        "dbScripts/insert_local_idp.sql"})
public class DeviceFlowResponseTypeHandlerTest {

    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
    private OAuthAppDO oAuthAppDO = new OAuthAppDO();
    private static final String DB_NAME = "SCOPE_DB";
    private static final String TEST_URL = "testURL";

    @BeforeMethod
    public void setUp() throws Exception {

        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("identity.sql"));
        oAuth2AuthorizeReqDTO.setConsumerKey("testConsumerKey");
        oAuth2AuthorizeReqDTO.setNonce("testUserCode");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        oAuth2AuthorizeReqDTO.setUser(user);
        oAuth2AuthorizeReqDTO.setCallbackUrl(TEST_URL);
        oAuth2AuthorizeReqDTO.setTenantDomain(TestConstants.TENANT_DOMAIN);
    }

    @Test
    public void testSuccessIssue() throws IdentityOAuth2Exception, InvalidOAuthClientException, SQLException,
            URLBuilderException {

        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<ServiceURLBuilder> serviceURLBuilder = mockStatic(ServiceURLBuilder.class)) {

            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
            oAuth2Util.when(() -> OAuth2Util.getDeviceFlowCompletionPageURI(anyString(), anyString()))
                    .thenCallRealMethod();
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
            identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
            identityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                    .thenReturn(TEST_URL);
            ServiceURLBuilder mockServiceURLBuilder = Mockito.mock(ServiceURLBuilder.class);
            ServiceURL mockServiceURL = Mockito.mock(ServiceURL.class);
            serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
            when(mockServiceURLBuilder.addPath(anyString())).thenReturn(mockServiceURLBuilder);
            when(mockServiceURLBuilder.addParameter(anyString(), anyString())).thenReturn(mockServiceURLBuilder);
            when(mockServiceURLBuilder.build()).thenReturn(mockServiceURL);
            when(mockServiceURL.getAbsolutePublicURL())
                    .thenReturn(Constants.DEVICE_SUCCESS_ENDPOINT_PATH);

            oAuthAppDO.setApplicationName("testApplicationName");
            OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext =
                    new OAuthAuthzReqMessageContext(oAuth2AuthorizeReqDTO);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setApplicationName("testApp");
            oAuthAuthzReqMessageContext.addProperty("OAuthAppDO", oAuthAppDO);
            DeviceFlowResponseTypeHandler deviceFlowResponseTypeHandler = new DeviceFlowResponseTypeHandler();
            OAuth2AuthorizeRespDTO res = deviceFlowResponseTypeHandler.issue(oAuthAuthzReqMessageContext);
            assertEquals(res.getCallbackURI(), Constants.DEVICE_SUCCESS_ENDPOINT_PATH + "?app_name=testApp");
        }
    }
}
