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

import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.SQLException;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({OAuth2Util.class, DeviceFlowPersistenceFactory.class, IdentityDatabaseUtil.class, IdentityUtil.class})
@PowerMockIgnore({"javax.crypto.*"})
@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
public class DeviceFlowResponseTypeHandlerTest extends PowerMockTestCase {

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

    }

    @Test
    public void testIssue() throws IdentityOAuth2Exception, InvalidOAuthClientException, SQLException {

        try (Connection connection1 = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(OAuth2Util.class);
            when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection1);
            when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection1);
            mockStatic(IdentityUtil.class);
            when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(TEST_URL);
            oAuthAppDO.setApplicationName("testApplicationName");
            DeviceFlowDAO deviceFlowPersistenceFactory = PowerMockito.spy(DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO());
            doNothing().when(deviceFlowPersistenceFactory).setAuthzUser(anyString(), anyString());
            OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext =
                    new OAuthAuthzReqMessageContext(oAuth2AuthorizeReqDTO);
            DeviceFlowResponseTypeHandler deviceFlowResponseTypeHandler = new DeviceFlowResponseTypeHandler();
            assertEquals(TEST_URL, deviceFlowResponseTypeHandler.issue(oAuthAuthzReqMessageContext).getCallbackURI());
        } catch (SQLException e) {
            throw new SQLException("Error while database processes", e);
        }
    }
}