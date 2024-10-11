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

package org.wso2.carbon.identity.oauth2.device.grant;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowDAO;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/identity.sql", "dbScripts/insert_consumer_app.sql",
        "dbScripts/insert_local_idp.sql"})
public class DeviceFlowGrantTest {

    private Date date = new Date();
    private Timestamp newTime = new Timestamp(date.getTime());
    private DeviceFlowDO deviceFlowDO1 = new DeviceFlowDO();
    private DeviceFlowDO deviceFlowDO2 = new DeviceFlowDO();
    private DeviceFlowGrant deviceFlowGrant;
    private OAuthTokenReqMessageContext oAuthTokenReqMessageContext;
    private DeviceFlowDO deviceFlowDO3;

    MockedStatic<DeviceFlowPersistenceFactory> mockedStatic;

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT2_NAME = "identity.sql";
    MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;

    @BeforeClass
    public void setupBeforeClass() throws Exception {

        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath(H2_SCRIPT2_NAME));
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        System.setProperty(
                "java.naming.factory.initial",
                "org.wso2.carbon.identity.common.testng.MockInitialContextFactory"
        );

        deviceFlowDO3 = new DeviceFlowDO();
        deviceFlowDO3.setStatus(Constants.AUTHORIZED);
        long currentTimeMillis = System.currentTimeMillis();
        long twentyFourHoursInMillis = 24 * 60 * 60 * 1000;
        Timestamp expiryTime = new Timestamp(currentTimeMillis + twentyFourHoursInMillis);
        deviceFlowDO3.setExpiryTime(expiryTime);

        List<String> scopesList = new ArrayList<>();
        scopesList.add("internal");
        deviceFlowDO3.setScopes(scopesList);

        AuthenticatedUser authorizedUser = new AuthenticatedUser();
        authorizedUser.setUserName("test");
        deviceFlowDO3.setAuthorizedUser(authorizedUser);

        // Mocking DeviceFlowDAO and DeviceFlowPersistenceFactory
        DeviceFlowDAO deviceFlowDAO = mock(DeviceFlowDAO.class);
        mockedStatic = mockStatic(DeviceFlowPersistenceFactory.class);
        mockedStatic.when(DeviceFlowPersistenceFactory::getInstance).thenReturn
                (mock(DeviceFlowPersistenceFactory.class));
        when(DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()).thenReturn(deviceFlowDAO);
        when(deviceFlowDAO.getAuthenticationDetails(anyString(), anyString())).thenReturn(deviceFlowDO3);
    }

    @BeforeMethod
    public void setUp() throws Exception {

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(anyBoolean()))
                .thenReturn(DAOUtils.getConnection(DB_NAME));
        deviceFlowDO1.setExpiryTime(new Timestamp(date.getTime() - 1000));
        deviceFlowDO1.setLastPollTime(new Timestamp(date.getTime() - 1000));
        deviceFlowDO1.setPollTime(1500);
        deviceFlowDO2.setExpiryTime(new Timestamp(date.getTime() + 1000));
        deviceFlowDO2.setLastPollTime(new Timestamp(date.getTime() - 2000));
        deviceFlowDO2.setPollTime(1500);
        deviceFlowGrant = new DeviceFlowGrant();
        oAuthTokenReqMessageContext = mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn("clientId123");
        when(oAuth2AccessTokenReqDTO.getRequestParameters()).thenReturn(
                new RequestParameter[] {
                        new RequestParameter(Constants.DEVICE_CODE, new String[]{"validDeviceCode"})
                }
        );
        when(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
    }

    @AfterMethod
    public void tearDown() {
        identityDatabaseUtil.close();
    }

    @Test
    public void testIsExpiredDeviceCode() throws Exception {

        Assert.assertTrue(
                (Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class, "isExpiredDeviceCode", deviceFlowDO1, date));
        Assert.assertFalse((Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class,
                "isExpiredDeviceCode", deviceFlowDO2, date));
    }

    @Test
    public void testIsValidPollTime() throws Exception {
        Assert.assertFalse((Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class,
                "isWithinValidPollInterval", newTime, deviceFlowDO1));
        Assert.assertTrue((Boolean) invokePrivateStaticMethod(DeviceFlowGrant.class,
                "isWithinValidPollInterval", newTime, deviceFlowDO2));
    }

    @Test
    public void testValidateGrantAuthorizedDevice() throws Exception {

        deviceFlowDO3.setStatus(Constants.AUTHORIZED);
        boolean result = deviceFlowGrant.validateGrant(oAuthTokenReqMessageContext);

        Assert.assertTrue(result, "The grant validation should be successful.");

    }

    @Test
    public void testValidateGrantPendingDevice() throws Exception {

        deviceFlowDO3.setStatus(Constants.PENDING);
        boolean result = deviceFlowGrant.validateGrant(oAuthTokenReqMessageContext);

        assertFalse(result, "The grant validation should not be successful.");
    }

    private Object invokePrivateStaticMethod(Class<?> clazz, String methodName, Object... params) throws Exception {

        Class<?>[] paramTypes = new Class[params.length];
        for (int i = 0; i < params.length; i++) {
            paramTypes[i] = params[i].getClass();
        }
        Method method = clazz.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(null, params);
    }
}
