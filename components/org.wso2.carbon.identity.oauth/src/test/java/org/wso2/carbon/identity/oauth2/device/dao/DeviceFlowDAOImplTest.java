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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.device.dao;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.errorcodes.DeviceErrorCodes;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.Calendar;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests error responses for pending and expired device codes without waiting for expiry or polling intervals.
 */
public class DeviceFlowDAOImplTest {

    @DataProvider(name = "deviceCodeStates")
    public Object[][] deviceCodeStates() {

        return new Object[][] {
                {Constants.PENDING, -600000L, -1200000L, DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN},
                {Constants.PENDING, -600000L, 0L, DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN},
                {Constants.PENDING, 600000L, -1200000L, DeviceErrorCodes.SubDeviceErrorCodes.AUTHORIZATION_PENDING},
                {Constants.PENDING, 600000L, 0L, DeviceErrorCodes.SubDeviceErrorCodes.SLOW_DOWN},
                {Constants.EXPIRED, 600000L, -1200000L, DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN},
                {Constants.EXPIRED, 600000L, 0L, DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN}
        };
    }

    @Test(dataProvider = "deviceCodeStates")
    public void testGetAuthenticationDetailsForInactiveDevice(String status, long expiryOffset, long lastPollOffset,
                                                            String expectedError) throws Exception {

        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        long now = System.currentTimeMillis();
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(1)).thenReturn(status);
        when(resultSet.getTimestamp(eq(2), any(Calendar.class))).thenReturn(new Timestamp(now + lastPollOffset));
        when(resultSet.getLong(3)).thenReturn(600000L);
        when(resultSet.getTimestamp(eq(4), any(Calendar.class))).thenReturn(new Timestamp(now + expiryOffset));

        try (MockedStatic<IdentityDatabaseUtil> databaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            databaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);

            IdentityOAuth2Exception error = Assert.expectThrows(IdentityOAuth2Exception.class,
                    () -> new DeviceFlowDAOImpl().getAuthenticationDetails("device-code", "client-id"));

            Assert.assertEquals(error.getErrorCode(), expectedError);
            verify(resultSet).close();
            verify(statement).close();
            verify(connection).close();
        }
    }
}
