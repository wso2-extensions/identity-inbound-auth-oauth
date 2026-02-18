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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.grant;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@Listeners(MockitoTestNGListener.class)
public class CibaGrantHandlerTest {

    @Mock
    OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    CibaMgtDAO cibaMgtDAO;

    @Mock
    CibaDAOFactory mockCibaDAOFactory;

    @Mock
    CibaGrantHandler cibaGrantHandler;

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<CibaDAOFactory> cibaDAOFactory;

    @BeforeMethod
    public void setUp() throws Exception {

        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        cibaDAOFactory = mockStatic(CibaDAOFactory.class);
        when(CibaDAOFactory.getInstance()).thenReturn(mockCibaDAOFactory);
    }

    @AfterMethod
    public void tearDown() {
        oAuthServerConfiguration.close();
        cibaDAOFactory.close();
    }

    @Test
    public void testIsAuthorized() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoDenied = new CibaAuthCodeDO();
        cibaAuthCodeDoDenied.setAuthReqStatus(AuthReqStatus.CONSENT_DENIED);

        Assert.assertFalse((Boolean) invokePrivateMethod(cibaGrantHandler, "isAuthorized",
                cibaAuthCodeDoDenied));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthReqStatus(AuthReqStatus.AUTHENTICATED);

        Assert.assertTrue((Boolean) invokePrivateMethod(cibaGrantHandler, "isAuthorized",
                cibaAuthCodeDoAuth));
    }

    @Test
    public void testIsAuthorizationPending() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoDenied = new CibaAuthCodeDO();
        cibaAuthCodeDoDenied.setAuthReqStatus(AuthReqStatus.AUTHENTICATED);

        Assert.assertFalse((Boolean) invokePrivateMethod(cibaGrantHandler, "isAuthorizationPending",
                cibaAuthCodeDoDenied));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthReqStatus(AuthReqStatus.REQUESTED);

        Assert.assertTrue((Boolean) invokePrivateMethod(cibaGrantHandler, "isAuthorizationPending",
                cibaAuthCodeDoAuth));
    }

    @Test
    public void testUpdateLastPolledTime() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoDenied = new CibaAuthCodeDO();

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        Assert.assertNull(invokePrivateMethod(cibaGrantHandler, "updateLastPolledTime",
                cibaAuthCodeDoDenied));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testActiveAuthReqId() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis();
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        cibaAuthCodeDO.setExpiresIn(0);
        cibaAuthCodeDO.setIssuedTime(issuedTime);

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        invokePrivateMethod(cibaGrantHandler, "validateAuthReqId", cibaAuthCodeDO);
        Assert.fail();

        cibaAuthCodeDO.setExpiresIn(120L);
        Assert.assertNull(invokePrivateMethod(cibaGrantHandler, "validateAuthReqId", cibaAuthCodeDO));
    }

    @Test
    public void testIsTokenAlreadyIssued() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoIssued = new CibaAuthCodeDO();
        cibaAuthCodeDoIssued.setAuthReqStatus(AuthReqStatus.TOKEN_ISSUED);

        Assert.assertTrue((Boolean) invokePrivateMethod(cibaGrantHandler, "isTokenAlreadyIssued",
                cibaAuthCodeDoIssued));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthReqStatus(AuthReqStatus.REQUESTED);

        Assert.assertFalse((Boolean) invokePrivateMethod(cibaGrantHandler, "isTokenAlreadyIssued",
                cibaAuthCodeDoAuth));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidatePollingFrequency() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();

        long lastPolledTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis();
        Timestamp polledTime = new Timestamp(lastPolledTimeInMillis - 1000);
        cibaAuthCodeDO.setInterval(2);
        cibaAuthCodeDO.setLastPolledTime(polledTime);

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        invokePrivateMethod(cibaGrantHandler, "validatePollingFrequency", cibaAuthCodeDO);
        Assert.fail();
    }

    @Test
    public void testValidateCorrectPollingFrequency() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();

        long lastPolledTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis();
        cibaAuthCodeDO.setInterval(2);
        Timestamp polledTimeforSucess = new Timestamp(lastPolledTimeInMillis - 10000);
        cibaAuthCodeDO.setLastPolledTime(polledTimeforSucess);

        Assert.assertNull(invokePrivateMethod(cibaGrantHandler, "validatePollingFrequency",
                cibaAuthCodeDO));
    }

    @Test
    public void testValidateCorrectAuthReqIdOwner() throws Exception {

        String dummyString = "dummyString";
        Assert.assertNull(invokePrivateMethod(cibaGrantHandler, "validateAuthReqIdOwner",
                dummyString, dummyString));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateIncorrectAuthReqIdOwner() throws Exception {

        String firstDummyString = "firstDummyString";
        String secondDummyString = "secondDummyString";

        invokePrivateMethod(cibaGrantHandler, "validateAuthReqIdOwner",
                firstDummyString, secondDummyString);
    }

    private Object invokePrivateMethod(Object object, String methodName, Object... params) throws Exception {

        Class<?>[] paramTypes = new Class[params.length];
        for (int i = 0; i < params.length; i++) {
            paramTypes[i] = params[i].getClass();
        }
        Method method = object.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);

        try {
            return method.invoke(object, params);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getTargetException();
        }
    }
}
