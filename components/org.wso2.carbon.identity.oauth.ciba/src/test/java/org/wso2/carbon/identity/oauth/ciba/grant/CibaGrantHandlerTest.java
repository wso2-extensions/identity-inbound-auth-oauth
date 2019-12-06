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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaMgtDAO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, CibaDAOFactory.class})
public class CibaGrantHandlerTest extends PowerMockTestCase {

    private static final String NONCE = "2201e5aa-1c5f-4a17-90c9-1956a3540b19";
    private static final String CONSUMER_KEY = "ZzxmDqqK8YYfjtlOh9vw85qnNVoa";
    private static final String AUTH_CODE_KEY = "039e8fff-1b24-420a-9dae-0ad745c96e97";
    private static final String TEST_CALLBACK_URL = "https://localhost:8000/callback";

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    CibaMgtDAO cibaMgtDAO;

    @Mock
    CibaDAOFactory cibaDAOFactory;

    @Mock
    CibaGrantHandler cibaGrantHandler;

    @Mock
    OAuthTokenReqMessageContext oAuthTokenReqMessageContext;

    @Mock
    OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;

    @BeforeMethod
    public void setUp() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

        mockStatic(CibaDAOFactory.class);
        when(CibaDAOFactory.getInstance()).thenReturn(cibaDAOFactory);
    }

    @Test
    public void testIsConsentGiven() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoDenied = new CibaAuthCodeDO();
        cibaAuthCodeDoDenied.setAuthReqStatus(AuthReqStatus.CONSENT_DENIED);

        Assert.assertFalse(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isConsentGiven",
                cibaAuthCodeDoDenied));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthReqStatus(AuthReqStatus.AUTHENTICATED);

        Assert.assertTrue(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isConsentGiven",
                cibaAuthCodeDoAuth));
    }

    @Test
    public void testIsAuthorizationPending() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoDenied = new CibaAuthCodeDO();
        cibaAuthCodeDoDenied.setAuthReqStatus(AuthReqStatus.AUTHENTICATED);

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        Assert.assertFalse(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isAuthorizationPending",
                cibaAuthCodeDoDenied));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthReqStatus(AuthReqStatus.REQUESTED);

        Assert.assertTrue(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isAuthorizationPending",
                cibaAuthCodeDoAuth));
    }

    @Test
    public void testUpdateLastPolledTime() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoDenied = new CibaAuthCodeDO();

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        Assert.assertNull(WhiteboxImpl.invokeMethod(cibaGrantHandler, "updateLastPolledTime",
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

        WhiteboxImpl.invokeMethod(cibaGrantHandler, "validateAuthReqId", cibaAuthCodeDO);
        Assert.fail();

        cibaAuthCodeDO.setExpiresIn(120L);
        Assert.assertNull(WhiteboxImpl.invokeMethod(cibaGrantHandler, "validateAuthReqId", cibaAuthCodeDO));
    }

    @Test
    public void testIsTokenAlreadyIssued() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDoIssued = new CibaAuthCodeDO();
        cibaAuthCodeDoIssued.setAuthReqStatus(AuthReqStatus.TOKEN_ISSUED);

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        Assert.assertTrue(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isTokenAlreadyIssued",
                cibaAuthCodeDoIssued));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthReqStatus(AuthReqStatus.REQUESTED);

        Assert.assertFalse(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isTokenAlreadyIssued",
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

        WhiteboxImpl.invokeMethod(cibaGrantHandler, "validatePollingFrequency", cibaAuthCodeDO);
        Assert.fail();
    }

    @Test
    public void testValidateCorrectPollingFrequency() throws Exception {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();

        long lastPolledTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis();
        cibaAuthCodeDO.setInterval(2);
        Timestamp polledTimeforSucess = new Timestamp(lastPolledTimeInMillis - 10000);
        cibaAuthCodeDO.setLastPolledTime(polledTimeforSucess);

        when(CibaDAOFactory.getInstance().getCibaAuthMgtDAO()).thenReturn(cibaMgtDAO);

        Assert.assertNull(WhiteboxImpl.invokeMethod(cibaGrantHandler, "validatePollingFrequency",
                cibaAuthCodeDO));
    }
}
