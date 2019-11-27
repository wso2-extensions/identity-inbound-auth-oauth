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
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class, CibaDAOFactory.class})
public class CibaGrantHandlerTest extends PowerMockTestCase {

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    CibaMgtDAO cibaMgtDAO;

    @Mock
    CibaDAOFactory cibaDAOFactory;

    @Mock
    CibaGrantHandler cibaGrantHandler;

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
        cibaAuthCodeDoDenied.setAuthenticationStatus(AuthReqStatus.DENIED);

        Assert.assertFalse(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isConsentGiven",
                cibaAuthCodeDoDenied));

        CibaAuthCodeDO cibaAuthCodeDoAuth = new CibaAuthCodeDO();
        cibaAuthCodeDoAuth.setAuthenticationStatus(AuthReqStatus.AUTHENTICATED);

        Assert.assertTrue(WhiteboxImpl.invokeMethod(cibaGrantHandler, "isConsentGiven",
                cibaAuthCodeDoAuth));
    }
}