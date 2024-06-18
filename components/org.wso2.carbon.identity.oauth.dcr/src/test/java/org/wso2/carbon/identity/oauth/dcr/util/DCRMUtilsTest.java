/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.dcr.util;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;

import static org.wso2.carbon.identity.oauth.dcr.util.DCRConstants.APP_NAME_VALIDATING_REGEX;

public class DCRMUtilsTest {

    @DataProvider(name = "BuildRedirectUrl")
    public Object[][] buildRedirectUrl() {

        return new Object[][]{
                {"http://example.com/", true},
                {"http:\\example.com/", false},
                {null, false},
                {"", false},
        };
    }

    @Test(dataProvider = "BuildRedirectUrl")
    public void testIsRedirectionUriValid(String url, boolean response) throws Exception {

        Assert.assertEquals(DCRMUtils.isRedirectionUriValid(url), response);
    }

    @DataProvider(name = "BuildServerException")
    public Object[][] buildServerException() {

        return new Object[][]{
                {DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_INPUT, ""},
                {DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_INPUT, "error from bad request"}
        };
    }

    @Test(dataProvider = "BuildServerException", expectedExceptions = DCRMServerException.class)
    public void testThrowableServerException(DCRMConstants.ErrorMessages error, String data) throws Exception {

        Throwable e = new Throwable();
        throw DCRMUtils.generateServerException(error, data, e);
    }

    @Test(dataProvider = "BuildServerException", expectedExceptions = DCRMServerException.class)
    public void testGenerateServerException(DCRMConstants.ErrorMessages error, String data) throws Exception {

        throw DCRMUtils.generateServerException(error, data);
    }

    @Test(dataProvider = "BuildServerException", expectedExceptions = DCRMClientException.class)
    public void testThrowableClientException(DCRMConstants.ErrorMessages error, String data) throws Exception {

        Throwable e = new Throwable();
        throw DCRMUtils.generateClientException(error, data, e);
    }

    @Test(dataProvider = "BuildServerException", expectedExceptions = DCRMClientException.class)
    public void testGenerateClientException(DCRMConstants.ErrorMessages error, String data) throws Exception {

        throw DCRMUtils.generateClientException(error, data);
    }

    @DataProvider(name = "BuildBackchannelLogoutUri")
    public Object[][] buildBackchannelLogoutUri() {

        return new Object[][]{
                {"http://example.com/", true},
                {"", true},
                {"http://examp#le.com/", false},
                {"http:\\example.com", false},
                {"example", false},
        };
    }

    @Test(dataProvider = "BuildBackchannelLogoutUri")
    public void backChannelURIValidTest(String url, boolean response) {

        Assert.assertEquals(DCRMUtils.isBackchannelLogoutUriValid(url), response);
    }

    @DataProvider(name = "applicationName")
    public Object[][] buildApplicationName() {

        return new Object[][]{
                {"dummyApplicationName", true},
                {"", true},
                {"dummy@ApllicationName", false}
        };
    }

    @Test(dataProvider = "applicationName")
    public void regrexTest(String input, boolean expected) {

        Assert.assertEquals(DCRMUtils.isRegexValidated(input, APP_NAME_VALIDATING_REGEX), expected);
    }
}
