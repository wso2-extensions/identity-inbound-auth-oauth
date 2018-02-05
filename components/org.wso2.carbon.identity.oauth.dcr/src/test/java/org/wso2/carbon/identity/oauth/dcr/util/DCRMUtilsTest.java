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
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.testng.Assert.fail;

public class DCRMUtilsTest extends IdentityBaseTest{

    @DataProvider(name = "BuildRedirectUrl")
    public Object[][] buildRedirectUrl() {
        return new Object[][] {
                {"http://example.com/", true},
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
        return new Object[][] {
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
}
