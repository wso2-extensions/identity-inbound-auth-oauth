/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.oauth.common.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class OAuthClientExceptionTest {

    private static final String MESSAGE = "Message for InvalidOAuthClientExceptionTest";
    private static final String MESSAGE_THROWABLE = "Message for InvalidOAuthClientExceptionTest Throwable";

    @Test
    public void testConstructorWithMessage(){
        OAuthClientException e = new OAuthClientException(MESSAGE);
        Assert.assertEquals(e.getMessage(), MESSAGE);
    }

    @Test
    public void testConstructorWithMessageAndThrowable(){
        Exception throwable = new Exception(MESSAGE_THROWABLE);
        OAuthClientException e = new OAuthClientException(MESSAGE, throwable);
        Assert.assertEquals(e.getMessage(), MESSAGE);
        Assert.assertNotNull(e.getCause(), "Cause cannot be null.");
        Assert.assertNotNull(e.getCause().getMessage(), MESSAGE_THROWABLE);
    }

}
