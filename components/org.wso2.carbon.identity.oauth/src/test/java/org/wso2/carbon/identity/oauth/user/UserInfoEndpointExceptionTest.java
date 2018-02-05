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

package org.wso2.carbon.identity.oauth.user;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.testng.Assert.assertNull;
import static org.testng.AssertJUnit.assertEquals;

public class UserInfoEndpointExceptionTest extends IdentityBaseTest {

    @Test
    public void testGetErrorCodeAndMessage() throws Exception {
        UserInfoEndpointException userInfoEndpointException = new UserInfoEndpointException(
                UserInfoEndpointException.ERROR_CODE_INVALID_TOKEN);
        assertEquals(userInfoEndpointException.getErrorMessage(), UserInfoEndpointException.ERROR_CODE_INVALID_TOKEN);
        assertNull(userInfoEndpointException.getErrorCode());

        userInfoEndpointException = new UserInfoEndpointException(UserInfoEndpointException.
                ERROR_CODE_INSUFFICIENT_SCOPE, UserInfoEndpointException.ERROR_CODE_INSUFFICIENT_SCOPE);
        assertEquals(userInfoEndpointException.getErrorMessage(), UserInfoEndpointException.
                ERROR_CODE_INSUFFICIENT_SCOPE);
        assertEquals(userInfoEndpointException.getErrorCode(), UserInfoEndpointException.ERROR_CODE_INSUFFICIENT_SCOPE);

        userInfoEndpointException = new UserInfoEndpointException(UserInfoEndpointException.
                ERROR_CODE_INSUFFICIENT_SCOPE, new Throwable());
        assertEquals(userInfoEndpointException.getErrorMessage(), UserInfoEndpointException.ERROR_CODE_INSUFFICIENT_SCOPE);
    }
}
