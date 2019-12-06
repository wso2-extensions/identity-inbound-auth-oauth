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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.test.common.testng.utils;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

/**
 * A mock authenticated user can be used for unit tests.
 */
public class MockAuthenticatedUser extends AuthenticatedUser {

    private static final long serialVersionUID = -6173380521599043423L;

    public MockAuthenticatedUser(String userName) {
        this.userName = userName;
    }

    @Override
    public String toString() {
        return userName;
    }

}
