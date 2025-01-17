/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.util;

/**
 * Rich Authorization Requests Test Constants.
 */
public class TestConstants {

    public static final String TEST_AUTHORIZATION_CODE = "b1b833f0-f605-4f5c-add6-38ea8ce1b969";
    public static final String TEST_CODE_ID = "81197bc6-63f3-4c0f-90dd-1588076ab50f";
    public static final String TEST_CONSENT_ID = "52481ccd-0927-4d17-8cfc-5110fc4aa009";
    public static final String TEST_DB_NAME = "TEST_IAM_RAR_DATABASE";
    public static final int TEST_TENANT_ID = 1234;
    public static final String TEST_TOKEN_ID = "e1fea951-a3b5-4347-bd73-b18b3feecd54";
    public static final String TEST_TYPE = "test_type_v1";
    public static final String TEST_NAME = "test_name_v1";
    public static final String TEST_SCHEMA = "{\"type\":\"object\",\"required\":[\"type\"],\"properties\":" +
            "{\"type\":{\"type\":\"string\",\"enum\":[\"test_type_v1\"]},\"actions\":{\"type\":\"array\"," +
            "\"items\":{\"type\":\"string\",\"enum\":[\"initiate\"]}}}}";

    private TestConstants() {
        // Private constructor to prevent instantiation
    }
}
