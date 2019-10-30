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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.device.errorcodes;

/**
 * Error Codes for device flow.
 */
public class DeviceErrorCodes {

    public static final String UNAUTHORIZED_CLIENT = "unauthorized client";
    public static final String INVALID_REQUEST = "invalid request";
    public static final String UNSUPPORTED_GRANT_TYPE = "invalid grant";

    public DeviceErrorCodes() {

    }

    /**
     * Error codes that will be used in polling.
     */
    public static class SubDeviceErrorCodes {

        public static final String SLOW_DOWN = "slow_down";
        public static final String AUTHORIZATION_PENDING = "authorization_pending";
        public static final String EXPIRED_TOKEN = "expired_token";

    }
}
