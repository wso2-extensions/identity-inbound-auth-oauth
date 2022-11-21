/*
 * Copyright (c) 2010-2021, WSO2 LLC. (https://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2;

/**
 * Runtime constants for Password Grant Password Expiry enforcement
 */
public class PasswordPolicyConstants {

        public static final String STATE = "state";
        public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM =
                "http://wso2.org/claims/identity/lastPasswordUpdateTime";
        public static final String CREATED_CLAIM = "http://wso2.org/claims/created";
        public static final String CREATED_CLAIM_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
        public static final String CREATED_CLAIM_TIMEZONE = "GMT";
        public static final String PASSWORD_CHANGE_EVENT_HANDLER_NAME = "passwordExpiry";
        public static final String PASSWORD_EXPIRY_IN_DAYS_FROM_CONFIG = "passwordExpiry.passwordExpiryInDays";
        public static final int PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE = 30;

        private PasswordPolicyConstants() {      // To prevent instantiation
        }
}
