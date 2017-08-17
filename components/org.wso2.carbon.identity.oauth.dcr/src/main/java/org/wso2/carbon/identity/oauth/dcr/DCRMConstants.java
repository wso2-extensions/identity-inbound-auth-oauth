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

package org.wso2.carbon.identity.oauth.dcr;

public class DCRMConstants {

    public enum ErrorMessages {

        CONFLICT_EXISTING_APPLICATION("80001", "Application with the name %s already exist in the system"),
        FAILED_TO_REGISTER_SP("80002","Error occurred while creating service provider %s" ),
        FAILED_TO_GET_SP("80003","Error occurred while retrieving service provider %s" ),
        FAILED_TO_UPDATE_SP("80004","Error occurred while updating service provider %s" ),
        FAILED_TO_DELETE_SP("80005","Error occurred while deleting service provider %s" ),
        FAILED_TO_REGISTER_APPLICATION("80006","Error occurred while creating application with application name:  %s" ),
        FAILED_TO_GET_APPLICATION("80007","Error occurred while retrieving application with application name: %s" ),
        FAILED_TO_GET_APPLICATION_BY_ID("80008","Error occurred while retrieving application with client key: %s" ),
        FAILED_TO_UPDATE_APPLICATION("80009","Error occurred while updating application with client key: %s" ),
        BAD_REQUEST_INVALID_REDIRECT_URI("80010", "Invalid redirect URI: %s"),
        BAD_REQUEST_INVALID_INPUT("80011", "%s"),
        NOT_FOUND_APPLICATION_WITH_ID("80012", "Application not available for given client key: %s"),
        ERROR_CODE_UNEXPECTED("80000", "Unexpected error");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return code + " - " + message;
        }
    }
}
