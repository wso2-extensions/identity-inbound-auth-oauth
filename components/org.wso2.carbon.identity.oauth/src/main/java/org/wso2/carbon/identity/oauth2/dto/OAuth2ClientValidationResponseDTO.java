/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.dto;

public class OAuth2ClientValidationResponseDTO {
    private boolean validClient;
    private String applicationName;
    private String errorCode;
    private String errorMsg;
    private String callbackURL;
    private boolean pkceMandatory;
    private boolean pkceSupportPlain;
    private boolean tbMandatory;

    public boolean isTbMandatory() {
        return tbMandatory;
    }

    public void setTbMandatory(boolean tbMandatory) {
        this.tbMandatory = tbMandatory;
    }
    public boolean isValidClient() {
        return validClient;
    }

    public void setValidClient(boolean validClient) {
        this.validClient = validClient;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public String getCallbackURL() {
        return callbackURL;
    }

    public void setCallbackURL(String callbackURL) {
        this.callbackURL = callbackURL;
    }

    public boolean isPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public boolean isPkceMandatory() {
        return pkceMandatory;
    }

    public void setPkceMandatory(boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
    }
}
