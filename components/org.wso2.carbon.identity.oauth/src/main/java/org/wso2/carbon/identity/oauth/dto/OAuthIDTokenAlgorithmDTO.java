/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.oauth.dto;

import java.util.List;

/**
 * Class to transfer ID token encryption related algorithms.
 */
public class OAuthIDTokenAlgorithmDTO {

    private String defaultIdTokenEncryptionAlgorithm;
    private List<String> supportedIdTokenEncryptionAlgorithms;
    private String defaultIdTokenEncryptionMethod;
    private List<String> supportedIdTokenEncryptionMethods;

    public String getDefaultIdTokenEncryptionAlgorithm() {
        return defaultIdTokenEncryptionAlgorithm;
    }

    public String getDefaultIdTokenEncryptionMethod() {
        return defaultIdTokenEncryptionMethod;
    }

    public List<String> getSupportedIdTokenEncryptionAlgorithms() {
        return supportedIdTokenEncryptionAlgorithms;
    }

    public List<String> getSupportedIdTokenEncryptionMethods() {
        return supportedIdTokenEncryptionMethods;
    }

    public void setDefaultIdTokenEncryptionAlgorithm(String defaultIdTokenEncryptionAlgorithm) {
        this.defaultIdTokenEncryptionAlgorithm = defaultIdTokenEncryptionAlgorithm;
    }

    public void setDefaultIdTokenEncryptionMethod(String defaultIdTokenEncryptionMethod) {
        this.defaultIdTokenEncryptionMethod = defaultIdTokenEncryptionMethod;
    }

    public void setSupportedIdTokenEncryptionAlgorithms(List<String> supportedIdTokenEncryptionAlgorithms) {
        this.supportedIdTokenEncryptionAlgorithms = supportedIdTokenEncryptionAlgorithms;
    }

    public void setSupportedIdTokenEncryptionMethods(List<String> supportedIdTokenEncryptionMethods) {
        this.supportedIdTokenEncryptionMethods = supportedIdTokenEncryptionMethods;
    }
}
