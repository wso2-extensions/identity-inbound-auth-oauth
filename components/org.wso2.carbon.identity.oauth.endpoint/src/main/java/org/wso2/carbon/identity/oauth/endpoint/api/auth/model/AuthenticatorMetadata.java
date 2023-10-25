/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth.model;

import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Contains the metadata related to an authenticator.
 */
public class AuthenticatorMetadata {

    private String i18nKey;

    private FrameworkConstants.AuthenticatorPromptType promptType;
    private List<Param> params = new ArrayList<>();

    private Map<String, String> additionalData = new HashMap<>();

    public AuthenticatorMetadata() {

    }

    public String getI18nKey() {

        return i18nKey;
    }

    public void setI18nKey(String i18nKey) {

        this.i18nKey = i18nKey;
    }

    public FrameworkConstants.AuthenticatorPromptType getPromptType() {

        return promptType;
    }

    public void setPromptType(FrameworkConstants.AuthenticatorPromptType promptType) {

        this.promptType = promptType;
    }

    public List<Param> getParams() {

        return params;
    }

    public void setParams(List<Param> params) {

        this.params = params;
    }

    public Map<String, String> getAdditionalData() {

        return additionalData;
    }

    public void setAdditionalData(Map<String, String> additionalData) {

        this.additionalData = additionalData;
    }
}

