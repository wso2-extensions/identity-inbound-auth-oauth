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

/**
 * Class containing the data related to an input parameter.
 */
public class Param {

    private String param;
    private FrameworkConstants.AuthenticatorParamType type;
    private Boolean isConfidential;
    private Integer order;
    private String validationRegex;
    private String i18nKey;

    public Param() {

    }

    public Param(String param, FrameworkConstants.AuthenticatorParamType type, Boolean isConfidential, Integer order,
                 String validationRegex, String i18nKey) {

        this.param = param;
        this.type = type;
        this.isConfidential = isConfidential;
        this.order = order;
        this.validationRegex = validationRegex;
        this.i18nKey = i18nKey;
    }

    public String getParam() {

        return param;
    }

    public void setParam(String param) {

        this.param = param;
    }

    public FrameworkConstants.AuthenticatorParamType getType() {

        return type;
    }

    public void setType(FrameworkConstants.AuthenticatorParamType type) {

        this.type = type;
    }

    public Boolean getConfidential() {

        return isConfidential;
    }

    public void setConfidential(Boolean confidential) {

        isConfidential = confidential;
    }

    public Integer getOrder() {

        return order;
    }

    public void setOrder(Integer order) {

        this.order = order;
    }

    public String getValidationRegex() {

        return validationRegex;
    }

    public void setValidationRegex(String validationRegex) {

        this.validationRegex = validationRegex;
    }

    public String getI18nKey() {

        return i18nKey;
    }

    public void setI18nKey(String i18nKey) {

        this.i18nKey = i18nKey;
    }
}

