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

/**
 * Class containing step type enums.
 */
public enum StepTypeEnum {

    MULTI_OPTIONS_PROMPT("MULTI_OPTIONS_PROMPT"),
    AUTHENTICATOR_PROMPT("AUTHENTICATOR_PROMPT");

    private String value;

    StepTypeEnum(String v) {

        value = v;
    }

    public String value() {

        return value;
    }

    @Override
    public String toString() {

        return String.valueOf(value);
    }

    /**
     * This method is used to get the StepTypeEnum from the given value.
     *
     * @param value The value of the StepTypeEnum.
     * @return The StepTypeEnum.
     */
    public static StepTypeEnum fromValue(String value) {

        for (StepTypeEnum stepType : StepTypeEnum.values()) {
            if (stepType.value.equals(value)) {
                return stepType;
            }
        }
        return null;
    }
}

