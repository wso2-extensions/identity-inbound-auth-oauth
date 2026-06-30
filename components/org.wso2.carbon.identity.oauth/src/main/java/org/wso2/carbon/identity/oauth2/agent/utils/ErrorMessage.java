/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.agent.utils;

/**
 * Error message enum for Agent Config Mgt Exceptions.
 */
public enum ErrorMessage {

    ERROR_CODE_INVALID_TENANT_DOMAIN("60004",
            "Invalid input.",
            "%s is not a valid tenant domain."),

    ERROR_CODE_AGENT_CONFIG_RETRIEVE("65023",
            "Unable to retrieve Agent configuration.",
            "Server encountered an error while retrieving the Agent configuration of %s."),

    ERROR_CODE_AGENT_CONFIG_UPDATE("65024",
            "Unable to update Agent configuration.",
            "Server encountered an error while updating the Agent configuration of %s."),

    ERROR_CODE_AGENT_CONFIG_DELETE("65025",
            "Unable to delete Agent configuration.",
            "Server encountered an error while deleting the Agent configuration of %s.");

    private final String code;
    private final String message;
    private final String description;

    ErrorMessage(String code, String message, String description) {

        this.code = code;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the {@code code}.
     *
     * @return Returns the {@code code}.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get the {@code message}.
     *
     * @return Returns the {@code message}.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get the {@code description}.
     *
     * @return Returns the {@code description}.
     */
    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return code + ":" + message;
    }
}
