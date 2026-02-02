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

package org.wso2.carbon.identity.oauth2.config.models;

import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigMgtErrorMessages;

import static org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigUtils.handleServerException;

/**
 * Enum representing the usage scope of an issuer.
 */
public enum UsageScope {

    /**
     * Issuer is not used in any organization.
     */
    NONE("NONE"),

    /**
     * Issuer is used in all existing and future organizations.
     */
    ALL_EXISTING_AND_FUTURE_ORGS("ALL_EXISTING_AND_FUTURE_ORGS");

    private final String value;

    UsageScope(String value) {

        this.value = value;
    }

    public String getValue() {

        return value;
    }

    /**
     * Get UsageScope enum from string value.
     *
     * @param value String value of the usage scope.
     * @return UsageScope enum.
     * @throws OAuth2OIDCConfigMgtServerException if the value is invalid.
     */
    public static UsageScope fromValue(String value) throws OAuth2OIDCConfigMgtServerException {

        if (value == null) {
            throw handleServerException(
                    OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_INVALID_SCOPE,
                    null, "null");
        }

        for (UsageScope scope : UsageScope.values()) {
            if (scope.value.equals(value)) {
                return scope;
            }
        }
        throw handleServerException(
                OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_INVALID_SCOPE, null,
                value);
    }

    @Override
    public String toString() {

        return this.value;
    }
}

