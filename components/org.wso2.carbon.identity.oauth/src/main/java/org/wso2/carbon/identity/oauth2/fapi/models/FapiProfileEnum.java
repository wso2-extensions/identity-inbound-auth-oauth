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

package org.wso2.carbon.identity.oauth2.fapi.models;

import org.wso2.carbon.identity.oauth.common.OAuthConstants;

/**
 * Enum representing supported FAPI profiles.
 * <p>
 * Each enum constant holds the string value used in configuration.
 */
public enum FapiProfileEnum {

    FAPI1_ADVANCED(OAuthConstants.FAPIProfiles.FAPI1_ADVANCED),
    FAPI2_SECURITY(OAuthConstants.FAPIProfiles.FAPI2_SECURITY);

    private final String value;

    /**
     * Create a FapiProfileEnum with the given string value.
     *
     * @param value the string value for the enum constant
     */
    FapiProfileEnum(String value) {
        this.value = value;
    }

    /**
     * Return the string value associated with this enum constant.
     *
     * @return the enum string value
     */
    public String value() {
        return value;
    }

    /**
     * Return the string representation of this enum constant.
     *
     * @return string representation of the enum
     */
    @Override
    public String toString() {
        return String.valueOf(value);
    }

    /**
     * Convert a string value to the corresponding FapiProfileEnum constant.
     *
     * @param value the string representation of the enum
     * @return matching FapiProfileEnum constant, or null if no match is found
     */
    public static FapiProfileEnum fromValue(String value) {
        for (FapiProfileEnum profileEnum : FapiProfileEnum.values()) {
            if (profileEnum.value().equals(value)) {
                return profileEnum;
            }
        }
        return null;
    }
}
