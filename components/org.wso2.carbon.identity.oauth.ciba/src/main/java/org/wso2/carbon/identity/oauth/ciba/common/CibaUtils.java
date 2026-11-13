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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.common;

/**
 * CIBA related utility operations.
 */
public class CibaUtils {

    private CibaUtils() {

    }

    /**
     * Get the expiry time in human readable format.
     *
     * @param expiresIn Expiry time in seconds.
     * @return Expiry time string.
     */
    public static String getExpiryTimeAsString(long expiresIn) {

        if (expiresIn >= 3600) {
            long hours = expiresIn / 3600;
            return hours + (hours == 1 ? " hour" : " hours");
        } else if (expiresIn >= 60) {
            long minutes = expiresIn / 60;
            return minutes + (minutes == 1 ? " minute" : " minutes");
        } else {
            return expiresIn + (expiresIn == 1 ? " second" : " seconds");
        }
    }
}
