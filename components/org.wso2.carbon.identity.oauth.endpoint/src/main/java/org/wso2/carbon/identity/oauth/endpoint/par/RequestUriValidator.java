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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.par;

import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;

import java.time.Duration;
import java.time.LocalTime;
import java.util.Calendar;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

public class RequestUriValidator {

    public static boolean isValidRequestUri (String requestUri) throws InvalidRequestException {

        if (requestUriExists(requestUri) && !requestUriExpired(requestUri)) {
            return true;
        }
        return false;
    }


    public static boolean requestUriExists(String requestUri) throws InvalidRequestException {
        Map<String, Map<String, String>> parRequests = ParRequestData.getRequests();

        if (parRequests.containsKey(requestUri) ) {
            return true;
        } else {
            throw new InvalidRequestException("Invalid request URI in the authorization request.",
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.SESSION_TIME_OUT);
        }
    }

    public static boolean requestUriExpired(String requestUri) throws InvalidRequestException {

        Map<String, Long> requestTimes = ParRequestData.getRequestTimes();
        //LocalTime currentTime = java.time.LocalTime.now();
        long currentTime = Calendar.getInstance(TimeZone.getTimeZone(ParConstants.UTC)).getTimeInMillis();
        long requestMade = requestTimes.get(requestUri);
        long defaultExpiryInSecs = ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;

        long duration = (currentTime - requestMade);

        if (TimeUnit.MILLISECONDS.toSeconds(duration) < defaultExpiryInSecs) {
            return false;
        } else {
            throw new InvalidRequestException("Request URI expired",
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REQUEST_URI);
        }
    }
}
