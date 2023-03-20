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

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;

public class ParRequestData {

    private static Map<String, Map<String,String>> requests = new HashMap<>();
    private static Map<String, Long> requestTimes = new HashMap<>();
    private static Map<String, OAuthAuthzRequest> oauthRequests = new HashMap<>();

    public static void addRequest(String requestUri, Map<String, String> parameters) {

        requests.put(requestUri, parameters);
    }

    public static void addTime(String requestUri, long currentTime) {

        requestTimes.put(requestUri, currentTime);
    }

    public static void addOauthRequest(String requestUri, OAuthAuthzRequest oauthRequest) {

        oauthRequests.put(requestUri, oauthRequest);
    }

    public static Map<String, Map<String, String>> getRequests() {

        return requests;
    }

    public static Map<String, Long> getRequestTimes() {

        return requestTimes;
    }

    public static Map<String, OAuthAuthzRequest> getOauthRequests() {

        return oauthRequests;
    }
}
