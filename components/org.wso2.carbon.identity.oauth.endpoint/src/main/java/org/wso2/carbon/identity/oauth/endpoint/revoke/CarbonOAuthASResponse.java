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

package org.wso2.carbon.identity.oauth.endpoint.revoke;

import org.apache.oltu.oauth2.common.message.OAuthResponse;

/**
 * Implementation of OAuth response.
 */
public class CarbonOAuthASResponse extends OAuthResponse {

    private static OAuthRevokeResponseBuilder revokeResponseBuilder;

    protected CarbonOAuthASResponse(String uri, int responseStatus) {

        super(uri, responseStatus);
    }

    public static OAuthRevokeResponseBuilder revokeResponse(int code) {

        revokeResponseBuilder = new OAuthRevokeResponseBuilder(code);
        return revokeResponseBuilder;
    }

    /**
     * This class build OAuth revoke response.
     */
    public static class OAuthRevokeResponseBuilder extends OAuthResponseBuilder {

        public OAuthRevokeResponseBuilder(int responseCode) {

            super(responseCode);

        }
    }
}
