/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.rar.util;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.common.util.AuthorizationDetailsConstants;

/**
 * Utility class for handling and validating authorization details in OAuth2 requests.
 */
public class AuthorizationDetailsUtils {

    /**
     * Determines if the given {@link OAuth2Parameters} object contains
     * {@link org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails AuthorizationDetails}.
     *
     * @param oAuth2Parameters The requested OAuth2 parameters to check.
     * @return {@code true} if the OAuth2 parameters contain non-empty authorization details array,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuth2Parameters oAuth2Parameters) {

        return oAuth2Parameters.getAuthorizationDetails() != null &&
                !oAuth2Parameters.getAuthorizationDetails().getDetails().isEmpty();
    }

    /**
     * Determines if the given {@link OAuthAuthzRequest} object contains {@code authorization_details}.
     *
     * @param oauthRequest The OAuth Authorization Request to check.
     * @return {@code true} if the OAuth authorization request contains a non-blank authorization details parameter,
     * {@code false} otherwise.
     */
    public static boolean isRichAuthorizationRequest(final OAuthAuthzRequest oauthRequest) {

        return StringUtils.isNotBlank(oauthRequest.getParam(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS));
    }
}
