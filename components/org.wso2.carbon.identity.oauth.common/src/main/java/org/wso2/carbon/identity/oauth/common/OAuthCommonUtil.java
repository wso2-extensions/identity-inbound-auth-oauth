/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.common;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ALLOWED_CONTENT_TYPES;

/**
 * Common utility functions for OAuth related operations.
 */
public class OAuthCommonUtil {

    /**
     * Check whether HTTP content type header is an allowed content type.
     *
     * @param contentTypeHeader Content-Type header sent in HTTP request.
     * @param allowedContentTypes Allowed list of content types.
     * @return true if the content type is allowed, else, false.
     */
    public static boolean isAllowedContentType(String contentTypeHeader, List<String> allowedContentTypes) {

        if (contentTypeHeader == null || allowedContentTypes == null) {
            return false;
        }

        String[] requestContentTypes = contentTypeHeader.split(";");
        for (String requestContentType : requestContentTypes) {
            if (allowedContentTypes.contains(requestContentType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validate whether the HTTP request's content type are either "application/x-www-form-urlencoded" or
     * "application/json".
     *
     * @param request HTTP request to be validated.
     * @throws OAuthProblemException if HTTP request is has an unsupported content type.
     */
    public static void validateContentTypes(HttpServletRequest request) throws OAuthProblemException {

        String contentType = request.getContentType();
        if (!isAllowedContentType(contentType, ALLOWED_CONTENT_TYPES)) {
            throw OAuthUtils.handleBadContentTypeException(String.join(" or ", ALLOWED_CONTENT_TYPES));
        }
    }

    /**
     * Method to decode the request object jwt.
     * @param requestObjectJwt request object jwt
     * @return json body of the request object
     */
    public static JSONObject decodeRequestObject(String requestObjectJwt) {
        byte[] requestObjectBytes;
        try {
            requestObjectBytes = Base64.getDecoder().decode(requestObjectJwt.split("\\.")[1]);
        } catch (IllegalArgumentException e) {
            // Decode if the requestObject is base64-url encoded.
            requestObjectBytes = Base64.getUrlDecoder().decode(requestObjectJwt.split("\\.")[1]);
        }
        return new JSONObject(new String(requestObjectBytes, StandardCharsets.UTF_8));
    }
}
