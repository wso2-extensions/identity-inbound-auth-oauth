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
package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoRequestValidator;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;

/**
 * Validates the schema and authorization header according to the specification
 *
 * @see http://openid.net/specs/openid-connect-basic-1_0-22.html#anchor6
 */
public class UserInforRequestDefaultValidator implements UserInfoRequestValidator {

    private static final String US_ASCII = "US-ASCII";
    private static final String ACCESS_TOKEN_PARAM = "access_token=";
    private static final String BEARER = "Bearer";
    private static final String CONTENT_TYPE_HEADER_VALUE = "application/x-www-form-urlencoded";
    public static final String CHARSET = "charset=";

    @Override
    public String validateRequest(HttpServletRequest request) throws UserInfoEndpointException {

        String authzHeaders = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authzHeaders == null) {
            String contentTypeHeaders = request.getHeader(HttpHeaders.CONTENT_TYPE);
            // To validate the Content_Type header.
            if (StringUtils.isBlank(contentTypeHeaders)) {
                throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                        "Authorization or Content-Type header is missing");
            }

            // Restricting passing the access token via request body in GET requests.
            if (HttpMethod.GET.equals(request.getMethod())) {
                throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                        "Authorization header is missing");
            }
            if (contentTypeHeaders.trim().startsWith(CONTENT_TYPE_HEADER_VALUE)) {
                String charset = getCharsetFromContentType(contentTypeHeaders);

                // Use a default charset if none is provided
                Charset encodingCharset;
                try {
                    encodingCharset = charset != null ? Charset.forName(charset) : StandardCharsets.UTF_8;
                } catch (IllegalArgumentException e) {
                    encodingCharset = StandardCharsets.UTF_8;
                }
                String[] arrAccessToken = new String[2];
                String requestBody = EndpointUtil.readRequestBody(request, encodingCharset);
                String[] arrAccessTokenNew;
                // To check whether the entity-body consist entirely of ASCII [USASCII] characters.
                if (!isPureAscii(requestBody)) {
                    throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                            "Body contains non ASCII characters");
                }
                if (requestBody.contains(ACCESS_TOKEN_PARAM)) {
                    arrAccessToken = requestBody.trim().split(ACCESS_TOKEN_PARAM);
                    if (arrAccessToken[1].contains("&")) {
                        arrAccessTokenNew = arrAccessToken[1].split("&", 2);
                        return arrAccessTokenNew[0];
                    }
                }
                return arrAccessToken[1];
            } else {
                throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                        "Content-Type header is wrong");
            }
        }
        String[] authzHeaderInfo = authzHeaders.trim().split(" ");
        if (authzHeaderInfo.length < 2 || !BEARER.equals(authzHeaderInfo[0])) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Bearer token missing");
        }
        return authzHeaderInfo[1];
    }

    public static boolean isPureAscii(String requestBody) {

        byte[] bytearray = requestBody.getBytes(StandardCharsets.UTF_8);
        CharsetDecoder charsetDecoder = Charset.forName(US_ASCII).newDecoder();
        try {
            CharBuffer charBuffer = charsetDecoder.decode(ByteBuffer.wrap(bytearray));
            charBuffer.toString();
        } catch (CharacterCodingException e) {
            return false;
        }
        return true;
    }

    private String getCharsetFromContentType(String contentTypeHeader) {
        // Split the Content-Type header value to extract charset
        String[] parts = contentTypeHeader.split(";");

        for (String part : parts) {
            String trimmedPart = part.trim();
            if (trimmedPart.toLowerCase().startsWith(CHARSET)) {
                return trimmedPart.substring(CHARSET.length()).trim();
            }
        }
        return null;
    }
}
