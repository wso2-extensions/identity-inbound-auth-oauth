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
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoRequestValidator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.Scanner;

/**
 * Validates the schema and authorization header according to the specification
 *
 * @see http://openid.net/specs/openid-connect-basic-1_0-22.html#anchor6
 */
public class UserInforRequestDefaultValidator implements UserInfoRequestValidator {
    private static String CONTENT_TYPE_HEADER_VALUE = "application/x-www-form-urlencoded";
    private static String US_ASCII = "US-ASCII";

    @Override
    public String validateRequest(HttpServletRequest request) throws UserInfoEndpointException {
        String authzHeaders = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authzHeaders == null) {
            String contentTypeHeaders = request.getHeader(HttpHeaders.CONTENT_TYPE);
            //to validate the Content_Type header
            if (StringUtils.isEmpty(contentTypeHeaders)) {
                throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                        "Authorization or Content-Type header is missing");
            }
            if ((CONTENT_TYPE_HEADER_VALUE).equals(contentTypeHeaders.trim())) {
                StringBuilder stringBuilder = new StringBuilder();

                Scanner scanner = null;
                try {
                    scanner = new Scanner(request.getInputStream());
                } catch (IOException e) {
                    throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                            "can not read the request body");
                }
                while (scanner.hasNextLine()) {
                    stringBuilder.append(scanner.nextLine());
                }
                String[] arrAccessToken = new String[2];
                String requestBody = stringBuilder.toString();
                String[] arrAccessTokenNew;
                //to check whether the entity-body consist entirely of ASCII [USASCII] characters
                if (!isPureAscii(requestBody)) {
                    throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                            "Body contains non ASCII characters");
                }
                if (requestBody.contains("access_token=")) {
                    arrAccessToken = requestBody.trim().split("access_token=");
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

        String[] authzHeaderInfo = ((String) authzHeaders).trim().split(" ");
        if (!"Bearer".equals(authzHeaderInfo[0])) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Bearer token missing");
        }
        if (authzHeaderInfo.length == 1) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Access token missing");
        }
        return authzHeaderInfo[1];
    }


    public static boolean isPureAscii(String requestBody) {
        byte bytearray[] = requestBody.getBytes();
        CharsetDecoder charsetDecoder = Charset.forName(US_ASCII).newDecoder();
        try {
            CharBuffer charBuffer = charsetDecoder.decode(ByteBuffer.wrap(bytearray));
            charBuffer.toString();
        } catch (CharacterCodingException e) {
            return false;
        }
        return true;
    }
}
