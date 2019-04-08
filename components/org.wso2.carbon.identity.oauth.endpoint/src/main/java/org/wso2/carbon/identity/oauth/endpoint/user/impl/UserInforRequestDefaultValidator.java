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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

/**
 * Validates the schema and authorization header according to the specification
 *
 * @see http://openid.net/specs/openid-connect-basic-1_0-22.html#anchor6
 */
public class UserInforRequestDefaultValidator implements UserInfoRequestValidator {

    private static final String US_ASCII = "US-ASCII";
    private static final String ACCESS_TOKEN_PARAM = "access_token";
    private static final String BEARER = "Bearer";

    @Override
    public String validateRequest(HttpServletRequest request) throws UserInfoEndpointException {

        String authzHeaders = request.getHeader(HttpHeaders.AUTHORIZATION);
        String accessToken = request.getParameter(ACCESS_TOKEN_PARAM);
        if (StringUtils.isBlank(authzHeaders) && StringUtils.isNotBlank(accessToken)) {
            return accessToken;
        }

        if (StringUtils.isBlank(authzHeaders)) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Bearer token missing");
        }

        String[] authzHeaderInfo = authzHeaders.trim().split(" ");
        if (authzHeaderInfo.length < 2 || !BEARER.equals(authzHeaderInfo[0])) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Bearer token missing");
        }

        return authzHeaderInfo[1];
    }

    public static boolean isPureAscii(String requestBody) {

        byte[] bytearray = requestBody.getBytes();
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
