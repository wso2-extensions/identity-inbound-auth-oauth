/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session;

import org.apache.commons.codec.binary.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil.getOrigin;

public class DefaultOIDCSessionStateManager implements OIDCSessionStateManager {

    private static final String RANDOM_ALG_SHA1 = "SHA1PRNG";
    private static final String DIGEST_ALG_SHA256 = "SHA-256";

    /**
     * Generates a session state using the provided client id, client callback url and browser state cookie id
     *
     * @param clientId
     * @param rpCallBackUrl
     * @param opBrowserState
     * @return generated session state value
     */
    public String getSessionStateParam(String clientId, String rpCallBackUrl, String opBrowserState) {

        try {
            String salt = generateSaltValue();
            String sessionStateDataString =
                    clientId + " " + getOrigin(rpCallBackUrl) + " " + opBrowserState + " " + salt;

            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALG_SHA256);
            digest.update(sessionStateDataString.getBytes());
            return bytesToHex(digest.digest()) + "." + salt;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error while calculating session state.", e);
        }
    }

    /**
     * Adds the browser state cookie to the response
     *
     * @param response
     * @return Cookie
     */
    public Cookie addOPBrowserStateCookie(HttpServletResponse response) {

        Cookie cookie = new Cookie(OIDCSessionConstants.OPBS_COOKIE_ID, UUID.randomUUID().toString());
        cookie.setSecure(true);
        cookie.setPath("/");

        response.addCookie(cookie);
        return cookie;
    }

    private static String generateSaltValue() throws NoSuchAlgorithmException {

        byte[] bytes = new byte[16];
        SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALG_SHA1);
        secureRandom.nextBytes(bytes);
        return Base64.encodeBase64URLSafeString(bytes);
    }

    private static String bytesToHex(byte[] bytes) {

        StringBuilder result = new StringBuilder();
        for (byte byt : bytes) {
            result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        }
        return result.toString();
    }
}
