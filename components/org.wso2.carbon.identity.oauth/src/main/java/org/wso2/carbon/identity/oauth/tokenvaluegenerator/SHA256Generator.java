/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.tokenvaluegenerator;

import org.apache.oltu.oauth2.as.issuer.ValueGenerator;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Token value generator class to generate SHA-256 hash as a token value (256 bits, 64 Hex Characters).
 */
public class SHA256Generator implements ValueGenerator {

    @Override
    public String generateValue() throws OAuthSystemException {

        // UUID is a 36 (32 + 4) digit string directly hashing it to SHA-256 does not make sense since SHA-256 is a
        // 64 digit string. We are combining two UUIDs to generate a long string.
        return this.generateValue(UUID.randomUUID().toString() + UUID.randomUUID().toString());
    }

    @Override
    public String generateValue(String value) throws OAuthSystemException {

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            digest.reset();
            digest.update(value.getBytes(StandardCharsets.UTF_8));

            byte[] messageDigest = digest.digest();

            // Return the hex representation of the hash.
            return Hex.toHexString(messageDigest);
        } catch (Exception e) {
            throw new OAuthSystemException("Error while generating the token value.", e);
        }
    }
}
