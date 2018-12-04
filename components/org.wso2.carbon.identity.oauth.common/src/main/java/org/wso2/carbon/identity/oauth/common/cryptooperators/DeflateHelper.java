/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.common.cryptooperators;

import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.DeflateUtils;

/**
 * This class is used to compress and decompress JWT tokens.
 */
class DeflateHelper {

    DeflateHelper() {
    }

    static byte[] applyCompression(JWEHeader jweHeader, byte[] bytes) throws JOSEException {

        CompressionAlgorithm compressionAlg = jweHeader.getCompressionAlgorithm();
        if (compressionAlg == null) {
            return bytes;
        } else if (compressionAlg.equals(CompressionAlgorithm.DEF)) {
            try {
                return DeflateUtils.compress(bytes);
            } catch (Exception var4) {
                throw new JOSEException("Couldn't compress plain text: " + var4.getMessage(), var4);
            }
        } else {
            throw new JOSEException("Unsupported compression algorithm: " + compressionAlg);
        }
    }

    static byte[] applyDecompression(JWEHeader jweHeader, byte[] bytes) throws JOSEException {

        CompressionAlgorithm compressionAlg = jweHeader.getCompressionAlgorithm();
        if (compressionAlg == null) {
            return bytes;
        } else if (compressionAlg.equals(CompressionAlgorithm.DEF)) {
            try {
                return DeflateUtils.decompress(bytes);
            } catch (Exception var4) {
                throw new JOSEException("Couldn't decompress plain text: " + var4.getMessage(), var4);
            }
        } else {
            throw new JOSEException("Unsupported compression algorithm: " + compressionAlg);
        }
    }
}