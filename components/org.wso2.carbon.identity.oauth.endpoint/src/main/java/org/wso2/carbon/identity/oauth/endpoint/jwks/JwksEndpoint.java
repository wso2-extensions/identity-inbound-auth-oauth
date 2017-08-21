/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.endpoint.jwks;


import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.utils.CarbonUtils;


import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;


public class JwksEndpoint {
    private static final Log log = LogFactory.getLog(JwksEndpoint.class);
    private static final char[] ENCODE_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();
    private static final String alg = "RS256";
    private static final String use = "sig";
    private static final String kid = "d0ec514a32b6f88c0abd12a2840699bdd3deba9d";

    @GET
    @Path(value = "/jwks")
    @Produces(MediaType.APPLICATION_JSON)
    public String jwks() {

        String tenantDomain = null;
        Object tenantObj = IdentityUtil.threadLocalProperties.get().get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        if (tenantObj != null){
            tenantDomain = (String) tenantObj;
        }
        if (StringUtils.isEmpty(tenantDomain)){
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        RSAPublicKey publicKey = null;
        JSONObject jwksJson = new JSONObject();
        FileInputStream file = null;
        try {
            if (tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                file = new FileInputStream(CarbonUtils.getServerConfiguration().getFirstProperty
                        ("Security.KeyStore.Location"));
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                String password = CarbonUtils.getServerConfiguration().getInstance().getFirstProperty
                        ("Security.KeyStore.Password");
                keystore.load(file, password.toCharArray());
                String alias = CarbonUtils.getServerConfiguration().getInstance().getFirstProperty
                        ("Security.KeyStore.KeyAlias");
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(alias);
                // Get public key
                publicKey = (RSAPublicKey) cert.getPublicKey();
            } else {

                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                if (tenantId < 1 && tenantId != -1234) {
                    String errorMesage = "The tenant is not existing";
                    log.error(errorMesage);
                    return errorMesage;
                }
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                KeyStore keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                // Get certificate of public key
                Certificate cert = keyStore.getCertificate(tenantDomain);
                publicKey = (RSAPublicKey) cert.getPublicKey();

            }
            String modulus = base64EncodeUint(publicKey.getModulus());
            String exponent = base64EncodeUint(publicKey.getPublicExponent());
            String kty = publicKey.getAlgorithm();
            JSONArray jwksKeyArray = new JSONArray();
            JSONObject jwksKeys = new JSONObject();
            jwksKeys.put("kty", kty);
            jwksKeys.put("alg", alg);
            jwksKeys.put("use", use);
            jwksKeys.put("kid", kid);
            jwksKeys.put("n", modulus);
            jwksKeys.put("e", exponent);
            jwksKeyArray.put(jwksKeys);
            jwksJson.put("keys", jwksKeyArray);
        } catch (Exception e) {
            String errorMesage = "Error while generating the keyset";
            log.error(errorMesage);
            return errorMesage;
        } finally {
            IdentityIOStreamUtils.closeInputStream(file);
        }

        return jwksJson.toString();
    }

    /**
     * This method generates the key store file name from the Domain Name
     *
     * @return key store file name
     */
    private String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(".", "-");
        return (ksName + ".jks");
    }

    /**
     * This method is used to extract the modulus and exponent values of the jks file
     * by converting the raw value to big endian format and encoding it
     */
    public String base64Encode(final byte[] bytes, final int offset, final int length, final boolean padding) {
        final StringBuilder buffer = new StringBuilder(length * 3);
        for (int i = offset; i < offset + length; i += 3) {
            // p's are the segments for each byte. For every triple there are 6
            // segments
            int p0 = bytes[i] & 0xFC;
            p0 >>= 2;

            int p1 = bytes[i] & 0x03;
            p1 <<= 4;

            int p2;
            int p3;
            if (i + 1 < offset + length) {
                p2 = bytes[i + 1] & 0xF0;
                p2 >>= 4;
                p3 = bytes[i + 1] & 0x0F;
                p3 <<= 2;
            } else {
                p2 = 0;
                p3 = 0;
            }
            int p4;
            int p5;
            if (i + 2 < offset + length) {
                p4 = bytes[i + 2] & 0xC0;
                p4 >>= 6;
                p5 = bytes[i + 2] & 0x3F;
            } else {
                p4 = 0;
                p5 = 0;
            }

            if (i + 2 < offset + length) {
                buffer.append(ENCODE_MAP[p0]);
                buffer.append(ENCODE_MAP[p1 | p2]);
                buffer.append(ENCODE_MAP[p3 | p4]);
                buffer.append(ENCODE_MAP[p5]);
            } else if (i + 1 < offset + length) {
                buffer.append(ENCODE_MAP[p0]);
                buffer.append(ENCODE_MAP[p1 | p2]);
                buffer.append(ENCODE_MAP[p3]);
                if (padding) {
                    buffer.append('=');
                }
            } else {
                buffer.append(ENCODE_MAP[p0]);
                buffer.append(ENCODE_MAP[p1 | p2]);
                if (padding) {
                    buffer.append("==");
                }
            }
        }
        return buffer.toString();
    }

    public String base64urlEncode(final byte[] bytes) {

        return base64Encode(bytes, 0, bytes.length, false);
    }

    public String base64EncodeUint(final BigInteger v) {

        return base64urlEncode(v.toByteArray());
    }
}
