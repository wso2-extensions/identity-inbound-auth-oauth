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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.codec.binary.Base64;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.Properties;

/**
 * This class validates request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */

public class RequestObjectValidatorImpl implements RequestObjectValidator {

    private static final String X5T = "x5t";
    private static final String KID = "kid";
    private static final String JKU = "jku";
    private static final String JWK = "jwk";
    private static final String X5U = "x5u";
    private static final String X5C = "x5c";
    private static final String X5T_S256 = "x5t#s256";
    //JWE is consists of five parts seperated by 4 '.'s as JOSE header , JWE encrypted key, Initialization vector,
    // Cipher text and Authentication Tag
    private static final int NUMBER_OF_PARTS_IN_JWE = 5;
    //JWS is consists of three parts seperated by 2 '.'s as JOSE header, JWS payload, JWS signature
    private static final int NUMBER_OF_PARTS_IN_JWS = 3;

    private static Log log = LogFactory.getLog(RequestObjectValidatorImpl.class);
    private static Properties properties;
    private String jwtAssertion;
    private byte[] jwtSignature;
    private String headerValue;
    private static String payload;
    private static final Base64 base64Url = new Base64(true);

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        RequestObjectValidatorImpl.payload = payload;
    }

    @Override
    public void validateSignature(String requestObject) throws RequestObjectException {

        String thumbPrint;
        // The public key corresponding to the key used to sign the message can be any of these header elements:
        // jku, jwk, kid, x5u, x5c, x5t and x5t#s256
        if (getJsonHeaderObject() != null) {
            if (getJsonHeaderObject().get(X5T) != null) {
                thumbPrint = getJsonHeaderObject().get(X5T).toString();
            } else if (getJsonHeaderObject().get(KID) != null) {
                thumbPrint = getJsonHeaderObject().get(KID).toString();
            } else if (getJsonHeaderObject().get(JKU) != null) {
                thumbPrint = getJsonHeaderObject().get(JKU).toString();
            } else if (getJsonHeaderObject().get(JWK) != null) {
                thumbPrint = getJsonHeaderObject().get(JWK).toString();
            } else if (getJsonHeaderObject().get(X5U) != null) {
                thumbPrint = getJsonHeaderObject().get(X5U).toString();
            } else if (getJsonHeaderObject().get(X5C) != null) {
                thumbPrint = getJsonHeaderObject().get(X5C).toString();
            } else if (getJsonHeaderObject().get(X5T_S256) != null) {
                thumbPrint = getJsonHeaderObject().get(X5T_S256).toString();
            } else {
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Can not find the " +
                        "certificate thumbprint for signature validation");
            }
        } else {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "The request object " +
                    "header is null. Hence signature validation failed.");
        }
        if (log.isDebugEnabled()) {
            log.debug("The certificate thumbPrint value for the certificate is: " + thumbPrint + "with the header:" +
                    headerValue);
        }
        verifyJWTSignature(thumbPrint, requestObject);
    }

    /**
     * Decrypt the request object.
     *
     * @param requestObject    requestObject
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public void decrypt(String requestObject, OAuth2Parameters oAuth2Parameters) throws RequestObjectException {

        EncryptedJWT encryptedJWT;
        try {
            encryptedJWT = EncryptedJWT.parse(requestObject);
            RSAPrivateKey rsaPrivateKey = getRsaPrivateKey(oAuth2Parameters);
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
            encryptedJWT.decrypt(decrypter);
            if (encryptedJWT != null && encryptedJWT.getCipherText() != null) {
                setPayload(encryptedJWT.getCipherText().toString());
            }
            //if the request object is a nested jwt then the payload of the jwe is a jws.
            if (encryptedJWT != null && encryptedJWT.getCipherText() != null && encryptedJWT.getCipherText().toString()
                    .split(".").length == NUMBER_OF_PARTS_IN_JWS) {
                validateSignature(encryptedJWT.getCipherText().toString());
                if (log.isDebugEnabled()) {
                    log.debug("As the request object is a nested jwt, passed the payload to validate the signature.");
                }
            }
        } catch (JOSEException | IdentityOAuth2Exception | java.text.ParseException e) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Failed to decrypt " +
                    "request object.");
        }
    }

    private RSAPrivateKey getRsaPrivateKey(OAuth2Parameters oAuth2Parameters) throws IdentityOAuth2Exception {
        String tenantDomain = getTenantDomainForDecryption(oAuth2Parameters);
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        Key key = OAuth2Util.getPrivateKey(tenantDomain, tenantId);
        return (RSAPrivateKey) key;
    }

    /**
     * Decide whether this request object is a signed object encrypted object or a nested object.
     *
     * @param requestObject    request object
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public void validateRequestObject(String requestObject, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException {

        if (!OAuth2Util.isValidJson(requestObject)) {
            String[] jwtTokenValues = requestObject.split("\\.");
            if (jwtTokenValues.length == NUMBER_OF_PARTS_IN_JWS) {
                processRequestObject(jwtTokenValues);
                validateSignature(requestObject);
            } else if (jwtTokenValues.length == NUMBER_OF_PARTS_IN_JWE) {
                decrypt(requestObject, oAuth2Parameters);
            }
        }
    }

    private void processRequestObject(String[] jwtTokenValues) {

        headerValue = new String(base64Url.decode(jwtTokenValues[0].getBytes()));
        jwtSignature = base64Url.decode(jwtTokenValues[2].getBytes());
        jwtAssertion = jwtTokenValues[0] + "." + jwtTokenValues[1];
        if (StringUtils.isNotBlank(jwtTokenValues[1])) {
            setPayload(new String(base64Url.decode(jwtTokenValues[1].getBytes())));
        }
    }

    /**
     * Get tenant domain from oAuth2Parameters.
     *
     * @param oAuth2Parameters oAuth2Parameters
     * @return Tenant domain
     */
    private String getTenantDomainForDecryption(OAuth2Parameters oAuth2Parameters) {

        return oAuth2Parameters.getTenantDomain();
    }

    private void verifyJWTSignature(String thumbPrint, String requestObject) throws RequestObjectException {

        if (jwtAssertion != null && jwtSignature != null) {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(new FileInputStream(buildFilePath(getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE))),
                        getPropertyValue(OAuthConstants.CLIENT_TRUST_STORE_PASSWORD).toCharArray());
                String alias = getAliasForX509CertThumb(thumbPrint.getBytes(), keyStore);

                if (StringUtils.isEmpty(alias)) {
                    log.error("Could not obtain the alias from the certificate.");
                    throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Could not obtain" +
                            " the alias from the certificate.");
                }
                verifySignature(requestObject, keyStore, alias);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                    InvalidKeyException | SignatureException | JOSEException | java.text.ParseException e) {
                throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, e.getMessage());
            }
        } else {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Signature is null.");
        }
    }

    private void verifySignature(String requestObject, KeyStore keyStore
            , String alias) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            JOSEException, java.text.ParseException, RequestObjectException {

        Certificate certificate = keyStore.getCertificate(alias);
        // Get public key
        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        SignedJWT signedJWT = SignedJWT.parse(requestObject);
        if (!signedJWT.verify(verifier)) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Signature validation failed.");
        }
    }

    private JSONObject getJsonHeaderObject() throws RequestObjectException {

        JSONParser parser = new JSONParser();
        JSONObject jsonHeaderObject;
        try {
            jsonHeaderObject = (JSONObject) parser.parse(headerValue);
        } catch (ParseException e) {
            log.error("JWT json header is invalid.");
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "JWT json header is " +
                    "invalid.");
        }
        return jsonHeaderObject;
    }

    /**
     * Build the absolute path of a give file path
     *
     * @param path File path
     * @return Absolute file path
     */
    private static String buildFilePath(String path) {

        if (StringUtils.isNotEmpty(path) && path.startsWith(".")) {
            // Relative file path is given
            File currentDirectory = new File(new File(".")
                    .getAbsolutePath());
            try {
                path = currentDirectory.getCanonicalPath() + File.separator + path;
            } catch (IOException e) {
                log.error("Error occured while retrieving current directory path");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("File path for TrustStore : " + path);
        }
        return path;
    }

    /**
     * Get property value by key
     *
     * @param key Property key
     * @return Property value
     */
    private static String getPropertyValue(String key) throws IOException {

        if (properties == null) {
            properties = new Properties();
            String configFilePath = buildFilePath(OAuthConstants.CONFIG_RELATIVE_PATH);
            File configFile = new File(configFilePath);
            InputStream inputStream = new FileInputStream(configFile);
            properties.load(inputStream);
        }
        return properties.getProperty(key);
    }

    private static String getAliasForX509CertThumb(byte[] thumb, KeyStore keyStore) throws RequestObjectException {

        Certificate cert;
        MessageDigest sha;
        String alias = null;
        try {
            sha = MessageDigest.getInstance("SHA-1");
            for (Enumeration e = keyStore.aliases(); e.hasMoreElements(); ) {
                alias = (String) e.nextElement();
                Certificate[] certs = keyStore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    cert = keyStore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                } else {
                    cert = certs[0];
                }
                sha.update(cert.getEncoded());
                byte[] data = sha.digest();
                if (new String(thumb).equals(hexify(data))) {
                    return alias;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Failed to extract alias" +
                    " from the cert thumb.");
        }
        return alias;
    }

    private static String hexify(byte bytes[]) {

        char[] hexDigits =
                {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }
}

