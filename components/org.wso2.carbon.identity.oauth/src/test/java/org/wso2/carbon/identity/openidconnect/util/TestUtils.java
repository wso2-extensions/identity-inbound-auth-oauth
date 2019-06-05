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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.openidconnect.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.testng.Assert;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TestUtils {

    public static final String DB_NAME = "jdbc/WSO2CarbonDB";
    public static final String H2_SCRIPT_NAME = "scope_claim.sql";
    public static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    public static void initiateH2Base() throws SQLException {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + DB_NAME);
        Connection connection = dataSource.getConnection();
        connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT_NAME) + "'");

        dataSourceMap.put(DB_NAME, dataSource);
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts",
                    fileName).toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    public static Connection getConnection() throws SQLException {

        if (dataSourceMap.get(DB_NAME) != null) {
            return dataSourceMap.get(DB_NAME).getConnection();
        }
        throw new RuntimeException("No data source initiated for database: " + DB_NAME);
    }

    /**
     * Return a JWT string with provided info, and default time
     *
     * @param issuer
     * @param subject
     * @param jti
     * @param audience
     * @param algorythm
     * @param privateKey
     * @param notBeforeMillis
     * @return
     * @throws org.wso2.carbon.identity.oauth2.RequestObjectException
     */
    public static String buildJWT(String issuer, String subject, String jti, String audience, String algorythm,
                                  Key privateKey, long notBeforeMillis, Map<String,Object> claims)
            throws RequestObjectException {
        long lifetimeInMillis = 3600 * 1000;
        return buildJWTWithExpiry(issuer, subject, jti, audience, algorythm, privateKey,notBeforeMillis, claims,
                lifetimeInMillis);
    }

    /**
     * Return a JWT string with provided info, and default time
     *
     * @param issuer
     * @param subject
     * @param jti
     * @param audience
     * @param algorythm
     * @param privateKey
     * @param notBeforeMillis
     * @return
     * @throws org.wso2.carbon.identity.oauth2.RequestObjectException
     */
    public static String buildJWTWithExpiry(String issuer, String subject, String jti, String audience, String
            algorythm, Key privateKey, long notBeforeMillis, Map<String,Object> claims, long lifetimeInMillis)
            throws RequestObjectException {

        JWTClaimsSet jwtClaimsSet = getJwtClaimsSet(issuer, subject, jti, audience, notBeforeMillis, claims,
                lifetimeInMillis);
        if (JWSAlgorithm.NONE.getName().equals(algorythm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    private static JWTClaimsSet getJwtClaimsSet(String issuer, String subject, String jti, String audience, long
            notBeforeMillis, Map<String, Object> claims, long lifetimeInMillis) {

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        jwtClaimsSetBuilder.audience(Arrays.asList(audience));
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date((curTimeInMillis + lifetimeInMillis)));
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis + notBeforeMillis));
        }
        if (claims != null && !claims.isEmpty()) {
            for (Map.Entry entry : claims.entrySet()) {
                jwtClaimsSetBuilder.claim(entry.getKey().toString(), entry.getValue());
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    public static String buildJWT(String issuer, String subject, String jti, String audience, String algorythm,
                                  Key privateKey, long notBeforeMillis, long lifetimeInMillis, long issuedTime)
            throws RequestObjectException {

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        if (issuedTime < 0) {
            issuedTime = curTimeInMillis;
        }
        if (lifetimeInMillis <= 0) {
            lifetimeInMillis = 3600 * 1000;
        }
        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        jwtClaimsSetBuilder.audience(Arrays.asList(audience));
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date(issuedTime + lifetimeInMillis));
        jwtClaimsSetBuilder.issueTime(new Date(issuedTime));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(issuedTime + notBeforeMillis));
        }
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(algorythm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    /**
     * sign JWT token from RSA algorithm
     *
     * @param jwtClaimsSet contains JWT body
     * @param privateKey
     * @return signed JWT token
     * @throws RequestObjectException
     */
    public static String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, Key privateKey)
            throws RequestObjectException {
        SignedJWT signedJWT = getSignedJWT(jwtClaimsSet, (RSAPrivateKey) privateKey);
        return signedJWT.serialize();
    }

    private static SignedJWT getSignedJWT(JWTClaimsSet jwtClaimsSet, RSAPrivateKey privateKey) throws RequestObjectException {
        try {
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
        signedJWT.sign(signer);
        return signedJWT;
        } catch (JOSEException e) {
            throw new RequestObjectException("error_signing_jwt","Error occurred while signing JWT.");
        }
    }

    /**
     * Create a auth-app in the given tenant with given consumerKey and consumerSecreat
     *
     * @param consumerKey
     * @param consumerSecret
     * @param tenantId
     */
    public static void createApplication(String consumerKey, String consumerSecret, int tenantId) {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)) {
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, "testUser");
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            prepStmt.setString(6, "oauth2-app");
            prepStmt.setString(7, "OAuth-2.0");
            prepStmt.setString(8, "some-call-back");
            prepStmt.setString(9, "refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password " +
                    "client_credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:jwt-bearer");
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            Assert.fail("Unable to add Oauth application.");
        }
    }

    /**
     * Read Keystore from the file identified by given keystorename, password
     *
     * @param keystoreName
     * @param password
     * @param home
     * @return
     * @throws Exception
     */
    public static KeyStore getKeyStoreFromFile(String keystoreName, String password,
                                               String home) throws Exception {
        Path tenantKeystorePath = Paths.get(home, "repository",
                "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }


    public static String buildJWE(String issuer, String subject, String jti, String audience, String algorythm,
                                  Key privateKey,Key publicKey, long notBeforeMillis, Map<String,
            Object> claims) throws RequestObjectException {
        long lifetimeInMillis = 3600 * 1000;
        JWTClaimsSet jwtClaimsSet = getJwtClaimsSet(issuer, subject, jti, audience, notBeforeMillis, claims,
                lifetimeInMillis);

        if (JWSAlgorithm.NONE.getName().equals(algorythm)) {
            return getEncryptedJWT((RSAPublicKey) publicKey, jwtClaimsSet);
        } else {
            return getSignedAndEncryptedJWT(publicKey, (RSAPrivateKey) privateKey, jwtClaimsSet);
        }
    }

    private static String getSignedAndEncryptedJWT(Key publicKey, RSAPrivateKey privateKey, JWTClaimsSet jwtClaimsSet) throws RequestObjectException {
        SignedJWT signedJWT = getSignedJWT(jwtClaimsSet, privateKey);
        // Create JWE object with signed JWT as payload
        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(signedJWT.serialize()));
        // Perform encryption
        try {
            jweObject.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));
            return jweObject.serialize();
        } catch (JOSEException e) {
            throw new RequestObjectException("error_building_jwd","Error occurred while creating JWE.");
        }
    }

    private static String getEncryptedJWT(RSAPublicKey publicKey, JWTClaimsSet jwtClaimsSet) throws
            RequestObjectException {
        // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaimsSet);

        try {
        // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(publicKey);
            // Do the actual encryption
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RequestObjectException("error_building_jwd","Error occurred while creating JWE JWT.");

        }
        return jwt.serialize();
    }

    public static Object[][] getRequestObjects(Key privateKey, Key privateKey2 , PublicKey publicKey, String
            testClientId, String audience) throws
            Exception {

        Map<String,Object> claims1 = new HashMap<>();
        Map<String,Object> claims2 = new HashMap<>();
        Map<String,Object> claims3 = new HashMap<>();
        Map<String,Object> claims4 = new HashMap<>();

        claims1.put(Constants.STATE, "af0ifjsldkj");
        claims1.put(Constants.CLIENT_ID, testClientId);

        JSONObject userInfoClaims = new JSONObject();
        userInfoClaims.put("essential", true);
        userInfoClaims.put("value", "some-value");
        JSONArray valuesArray = new JSONArray();
        valuesArray.add("value1");
        valuesArray.add("value2");
        userInfoClaims.put("values", valuesArray);
        JSONObject userInfoClaim = new JSONObject();
        userInfoClaim.put("user_info", userInfoClaims);
        JSONObject acr = new JSONObject();
        acr.put("acr", userInfoClaim);
        claims2.put("claims", acr);

        claims3.put(Constants.CLIENT_ID, "some-string");

        JSONObject givenName = new JSONObject();
        givenName.put("given_name", null);

        JSONObject idTokenClaim = new JSONObject();
        idTokenClaim.put("id_token", givenName);
        claims4.put("claims", idTokenClaim);

        String jsonWebToken1 = buildJWT(testClientId, testClientId, "1000", audience, "RSA265", privateKey, 0,
                claims1);
        String jsonWebToken2 = buildJWT(testClientId, testClientId, "1001", audience, "none", privateKey, 0,
                claims1);
        String jsonWebToken3 = buildJWT(testClientId, testClientId, "1002", audience, "RSA265", privateKey, 0,
                claims2);
        String jsonWebToken4 = buildJWT(testClientId, testClientId, "1003", audience, "none", privateKey, 0,
                claims2);
        String jsonWebToken5 = buildJWT(testClientId, testClientId, "1004", audience, "none", privateKey, 0,
                claims3);
        String jsonWebToken6 = buildJWT(testClientId, testClientId, "1005", audience, "RSA265", privateKey2, 0,
                claims2);
        String jsonWebToken7 = buildJWT(testClientId, testClientId, "1000", audience, "RSA265", privateKey, 0,
                claims4);
        String jsonWebEncryption1 = buildJWE(testClientId, testClientId, "2000", audience,
                JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims1);
        String jsonWebEncryption2 = buildJWE(testClientId, testClientId, "2001", audience,
                JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims1);
        return new Object[][]{
                {jsonWebToken1, claims1, true, false, true, "Valid Request Object, signed, not encrypted."},
                {jsonWebToken2, claims1, false, false, true, "Valid Request Object, not signed, not encrypted."},
                {jsonWebToken3, claims2, true, false, true, "Valid Request Object, signed, not encrypted."},
                {jsonWebToken4, claims2, false, false, true, "Valid Request Object, not signed, not encrypted."},
                {jsonWebToken5, claims3, false, false, false, "Invalid Request Object, not signed, not encrypted, " +
                        "mismatching client_id."},
                {jsonWebToken6, claims2, true, false, false, "Invalid Request Object, signed but with different key, " +
                        "not encrypted."},
                {jsonWebToken7, claims4, true, false, true, "Valid Request Object, signed, not encrypted."},
                {"some-request-object", null, false, false, false, "Invalid Request Object string, " +
                        "signed not encrypted."},
                {"", null, false, false, false, "Invalid Request Object, signed not encrypted."},
                {jsonWebEncryption1, claims1, false, true, true, "Valid Request Object, signed and encrypted."},
                {jsonWebEncryption2, claims1, true, true, true, "Valid Request Object, signed and encrypted."}
        };
    }
}
