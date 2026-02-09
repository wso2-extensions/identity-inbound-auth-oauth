/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.openidconnect.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.internal.component.IdentityCoreServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.TestUtil;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

/**
 * This class contains unit tests for RequestObjectDAOImplTest..
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/identity.sql", "dbScripts/insert_application_and_token.sql",
                "dbScripts/insert_consumer_app.sql", "dbScripts/insert_local_idp.sql"})
@WithRealmService(tenantId = TestConstants.TENANT_ID, tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true, injectToSingletons = {IdentityCoreServiceDataHolder.class})
public class RequestObjectDAOImplTest {

    private static final Log log = LogFactory.getLog(AuthorizationCodeDAOImpl.class);
    private final String consumerKey = "ca19a540f544777860e44e75f605d927";
    private final String sessionDataKey = "d43e8da324a33bdc941b9b95cad6a6a2";
    private final String tokenId = "2sa9a678f890877856y66e75f605d456";
    private final String newToken = "a8f78c8420cb48ad91cbac72691d4597";
    private final String codeId = "a5eb9b95ca8ea324a63bdc911d6a6a2";
    private int consumerId;

    private RequestObjectDAO requestObjectDAO;
    private List<List<RequestedClaim>> requestedEssentialClaims;

    @BeforeClass
    public void setUp() throws Exception {
        requestObjectDAO = new RequestObjectDAOImpl();
        requestedEssentialClaims = new ArrayList<>();
        List lstRequestedClaims = new ArrayList<>();
        List values = new ArrayList<>();

        RequestedClaim requestedClaim = new RequestedClaim();
        requestedClaim.setName("email");
        requestedClaim.setType("userinfo");
        requestedClaim.setValue("value1");
        requestedClaim.setEssential(true);
        requestedClaim.setValues(values);
        values.add("val1");
        values.add("val2");
        requestedClaim.setValues(values);
        lstRequestedClaims.add(requestedClaim);
        requestedEssentialClaims.add(lstRequestedClaims);

        TestUtil.mockRealmInIdentityTenantUtil(TestConstants.TENANT_ID, TestConstants.TENANT_DOMAIN);
        consumerId = getConsumerId();
    }

    @AfterClass
    public void tearDown() throws Exception {
        deleteCodeId(codeId);
    }

    @Test
    public void testInsertRequestObject() throws Exception {

        requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                    requestedEssentialClaims);
        Result result = getData(sessionDataKey);
        Assert.assertEquals(consumerId, result.consumerId);
        Assert.assertEquals("email", requestObjectDAO.getRequestedClaimsbySessionDataKey(sessionDataKey,
                    true).get(0).getName());
    }

    @Test (dependsOnMethods = {"testInsertRequestObject"})
    public void testUpdateRequestObjectReferenceByToken() throws Exception {

        requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                requestedEssentialClaims);
        requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionDataKey, tokenId);
        Assert.assertEquals(tokenId, getData(sessionDataKey).tokenId);
    }

    @Test (dependsOnMethods = {"testUpdateRequestObjectReferenceByToken"})
    public void testRefreshRequestObjectReference() throws Exception {

        requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                requestedEssentialClaims);
        requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionDataKey, tokenId);
        requestObjectDAO.refreshRequestObjectReference(tokenId, newToken);
        Assert.assertEquals(newToken, getData(sessionDataKey).tokenId);
    }

    @Test (dependsOnMethods = {"testRefreshRequestObjectReference"})
    public void testDeleteRequestObjectReferenceByTokenId() throws Exception {

        requestObjectDAO.deleteRequestObjectReferenceByTokenId(newToken);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String query = "SELECT * FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE TOKEN_ID=?";
            PreparedStatement statement = connection.prepareStatement(query);
            statement.setString(1, newToken);
            ResultSet resultSet = statement.executeQuery();
            int resultSize = 0;
            if (resultSet.next()) {
                resultSize = resultSet.getRow();
            }
            Assert.assertEquals(0, resultSize);
        }
    }

    @Test (dependsOnMethods = {"testDeleteRequestObjectReferenceByTokenId"})
    public void testUpdateRequestObjectReferenceByCodeId() throws Exception {

        requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                requestedEssentialClaims);
        insertCodeId(codeId);
        requestObjectDAO.updateRequestObjectReferencebyCodeId(sessionDataKey, codeId);
        Assert.assertEquals(codeId, getData(sessionDataKey).codeId);
    }

    @Test (dependsOnMethods = {"testUpdateRequestObjectReferenceByCodeId"})
    public void testDeleteRequestObjectReferenceByCode() throws Exception {

        try {
            requestObjectDAO.deleteRequestObjectReferenceByCode(codeId);
            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
                String query = "SELECT * FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE CODE_ID=?";
                PreparedStatement statement = connection.prepareStatement(query);
                statement.setString(1, codeId);
                ResultSet resultSet = statement.executeQuery();
                int resultSize = 0;
                if (resultSet.next()) {
                    resultSize = resultSet.getFetchSize();
                }
                IdentityDatabaseUtil.commitTransaction(connection);
                Assert.assertEquals(0, resultSize);
            }
        } finally {
            deleteCodeId(codeId);
        }
    }

    @Test (dependsOnMethods = {"testDeleteRequestObjectReferenceByCode"})
    public void testUpdateRequestObjectReferenceCodeToToken() throws Exception {

        requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                requestedEssentialClaims);
        insertCodeId(codeId);
        requestObjectDAO.updateRequestObjectReferencebyCodeId(sessionDataKey, codeId);
        requestObjectDAO.updateRequestObjectReferenceCodeToToken(codeId, tokenId);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String query = "SELECT * FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE CODE_ID=? AND TOKEN_ID=?";
            PreparedStatement statement = connection.prepareStatement(query);
            statement.setString(1, codeId);
            statement.setString(2, tokenId);
            ResultSet resultSet = statement.executeQuery();
            int resultSize = 0;
            if (resultSet.next()) {
                resultSize = resultSet.getRow();
            }
            Assert.assertEquals(1, resultSize);
        }
    }

    @Test (dependsOnMethods = {"testUpdateRequestObjectReferenceCodeToToken"})
    public void testUpdateRequestObjectReferenceToTokenByCodeId() throws Exception {

        String newCodeId = "b6fc0c96db9fb425b74cdc922e7b7b3";
        String newTokenId = "c7gd1d07ec0gc536c85ded033f8c8c4";

        try {
            requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                    requestedEssentialClaims);
            insertCodeId(newCodeId);
            insertTokenId(newTokenId);
            requestObjectDAO.updateRequestObjectReferencebyCodeId(sessionDataKey, newCodeId);
            requestObjectDAO.updateRequestObjectReferenceToTokenByCodeId(newCodeId, newTokenId);

            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
                String query = "SELECT CODE_ID, TOKEN_ID FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE " +
                        "SESSION_DATA_KEY=? LIMIT 1";
                PreparedStatement statement = connection.prepareStatement(query);
                statement.setString(1, sessionDataKey);
                ResultSet resultSet = statement.executeQuery();

                if (resultSet.next()) {
                    // After updateRequestObjectReferenceToTokenByCodeId, CODE_ID should be null.
                    // and TOKEN_ID should be set.
                    Assert.assertNull("CODE_ID should be null after update",
                            resultSet.getString("CODE_ID"));
                    Assert.assertEquals("TOKEN_ID should match the new token", newTokenId,
                            resultSet.getString("TOKEN_ID"));
                } else {
                    Assert.fail("No record found for the session data key");
                }
            }
        } finally {
            deleteCodeId(newCodeId);
            deleteTokenId(newTokenId);
            requestObjectDAO.deleteRequestObjectReferenceByTokenId(newTokenId);
        }
    }

    @Test (dependsOnMethods = {"testUpdateRequestObjectReferenceToTokenByCodeId"})
    public void testUpdateRequestObjectReferenceToTokenByCodeIdWithExistingToken() throws Exception {

        String existingCodeId = "d8hf3f18ge1hd647d96fef144g9d9d5";
        String existingTokenId = "e9ig4g29hf2ie758e07gfg255h0e0e6";
        String newSessionKey = "f0jh5h30ig3jf869f18hgh366i1f1f7";

        try {
            insertTokenId(existingTokenId);
            
            // Insert first request object with token.
            requestObjectDAO.insertRequestObjectData(consumerKey, newSessionKey,
                    requestedEssentialClaims);
            requestObjectDAO.updateRequestObjectReferencebyTokenId(newSessionKey, existingTokenId);

            // Insert second request object with code.
            String secondSessionKey = "g1ki6i41jh4kg970g29ihi477j2g2g8";
            requestObjectDAO.insertRequestObjectData(consumerKey, secondSessionKey,
                    requestedEssentialClaims);
            insertCodeId(existingCodeId);
            requestObjectDAO.updateRequestObjectReferencebyCodeId(secondSessionKey, existingCodeId);

            // Update to use existing token - should delete old entry with token and update code entry.
            requestObjectDAO.updateRequestObjectReferenceToTokenByCodeId(existingCodeId, existingTokenId);

            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
                // Verify the code entry was updated with token.
                String query = "SELECT CODE_ID, TOKEN_ID FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE " +
                        "SESSION_DATA_KEY=?";
                PreparedStatement statement = connection.prepareStatement(query);
                statement.setString(1, secondSessionKey);
                ResultSet resultSet = statement.executeQuery();

                if (resultSet.next()) {
                    Assert.assertNull("CODE_ID should be null", resultSet.getString("CODE_ID"));
                    Assert.assertEquals("TOKEN_ID should be set to existing token", existingTokenId, 
                            resultSet.getString("TOKEN_ID"));
                } else {
                    Assert.fail("No record found for the second session data key");
                }

                // Verify the old entry with the same token was deleted.
                statement = connection.prepareStatement(query);
                statement.setString(1, newSessionKey);
                resultSet = statement.executeQuery();
                Assert.assertFalse("Old entry with same token should be deleted", resultSet.next());
            }
        } finally {
            deleteCodeId(existingCodeId);
            deleteTokenId(existingTokenId);
            requestObjectDAO.deleteRequestObjectReferenceByTokenId(existingTokenId);
        }
    }

    @Test(dependsOnMethods = {"testUpdateRequestObjectReferenceToTokenByCodeIdWithExistingToken"},
            expectedExceptions = IdentityOAuth2Exception.class)
    public void testUpdateRequestObjectReferenceToTokenByCodeIdWithInvalidConnection() throws Exception {

        String testCodeId = "h2jd6d42kh5lh758h29jhj588k3h3h9";
        // Use an extremely long token ID that exceeds database column limits to cause SQL error.
        // during delete operation in deleteRequestObjectReferenceforCode.
        StringBuilder longTokenId = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            longTokenId.append("a");
        }
        String testTokenId = longTokenId.toString();
        String testSessionKey = "j4lf8f64mj7nj970j41ljl700m5j5j1";

        try {
            insertCodeId(testCodeId);
            
            requestObjectDAO.insertRequestObjectData(consumerKey, testSessionKey,
                    requestedEssentialClaims);
            requestObjectDAO.updateRequestObjectReferencebyCodeId(testSessionKey, testCodeId);

            try {
                requestObjectDAO.updateRequestObjectReferenceToTokenByCodeId(testCodeId, testTokenId);
                Assert.fail("Expected IdentityOAuth2Exception to be thrown");
            } catch (IdentityOAuth2Exception e) {
                boolean isExpectedException = e.getMessage().contains("Can not delete existing entry") ||
                        e.getMessage().contains("Can not update token id");
                Assert.assertTrue("Exception should be from delete or update operation", isExpectedException);
                throw e; // Re-throw for expectedExceptions annotation.
            }
        } finally {
            try {
                deleteCodeId(testCodeId);
            } catch (Exception e) {
                // Ignore cleanup errors.
            }
        }
    }

    @Test(dependsOnMethods = {"testUpdateRequestObjectReferenceToTokenByCodeIdWithInvalidConnection"},
            expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*Can not delete existing entry for the same token id.*")
    public void testUpdateRequestObjectReferenceToTokenByCodeIdWithDeleteFailure() throws Exception {

        String testCodeId = "m6nh0h64oj9pj192j63njn922o7n7n3";
        String testTokenId = "n7oi1i75pk0qk203k74oko033p8o8o4";
        String testSessionKey = "o8pj2j86ql1rl314l85plp144q9p9p5";

        try {
            insertCodeId(testCodeId);
            insertTokenId(testTokenId);

            requestObjectDAO.insertRequestObjectData(consumerKey, testSessionKey,
                    requestedEssentialClaims);
            requestObjectDAO.updateRequestObjectReferencebyCodeId(testSessionKey, testCodeId);

            // Now mock the database connection to simulate SQLException during DELETE.
            try (MockedStatic<IdentityDatabaseUtil> mockedDbUtil = Mockito.mockStatic(IdentityDatabaseUtil.class)) {
                java.sql.Connection mockConnection = Mockito.mock(java.sql.Connection.class);
                java.sql.PreparedStatement mockPreparedStatement = Mockito.mock(java.sql.PreparedStatement.class);
                
                mockedDbUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                        .thenReturn(mockConnection);
                
                Mockito.when(mockConnection.prepareStatement(Mockito.anyString()))
                        .thenReturn(mockPreparedStatement);
                
                // Make the execute() throw SQLException to trigger IdentityOAuthAdminException.
                Mockito.doThrow(new java.sql.SQLException("Simulated DELETE failure"))
                        .when(mockPreparedStatement).execute();

                mockedDbUtil.when(() -> IdentityDatabaseUtil.closeAllConnections(
                        Mockito.any(), Mockito.any(), Mockito.any())).then(invocation -> null);
                mockedDbUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(Mockito.any()))
                        .then(invocation -> null);

                // This should trigger IdentityOAuthAdminException in deleteRequestObjectReferenceforCode.
                // which is then caught and wrapped as IdentityOAuth2Exception with the specific message.
                requestObjectDAO.updateRequestObjectReferenceToTokenByCodeId(testCodeId, testTokenId);

                Assert.fail("Expected IdentityOAuth2Exception to be thrown");
            }
        } finally {
            try {
                deleteCodeId(testCodeId);
            } catch (Exception e) {
                // Ignore.
            }
            try {
                deleteTokenId(testTokenId);
            } catch (Exception e) {
                // Ignore.
            }
        }
    }

    private int getConsumerId() throws Exception {

        PreparedStatement statement = null;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            String sql = "SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
            statement = connection.prepareStatement(sql);
            statement.setString(1, consumerKey);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                return resultSet.getInt("ID");
            }
        } finally {
            if (statement != null) {
                statement.close();
            }
        }
        return -1;
    }

    private void insertCodeId(String codeId) throws Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = SQLQueries.STORE_AUTHORIZATION_CODE;
            PreparedStatement ps = connection.prepareStatement(sql);
            ps.setString(1, codeId);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, "http://localhost:8080/redirect");
            ps.setString(4, "openid");
            ps.setString(5, "admin");
            ps.setString(6, "PRIMARY");
            ps.setInt(7, TestConstants.TENANT_ID);
            ps.setTimestamp(8, new Timestamp(System.currentTimeMillis()),
                    Calendar.getInstance(TimeZone.getTimeZone("UTC")));
            ps.setLong(9, 3600);
            ps.setString(10, "admin");
            ps.setString(11, UUID.randomUUID().toString());
            ps.setString(12, consumerKey);
            ps.setInt(13, TestConstants.TENANT_ID);

            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            log.error("Error when inserting codeID object.", e);
            throw new IdentityOAuth2Exception("Error when inserting codeID", e);
        }
    }

    private void deleteCodeId(String codeId) throws Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = "DELETE FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE CODE_ID=?";
            PreparedStatement ps = connection.prepareStatement(sql);
            ps.setString(1, codeId);
            ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            log.error("Error when deleting codeID object.", e);
            throw new IdentityOAuth2Exception("Error when inserting codeID", e);
        }
    }

    private void insertTokenId(String tokenId) throws Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN, " +
                    "CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID, USER_DOMAIN, USER_TYPE, GRANT_TYPE, " +
                    "TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, " +
                    "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, TOKEN_STATE, TOKEN_STATE_ID, " +
                    "SUBJECT_IDENTIFIER, ACCESS_TOKEN_HASH, REFRESH_TOKEN_HASH, IDP_ID, AUTHORIZED_ORGANIZATION) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)";
            PreparedStatement ps = connection.prepareStatement(sql);
            ps.setString(1, tokenId);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, UUID.randomUUID().toString());
            ps.setInt(4, consumerId);
            ps.setString(5, "admin");
            ps.setInt(6, TestConstants.TENANT_ID);
            ps.setString(7, "PRIMARY");
            ps.setString(8, "APPLICATION_USER");
            ps.setString(9, "password");
            ps.setLong(10, 3600);
            ps.setLong(11, 14400);
            ps.setString(12, "369db21a386ae433e65c0ff34d35708d"); // Fixed 32-char hash
            ps.setString(13, "ACTIVE");
            ps.setString(14, "NONE");
            ps.setString(15, "admin");
            ps.setInt(16, 1);
            ps.setString(17, "NONE");
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            log.error("Error when inserting tokenID object.", e);
            throw new IdentityOAuth2Exception("Error when inserting tokenID", e);
        }
    }

    private void deleteTokenId(String tokenId) throws Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = "DELETE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE TOKEN_ID=?";
            PreparedStatement ps = connection.prepareStatement(sql);
            ps.setString(1, tokenId);
            ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            log.error("Error when deleting tokenID object.", e);
            throw new IdentityOAuth2Exception("Error when deleting tokenID", e);
        }
    }

    private Result getData(String sessionDataKey) throws Exception {

        Result result = null;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = "SELECT CONSUMER_KEY_ID, CODE_ID, TOKEN_ID FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE " +
                    "SESSION_DATA_KEY=? LIMIT 1";

            PreparedStatement prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, sessionDataKey);
            ResultSet resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                result = new Result(resultSet.getInt(1), resultSet.getString(2), resultSet.getString(3));
            }
            return result;
        } catch (SQLException e) {
            log.error("Error when retrieving inserted request object.", e);
            throw new IdentityOAuth2Exception("Error when retrieving request object", e);
        }
    }

    /**
     * Store the output from database.
     */
   private class Result {
        private int consumerId;
        private String codeId;
        private String tokenId;

        Result(int consumerId, String codeId, String tokenId) {
            this.consumerId = consumerId;
            this.codeId = codeId;
            this.tokenId = tokenId;
        }
    }
}
