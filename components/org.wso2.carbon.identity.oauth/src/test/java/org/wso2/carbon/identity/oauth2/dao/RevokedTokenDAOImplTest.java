/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.dao;

import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Date;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for RevokedTokenDAOImpl.
 */
@WithCarbonHome
@Listeners(MockitoTestNGListener.class)
public class RevokedTokenDAOImplTest {

    private static final String DB_NAME = "RevokedTokenDB";
    private static final String H2_SCRIPT_NAME = "identity.sql";
    private static final String TEST_CONSUMER_KEY = "test_consumer_key";
    private static final String TEST_TOKEN = "test_token_identifier";
    private static final String TEST_ENTITY_ID = "test_entity_id";
    private static final String TEST_ENTITY_TYPE = "USER_ID";
    private static final int TEST_TENANT_ID = -1234;

    private RevokedTokenDAOImpl revokedTokenDAO;
    private Connection connection = null;

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeClass
    public void initTest() throws Exception {

        try {
            DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath(H2_SCRIPT_NAME));
        } catch (Exception e) {
            throw new IdentityOAuth2Exception("Error while initializing the data source", e);
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);

        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        oAuth2Util = mockStatic(OAuth2Util.class);
        identityUtil = mockStatic(IdentityUtil.class);

        // Configure OAuth2Util to enable revoked token persistence
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(false);
        oAuth2Util.when(OAuth2Util::isKeepRevokedAccessTokenEnabled).thenReturn(true);

        revokedTokenDAO = new RevokedTokenDAOImpl();
    }

    @AfterMethod(alwaysRun = true)
    public void closeup() throws Exception {

        if (connection != null) {
            connection.close();
        }

        closeMockSafely(identityDatabaseUtil);
        closeMockSafely(oAuth2Util);
        closeMockSafely(identityUtil);
    }

    private void closeMockSafely(MockedStatic<?> mock) {

        if (mock != null) {
            try {
                mock.close();
            } catch (Exception e) {
                // Ignore if already closed.
            }
        }
    }

    @AfterClass
    public void tearDown() throws Exception {

        DAOUtils.closeDataSource(DB_NAME);
    }

    // ======================== Tests for isRevokedToken ========================

    @Test
    public void testIsRevokedToken_WhenTokenNotRevoked() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        boolean result = revokedTokenDAO.isRevokedToken("non_existent_token", TEST_CONSUMER_KEY);
        assertFalse(result, "Token should not be marked as revoked when it doesn't exist in the database.");
    }

    @Test
    public void testIsRevokedToken_WhenTokenIsRevoked() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);

        // First add a revoked token
        long expiryTime = System.currentTimeMillis() + 3600000; // 1 hour from now
        revokedTokenDAO.addRevokedToken(TEST_TOKEN, TEST_CONSUMER_KEY, expiryTime);

        // Get a fresh connection for the read operation
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        // Now check if the token is revoked
        boolean result = revokedTokenDAO.isRevokedToken(TEST_TOKEN, TEST_CONSUMER_KEY);
        assertTrue(result, "Token should be marked as revoked after adding it to the revoked tokens table.");
    }

    @Test
    public void testIsRevokedToken_WhenDisabled() throws Exception {

        // Configure to disable revoked token persistence
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);
        oAuth2Util.when(OAuth2Util::isKeepRevokedAccessTokenEnabled).thenReturn(false);

        boolean result = revokedTokenDAO.isRevokedToken(TEST_TOKEN, TEST_CONSUMER_KEY);
        assertFalse(result, "Should return false when revoked token persistence is disabled.");
    }

    @Test
    public void testIsRevokedToken_SQLException() throws Exception {

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("Database connection error"));

        assertThrows(IdentityOAuth2Exception.class, () ->
                revokedTokenDAO.isRevokedToken(TEST_TOKEN, TEST_CONSUMER_KEY));
    }

    // ======================== Tests for addRevokedToken ========================

    @Test
    public void testAddRevokedToken_Success() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);

        String uniqueToken = "unique_token_" + System.currentTimeMillis();
        long expiryTime = System.currentTimeMillis() + 3600000;

        // This should not throw any exception
        revokedTokenDAO.addRevokedToken(uniqueToken, TEST_CONSUMER_KEY, expiryTime);

        // Verify by checking if the token is revoked
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        boolean result = revokedTokenDAO.isRevokedToken(uniqueToken, TEST_CONSUMER_KEY);
        assertTrue(result, "Token should be present in the revoked tokens table after adding.");
    }

    @Test
    public void testAddRevokedToken_WhenDisabled() throws Exception {

        // Configure to disable revoked token persistence
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);
        oAuth2Util.when(OAuth2Util::isKeepRevokedAccessTokenEnabled).thenReturn(false);

        // This should not throw any exception and should return early
        revokedTokenDAO.addRevokedToken(TEST_TOKEN, TEST_CONSUMER_KEY, System.currentTimeMillis());
    }

    @Test
    public void testAddRevokedToken_SQLException() throws Exception {

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("Database error"));
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(mockConnection))
                .then(invocation -> null);

        assertThrows(IdentityOAuth2Exception.class, () ->
                revokedTokenDAO.addRevokedToken(TEST_TOKEN, TEST_CONSUMER_KEY, System.currentTimeMillis()));
    }

    // ======================== Tests for isTokenRevokedForSubjectEntity ========================

    @Test
    public void testIsTokenRevokedForSubjectEntity_WhenNotRevoked() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        Date tokenIssuedTime = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity("non_existent_entity", tokenIssuedTime);
        assertFalse(result, "Should return false when no revocation event exists for the entity.");
    }

    @Test
    public void testIsTokenRevokedForSubjectEntity_WhenRevoked() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);

        String uniqueEntityId = "entity_" + System.currentTimeMillis();
        long revocationTime = System.currentTimeMillis();

        // First add a revocation event
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, revocationTime,
                TEST_TENANT_ID);

        // Get a fresh connection for the read operation
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        // Check with a token issued before the revocation
        Date tokenIssuedBeforeRevocation = new Date(revocationTime - 1000);
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity(uniqueEntityId, tokenIssuedBeforeRevocation);
        assertTrue(result, "Token should be marked as revoked when issued before the revocation event.");
    }

    @Test
    public void testIsTokenRevokedForSubjectEntity_WhenTokenIssuedAfterRevocation() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);

        String uniqueEntityId = "entity_after_" + System.currentTimeMillis();
        long revocationTime = System.currentTimeMillis() - 10000; // 10 seconds ago

        // First add a revocation event
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, revocationTime,
                TEST_TENANT_ID);

        // Get a fresh connection for the read operation
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        // Check with a token issued after the revocation
        Date tokenIssuedAfterRevocation = new Date(System.currentTimeMillis());
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity(uniqueEntityId, tokenIssuedAfterRevocation);
        assertFalse(result, "Token should not be marked as revoked when issued after the revocation event.");
    }

    @Test
    public void testIsTokenRevokedForSubjectEntity_WhenDisabled() throws Exception {

        // Configure to disable revoked token persistence
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);
        oAuth2Util.when(OAuth2Util::isKeepRevokedAccessTokenEnabled).thenReturn(false);

        Date tokenIssuedTime = new Date(System.currentTimeMillis());
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity(TEST_ENTITY_ID, tokenIssuedTime);
        assertFalse(result, "Should return false when revoked token persistence is disabled.");
    }

    @Test
    public void testIsTokenRevokedForSubjectEntity_SQLException() throws Exception {

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        when(mockPrepStmt.executeQuery()).thenThrow(new SQLException("Database connection error"));

        assertThrows(IdentityOAuth2Exception.class, () ->
                revokedTokenDAO.isTokenRevokedForSubjectEntity(TEST_ENTITY_ID, new Date()));
    }

    // ======================== Tests for revokeTokensBySubjectEvent ========================

    @Test
    public void testRevokeTokensBySubjectEvent_InsertNewEvent() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(connection))
                .then(invocation -> null);

        String uniqueEntityId = "new_entity_" + System.currentTimeMillis();
        long revocationTime = System.currentTimeMillis();

        // This should insert a new event
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, revocationTime,
                TEST_TENANT_ID);

        // Verify the event was inserted
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        Date tokenIssuedBeforeRevocation = new Date(revocationTime - 1000);
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity(uniqueEntityId, tokenIssuedBeforeRevocation);
        assertTrue(result, "Revocation event should be persisted in the database.");
    }

    @Test
    public void testRevokeTokensBySubjectEvent_UpdateExistingEvent() throws Exception {

        String uniqueEntityId = "update_entity_" + System.currentTimeMillis();
        long initialRevocationTime = System.currentTimeMillis() - 10000;
        long updatedRevocationTime = System.currentTimeMillis();

        // Insert initial event
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(connection))
                .then(invocation -> null);

        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, initialRevocationTime,
                TEST_TENANT_ID);

        // Update the event with a new revocation time
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);

        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, updatedRevocationTime,
                TEST_TENANT_ID);

        // Verify the updated time is effective
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        // Token issued between initial and updated revocation should now be revoked
        Date tokenIssuedBetween = new Date(initialRevocationTime + 5000);
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity(uniqueEntityId, tokenIssuedBetween);
        assertTrue(result, "Token issued before updated revocation time should be revoked.");
    }

    @Test
    public void testRevokeTokensBySubjectEvent_WhenDisabled() throws Exception {

        // Configure to disable revoked token persistence
        oAuth2Util.when(OAuth2Util::isAccessTokenPersistenceEnabled).thenReturn(true);
        oAuth2Util.when(OAuth2Util::isKeepRevokedAccessTokenEnabled).thenReturn(false);

        // This should not throw any exception and should return early
        revokedTokenDAO.revokeTokensBySubjectEvent(TEST_ENTITY_ID, TEST_ENTITY_TYPE,
                System.currentTimeMillis(), TEST_TENANT_ID);
    }

    @Test
    public void testRevokeTokensBySubjectEvent_SQLException() throws Exception {

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPrepStmt = mock(PreparedStatement.class);

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(mockConnection);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPrepStmt);
        when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("Database error"));
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(mockConnection))
                .then(invocation -> null);

        assertThrows(IdentityOAuth2Exception.class, () ->
                revokedTokenDAO.revokeTokensBySubjectEvent(TEST_ENTITY_ID, TEST_ENTITY_TYPE,
                        System.currentTimeMillis(), TEST_TENANT_ID));
    }

    @Test
    public void testRevokeTokensBySubjectEvent_WithDifferentEntityTypes() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(connection))
                .then(invocation -> null);

        String uniqueEntityId = "multi_type_entity_" + System.currentTimeMillis();
        long revocationTime = System.currentTimeMillis();

        // Add revocation event with USER_ID type
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, "USER_ID", revocationTime,
                TEST_TENANT_ID);

        // Add revocation event with same entity ID but CLIENT_ID type
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, "CLIENT_ID", revocationTime,
                TEST_TENANT_ID);

        // Verify both events exist by checking revocation status
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(false))
                .thenReturn(connection);

        Date tokenIssuedBefore = new Date(revocationTime - 1000);
        boolean result = revokedTokenDAO.isTokenRevokedForSubjectEntity(uniqueEntityId, tokenIssuedBefore);
        assertTrue(result, "Revocation event should exist for the entity.");
    }

    @Test
    public void testRevokeTokensBySubjectEvent_WithDifferentTenants() throws Exception {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.commitTransaction(connection))
                .then(invocation -> null);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.rollbackTransaction(connection))
                .then(invocation -> null);

        String uniqueEntityId = "multi_tenant_entity_" + System.currentTimeMillis();
        long revocationTime = System.currentTimeMillis();

        // Add revocation event for tenant 1
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, revocationTime,
                1);

        // Add revocation event for tenant 2
        connection = DAOUtils.getConnection(DB_NAME);
        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(true))
                .thenReturn(connection);
        revokedTokenDAO.revokeTokensBySubjectEvent(uniqueEntityId, TEST_ENTITY_TYPE, revocationTime,
                2);

        // Both should be persisted as separate entries (different tenants)
        // This test verifies that the constraint allows same entity_id with different tenant_id
    }
}

