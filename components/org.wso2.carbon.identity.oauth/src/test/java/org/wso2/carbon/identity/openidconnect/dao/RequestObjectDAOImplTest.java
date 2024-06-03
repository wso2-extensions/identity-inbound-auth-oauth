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
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.TestUtil;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAOImpl;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class contains unit tests for RequestObjectDAOImplTest..
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql",
                "dbScripts/insert_local_idp.sql"})
@WithRealmService(tenantId = TestConstants.TENANT_ID, tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true, injectToSingletons = {IdentityCoreServiceDataHolder.class})
public class RequestObjectDAOImplTest {

    private static final Log log = LogFactory.getLog(AuthorizationCodeDAOImpl.class);
    private final String consumerKey = "ca19a540f544777860e44e75f605d927";
    private final String sessionDataKey = "d43e8da324a33bdc941b9b95cad6a6a2";
    private final String tokenId = "2sa9a678f890877856y66e75f605d456";
    private final String newToken = "a8f78c8420cb48ad91cbac72691d4597";
    private final String codeId = "a5eb9b95ca8ea324a63bdc911d6a6a2";
    private final String consumerId = "1";

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
        insertCodeId(codeId, 1);
        requestObjectDAO.updateRequestObjectReferencebyCodeId(sessionDataKey, codeId);
        Assert.assertEquals(codeId, getData(sessionDataKey).codeId);
    }

    @Test (dependsOnMethods = {"testUpdateRequestObjectReferenceByCodeId"})
    public void testDeleteRequestObjectReferenceByCode() throws Exception {

        requestObjectDAO.deleteRequestObjectReferenceByCode(codeId);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String query = "SELECT * FROM IDN_OIDC_REQ_OBJECT_REFERENCE WHERE CODE_ID=?";
            PreparedStatement statement = connection.prepareStatement(query);
            statement.setString(1, codeId);
            ResultSet resultSet = statement.executeQuery();
            int resultSize = 0;
            if (resultSet.next()) {
                resultSize = resultSet.getRow();
            }
            Assert.assertEquals(0, resultSize);
        }
    }

    @Test
    public void testUpdateRequestObjectReferenceCodeToToken() throws Exception {

        requestObjectDAO.insertRequestObjectData(consumerKey, sessionDataKey,
                requestedEssentialClaims);
        insertCodeId(codeId, 1);
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

    private void insertCodeId(String codeId, int consumerKeyId) throws Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = "INSERT INTO IDN_OAUTH2_AUTHORIZATION_CODE (CODE_ID, CONSUMER_KEY_ID) VALUES (?,?)";
            PreparedStatement ps = connection.prepareStatement(sql);
            ps.setString(1, codeId);
            ps.setInt(2, consumerKeyId);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            log.error("Error when inserting codeID object.", e);
            throw new IdentityOAuth2Exception("Error when inserting codeID", e);
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
                result = new Result(resultSet.getString(1), resultSet.getString(2), resultSet.getString(3));
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
        private String consumerId;
        private String codeId;
        private String tokenId;

        Result(String consumerId, String codeId, String tokenId) {
            this.consumerId = consumerId;
            this.codeId = codeId;
            this.tokenId = tokenId;
        }
    }
}
