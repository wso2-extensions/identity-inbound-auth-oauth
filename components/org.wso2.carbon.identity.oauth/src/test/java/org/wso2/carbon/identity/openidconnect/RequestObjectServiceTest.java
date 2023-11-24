/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.TestUtil;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectDAOImpl;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.user.api.UserStoreException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@WithCarbonHome
@WithRealmService(tenantId = TestConstants.TENANT_ID, tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true, injectToSingletons = {IdentityCoreServiceDataHolder.class})
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
public class RequestObjectServiceTest extends PowerMockTestCase {

    private static final String consumerKey = TestConstants.CLIENT_ID;
    private static final String sessionKey = "d43e8da324a33bdc941b9b95cad6a6a2";
    private static final String token = "4bdc941b93e8da324dc941b93ea2d";
    private static final String tokenId = "2sa9a678f890877856y66e75f605d457";
    private static final String invalidTokenId = "77856y6690875f605d456e2sa9a678f8";
    RequestedClaim requestedClaimForEmail = new RequestedClaim();
    RequestedClaim requestedClaimForAddress = new RequestedClaim();

    private RequestObjectService requestObjectService;
    private List<List<RequestedClaim>> requestedEssentialClaims;

    @BeforeClass
    public void setUp() throws UserStoreException {

        requestObjectService = new RequestObjectService();
        requestedEssentialClaims = new ArrayList<>();
        List lstRequestedClams = new ArrayList<>();
        List values = new ArrayList<>();
        requestedEssentialClaims = new ArrayList<>();

        requestedClaimForEmail.setName("email");
        requestedClaimForEmail.setType("userinfo");
        requestedClaimForEmail.setValue("value1");
        requestedClaimForEmail.setEssential(true);
        requestedClaimForEmail.setValues(values);
        values.add("val1");
        values.add("val2");
        requestedClaimForAddress.setName("address");
        requestedClaimForAddress.setType("id_token");
        requestedClaimForAddress.setValue("value1");
        requestedClaimForAddress.setEssential(true);
        requestedClaimForAddress.setValues(values);
        lstRequestedClams.add(requestedClaimForEmail);
        lstRequestedClams.add(requestedClaimForAddress);
        requestedEssentialClaims.add(lstRequestedClams);

        TestUtil.mockRealmInIdentityTenantUtil(TestConstants.TENANT_ID, TestConstants.TENANT_DOMAIN);
    }

    @Test
    public void testAddRequestObject() throws Exception {

        requestObjectService.addRequestObject(consumerKey, sessionKey, requestedEssentialClaims);
        List<RequestedClaim> claims = requestObjectService.
                getRequestedClaimsForSessionDataKey(sessionKey, true);
        Assert.assertEquals(claims.get(0).getName(), "email");
    }

    @Test
    public void testGetRequestedClaimsForUserInfo() throws Exception {

        RequestObjectDAOImpl requestObjectDAO = new RequestObjectDAOImpl();
        requestObjectService.addRequestObject(consumerKey, sessionKey, requestedEssentialClaims);
        addToken(token, tokenId);
        requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionKey, tokenId);
        List<RequestedClaim> claims = requestObjectService.getRequestedClaimsForUserInfo(token);
        Assert.assertEquals(claims.get(0).getName(), "email");
    }

    @Test(expectedExceptions = {IdentityOAuth2Exception.class})
    public void testGetRequestedClaimsForUserInfoException() throws Exception {

        RequestObjectDAOImpl requestObjectDAO = new RequestObjectDAOImpl();
        requestObjectService.addRequestObject(consumerKey, sessionKey, requestedEssentialClaims);
        requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionKey, invalidTokenId);
        addToken(token, tokenId);
        List<RequestedClaim> claims = requestObjectService.getRequestedClaimsForUserInfo(token);
        Assert.assertEquals(claims.get(0).getName(), "email");
    }

    @Test
    public void testGetRequestedClaimsForIDToken() throws Exception {

        RequestObjectDAOImpl requestObjectDAO = new RequestObjectDAOImpl();
        addToken(token, tokenId);
        requestObjectService.addRequestObject(consumerKey, sessionKey, requestedEssentialClaims);
        requestObjectDAO.updateRequestObjectReferencebyTokenId(sessionKey, tokenId);
        List<RequestedClaim> claims = requestObjectService.getRequestedClaimsForIDToken(token);
        Assert.assertEquals(claims.get(0).getName(), "address");
    }

    protected void addToken(String token, String tokenId) throws Exception {

        // TODO this is not good :(
        TokenPersistenceProcessor hashingPersistenceProcessor = new HashingPersistenceProcessor();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN;
            PreparedStatement prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(token));
            prepStmt.setString(2, "refreshToken");
            prepStmt.setString(3, "userid");
            prepStmt.setInt(4, 1234);
            prepStmt.setString(5, "PRIMARY");
            prepStmt.setString(6, null);
            prepStmt.setString(7, null);
            prepStmt.setLong(8, 36000);
            prepStmt.setLong(9, 36000);
            prepStmt.setString(10, "scope");
            prepStmt.setString(11, "ACTIVE");
            prepStmt.setString(12, "TOKEN");
            prepStmt.setString(13, tokenId);
            prepStmt.setString(14, null);
            prepStmt.setString(15, "TOKEN_ID");
            prepStmt.setString(16, hashingPersistenceProcessor.getProcessedAccessTokenIdentifier(token));
            prepStmt.setString(17, "refreshToken");
            prepStmt.setString(18, null);
            prepStmt.setString(19, "NONE");
            prepStmt.setString(20, consumerKey);
            prepStmt.setInt(21, TestConstants.TENANT_ID);
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            String errorMsg = "Error occurred while inserting tokenID: " + tokenId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }
}
