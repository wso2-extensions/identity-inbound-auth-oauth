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

package org.wso2.carbon.identity.oauth2.dao;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for ScopeMgtDAO.
 */

@PrepareForTest(IdentityDatabaseUtil.class)
public class ScopeMgtDAOTest extends IdentityBaseTest {

    private static final int SAMPLE_TENANT_ID = 1;

    private static final String DB_NAME = "SCOPE_DB";

    @BeforeClass
    public void initTest() throws Exception {
        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("scope.sql"));
    }

    @DataProvider(name = "addScopeDataProvider")
    public Object[][] addScopeData() {

        return new Object[][]{
                {
                        new Scope("scope1", "scope1"),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope2", "scope2", Arrays.asList("sampleBinding1", "sampleBinding2")),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope1", "scope1"),
                        SAMPLE_TENANT_ID
                },
                {
                        new Scope("scope2", "scope2", Arrays.asList("sampleBinding1", "sampleBinding2")),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "addScopeDataProvider")
    public void addScope(Object scope, int tenantId) throws IdentityOAuth2ScopeException, SQLException {
        try (Connection connection1 = DAOUtils.getConnection(DB_NAME);
             Connection connection2 = DAOUtils.getConnection(DB_NAME);
             Connection connection3 = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            scopeMgtDAO.addScope((Scope) scope, tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);
            assertNotNull(scopeMgtDAO.getScopeByName(((Scope) scope).getName(), tenantId), "Failed to persist scope.");

            // Clean after test
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);
            scopeMgtDAO.deleteScopeByName(((Scope) scope).getName(), tenantId);
        }
    }

    @DataProvider(name = "getAllScopesDataProvider")
    public Object[][] getAllScopesData() {

        return new Object[][]{
                {
                        Arrays.asList(
                                new Scope("scope3", "scope3"),
                                new Scope("scope4", "scope4", Arrays.asList("sampleBinding3", "sampleBinding4"))
                        ),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        Arrays.asList(
                                new Scope("scope5", "scope5"),
                                new Scope("scope6", "scope6", Arrays.asList("sampleBinding3", "sampleBinding4"))
                        ),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "getAllScopesDataProvider")
    public void getAllScopes(List<Object> scopes, int tenantId) throws SQLException,
            IdentityOAuth2ScopeException {
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            assertTrue(scopes != null && !scopes.isEmpty(), "Failed to retrieve scopes.");

            addScopes(scopeMgtDAO, scopes, tenantId);

            // Clean after test
            deleteScopes(scopeMgtDAO, scopes, tenantId);
        }
    }

    @DataProvider(name = "getScopesWithPaginationDataProvider")
    public Object[][] getScopesWithPaginationData() {

        return new Object[][]{
                {
                        Arrays.asList(
                                new Scope("scope7", "scope7"),
                                new Scope("scope8", "scope8", Arrays.asList("sampleBinding5", "sampleBinding6")),
                                new Scope("scope9", "scope9", Arrays.asList("sampleBinding7", "sampleBinding8"))
                        ),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        Arrays.asList(
                                new Scope("scope10", "scope10"),
                                new Scope("scope11", "scope11", Arrays.asList("sampleBinding5", "sampleBinding6")),
                                new Scope("scope12", "scope12", Arrays.asList("sampleBinding7", "sampleBinding8"))
                        ),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "getScopesWithPaginationDataProvider")
    public void getScopesWithPagination(List<Object> scopes, int tenantId) throws
            SQLException, IdentityOAuth2ScopeException {
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            addScopes(scopeMgtDAO, scopes, tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<Scope> scopesList = scopeMgtDAO.getScopesWithPagination(1, 2, tenantId);
            assertTrue(scopesList != null && scopesList.size() == 2, "Failed to retrieve scopes with pagination.");

            // Clean after test
            deleteScopes(scopeMgtDAO, scopes, tenantId);
        }
    }

    @DataProvider(name = "getScopeByNameDataProvider")
    public Object[][] getScopeByNameData() {

        return new Object[][]{
                {
                        new Scope("scope13", "scope13"),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope14", "scope14"),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "getScopeByNameDataProvider")
    public void getScopeByName(Object scope, int tenantId) throws IdentityOAuth2ScopeException, SQLException {
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            addScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            assertNotNull(scopeMgtDAO.getScopeByName(((Scope) scope).getName(), tenantId), "Failed to retrieve by " +
                    "scope name.");

            // Clean after test
            deleteScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);
        }
    }

    @DataProvider(name = "isScopeExistsDataProvider")
    public Object[][] isScopeExistsData() {

        return new Object[][]{
                {
                        new Scope("scope15", "scope15"),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope16", "scope16"),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "isScopeExistsDataProvider")
    public void isScopeExists(Object scope, int tenantId) throws IdentityOAuth2ScopeException, SQLException {
        try (Connection connection1 = DAOUtils.getConnection(DB_NAME);
             Connection connection2 = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            addScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            assertTrue(scopeMgtDAO.isScopeExists(((Scope) scope).getName(), tenantId), "Failed to check existence " +
                    "by scope name.");
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);
            assertFalse(scopeMgtDAO.isScopeExists("invalidScopeName", tenantId), "Failed to check existence " +
                    "by scope name.");

            // Clean after test
            deleteScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);
        }
    }

    @DataProvider(name = "getScopeIDByNameDataProvider")
    public Object[][] getScopeIDByNameData() {

        return new Object[][]{
                {
                        new Scope("scope17", "scope17"),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope18", "scope18"),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "getScopeIDByNameDataProvider")
    public void getScopeIDByName(Object scope, int tenantId) throws IdentityOAuth2ScopeException, SQLException {
        try (Connection connection1 = DAOUtils.getConnection(DB_NAME);
             Connection connection2 = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            addScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            assertTrue(scopeMgtDAO.getScopeIDByName(((Scope) scope).getName(), tenantId) != Oauth2ScopeConstants
                    .INVALID_SCOPE_ID, "Failed to retrieve the scope id.");
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);
            assertTrue(scopeMgtDAO.getScopeIDByName("invalidScopeName", tenantId) == Oauth2ScopeConstants
                    .INVALID_SCOPE_ID, "Failed to retrieve the scope id.");
            // Clean after test
            deleteScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);
        }
    }

    @DataProvider(name = "deleteScopeByNameDataProvider")
    public Object[][] deleteScopeByNameData() {

        return new Object[][]{
                {
                        new Scope("scope19", "scope19"),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope20", "scope20"),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "deleteScopeByNameDataProvider")
    public void deleteScopeByName(Object scope, int tenantId) throws IdentityOAuth2ScopeException, SQLException {
        try (Connection connection1 = DAOUtils.getConnection(DB_NAME);
             Connection connection2 = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            addScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            scopeMgtDAO.deleteScopeByName(((Scope) scope).getName(), tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);
            assertNull(scopeMgtDAO.getScopeByName(((Scope) scope).getName(), tenantId), "Failed to delete the scope" +
                    " by name.");
        }
    }

    @DataProvider(name = "updateScopeByNameDataProvider")
    public Object[][] updateScopeByNameData() {

        return new Object[][]{
                {
                        new Scope("scope21", "scope21"),
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        new Scope("scope22", "scope22"),
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "updateScopeByNameDataProvider")
    public void updateScopeByName(Object scope, int tenantId) throws IdentityOAuth2ScopeException, SQLException {
        try (Connection connection1 = DAOUtils.getConnection(DB_NAME);
             Connection connection2 = DAOUtils.getConnection(DB_NAME)) {

            mockStatic(IdentityDatabaseUtil.class);
            ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

            addScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);

            Scope updatedScope = (Scope) scope;
            updatedScope.setName("updateScopeName");

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            scopeMgtDAO.updateScopeByName(updatedScope, tenantId);

            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);
            assertNotNull(scopeMgtDAO.getScopeByName(updatedScope.getName(), tenantId), "Failed to u[date scope.");
            // Clean after test
            deleteScopes(scopeMgtDAO, Collections.singletonList(scope), tenantId);
        }
    }

    private void addScopes(ScopeMgtDAO scopeMgtDAO, List<Object> scopes, int tenantId) throws SQLException,
            IdentityOAuth2ScopeException {
        for (Object scope : scopes) {
            try (Connection connection1 = DAOUtils.getConnection(DB_NAME)) {
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
                scopeMgtDAO.addScope((Scope) scope, tenantId);
            }
        }
    }

    private void deleteScopes(ScopeMgtDAO scopeMgtDAO, List<Object> scopes, int tenantId) throws SQLException,
            IdentityOAuth2ScopeException {
        for (Object scope : scopes) {
            try (Connection connection1 = DAOUtils.getConnection(DB_NAME)) {
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
                scopeMgtDAO.deleteScopeByName(((Scope) scope).getName(), tenantId);
            }
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
