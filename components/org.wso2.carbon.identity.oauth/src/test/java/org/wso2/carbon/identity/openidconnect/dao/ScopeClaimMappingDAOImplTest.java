package org.wso2.carbon.identity.openidconnect.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.common.testng.TestConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JdbcUtils;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@WithCarbonHome
@PrepareForTest({JdbcUtils.class, JDBCPersistenceManager.class, DataSource.class, ScopeClaimMappingDAOImpl.class,
        JdbcTemplate.class})
public class ScopeClaimMappingDAOImplTest extends PowerMockTestCase {
    private static final String CLIENT_NAME = "clientname";
    private static final String DB_NAME = "testOpenid";

    protected BasicDataSource dataSource;
    private ScopeDTO scopeDTO;
    private Connection connection;
    private List scopeDTOList = new ArrayList<ScopeDTO>();
    private static final Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private ScopeClaimMappingDAO scopeClaimMappingDAO;

    @BeforeClass
    public void setUp() throws Exception {

        scopeClaimMappingDAO = PowerMockito.spy(new ScopeClaimMappingDAOImpl());
        scopeDTO = new ScopeDTO();
        String[] claims = {"admin"};
        scopeDTO.setName(CLIENT_NAME);
        scopeDTO.setClaim(claims);
        scopeDTO.setDescription("Description");
        scopeDTO.setDisplayName("DisplayName");
        scopeDTOList.add(scopeDTO);
        initiateH2Base(DB_NAME);
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }

    @Test
    public void testAddScopes() throws Exception {

        String scope = "openid";
        String[] claims = {"email"};
        JdbcTemplate jdbcTemplate = Mockito.mock(JdbcTemplate.class);
        mockDataSource();

        mockStatic(JdbcUtils.class);
        Mockito.when(JdbcUtils.getNewTemplate()).thenReturn(jdbcTemplate);
        Mockito.when(jdbcTemplate.withTransaction(any())).thenReturn(null);

        scopeClaimMappingDAO.addScope(scopeDTO, TestConstants.TENANT_ID);
        scopeClaimMappingDAO.addScope(TestConstants.TENANT_ID, scope, claims);
        scopeClaimMappingDAO.addScopes(TestConstants.TENANT_ID, scopeDTOList);
    }

    @Test
    public void testAddScopesException() throws Exception {

        mockDataSource();
        mockStatic(JdbcUtils.class);
        JdbcTemplate jdbcTemplate = Mockito.mock(JdbcTemplate.class);
        Mockito.when(JdbcUtils.getNewTemplate()).thenReturn(jdbcTemplate);
        Mockito.when(jdbcTemplate.withTransaction(any())).thenReturn(1);
        try {
            scopeClaimMappingDAO.addScopes(TestConstants.TENANT_ID, scopeDTOList);
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals(e.getMessage(),
                    "Scope with the name " + CLIENT_NAME + " already exists in the system. " +
                            "Please use a different scope name.");
        }
    }

    @Test
    public void testGetScopes() throws Exception {

        mockDataSource();
        Assert.assertEquals(scopeClaimMappingDAO.getScopes(TestConstants.TENANT_ID).size(), 2);
        try {
            connection.close();
            scopeClaimMappingDAO.getScopes(TestConstants.TENANT_ID);
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "Error occured while loading scopes claims mapping.");
        }
    }

    @Test
    public void testGetScopeNames() throws Exception {

        mockDataSource();
        Assert.assertEquals(scopeClaimMappingDAO.getScopeNames(TestConstants.TENANT_ID).size(), 2);
        try {
            connection.close();
            scopeClaimMappingDAO.getScopeNames(TestConstants.TENANT_ID);
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "Error while loading OIDC scopes.");
        }
    }

    @Test
    public void testGetScope() throws Exception {

        String scope = "openid";
        mockDataSource();
        ScopeDTO scopeDTO1 = scopeClaimMappingDAO.getScope(scope, TestConstants.TENANT_ID);
        Assert.assertEquals(scopeDTO1.getName(), scope);
        Assert.assertEquals(scopeDTO1.getClaim().length, 12);
        try {
            connection.close();
            scopeClaimMappingDAO.getScope(scope, TestConstants.TENANT_ID);
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "Error while fetching scope details for scope: " + "openid");
        }
    }

    @Test
    public void testGetClaims() throws Exception {

        String scope = "openid";
        mockDataSource();
        ScopeDTO scopeDTO1 = scopeClaimMappingDAO.getClaims(scope, TestConstants.TENANT_ID);
        Assert.assertEquals(scopeDTO1.getName(), scope);
        Assert.assertEquals(scopeDTO1.getClaim().length, 12);
    }

    @Test
    public void testDeleteScope() throws Exception {

        String scope = "openid";
        String invlidScope = "invalid";
        mockDataSource();
        JdbcTemplate jdbcTemplate = Mockito.mock(JdbcTemplate.class);
        mockDataSource();
        mockStatic(JdbcUtils.class);
        Mockito.when(JdbcUtils.getNewTemplate()).thenReturn(jdbcTemplate);
        Mockito.when(jdbcTemplate.withTransaction(any())).thenReturn(1);
        scopeClaimMappingDAO.deleteScope(scope, TestConstants.TENANT_ID);
        try {
            Mockito.when(jdbcTemplate.withTransaction(any())).thenReturn(-1);
            scopeClaimMappingDAO.deleteScope(invlidScope, TestConstants.TENANT_ID);
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "The scope: " + invlidScope + " does not exist to delete.");
        }
    }

    @Test
    public void testUpdateScope() throws Exception {

        String scope = "openid";
        List<String> addClaims = new ArrayList<>();
        List<String> deleteClaims = new ArrayList<>();
        mockDataSource();
        addClaims.add("address");
        deleteClaims.add("email");

        JdbcTemplate jdbcTemplate = Mockito.mock(JdbcTemplate.class);
        mockDataSource();
        mockStatic(JdbcUtils.class);
        Mockito.when(JdbcUtils.getNewTemplate()).thenReturn(jdbcTemplate);
        Mockito.when(jdbcTemplate.withTransaction(any())).thenReturn(2);
        scopeClaimMappingDAO.updateScope(scope, TestConstants.TENANT_ID, addClaims, deleteClaims);
        scopeClaimMappingDAO.updateScope(scopeDTO, TestConstants.TENANT_ID);
    }

    @Test
    public void testHasScopesPopulated() throws Exception {

        mockDataSource();
        Assert.assertTrue(scopeClaimMappingDAO.hasScopesPopulated(TestConstants.TENANT_ID));
    }

    @Test
    public void testIsScopeExist() throws Exception {

        String scope = "openid";
        mockDataSource();
        Assert.assertTrue(scopeClaimMappingDAO.isScopeExist(scope, TestConstants.TENANT_ID));
    }

    private void mockDataSource() throws Exception {

        connection = getConnection(DB_NAME);
        mockStatic(JDBCPersistenceManager.class);
        DataSource dataSource = Mockito.mock(DataSource.class);
        JDBCPersistenceManager jdbcPersistenceManager = Mockito.mock(JDBCPersistenceManager.class);
        Mockito.when(dataSource.getConnection()).thenReturn(connection);
        Mockito.when(jdbcPersistenceManager.getInstance()).thenReturn(jdbcPersistenceManager);
        Mockito.when(jdbcPersistenceManager.getDataSource()).thenReturn(dataSource);
    }

    protected void initiateH2Base(String databaseName) throws Exception {

        dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + databaseName);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" +
                    getFilePath("scope_claim.sql") + "'");
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" +
                    getFilePath("identity.sql") + "'");
        }
        dataSourceMap.put(databaseName, dataSource);
    }

    protected void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    public static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }
}
