package org.wso2.carbon.identity.oauth2.rar.dao;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.util.DAOUtils;

import java.sql.SQLException;
import java.util.Collections;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;

public class AuthorizationDetailsDAOImplTest {

    private static final String TEST_CONSENT_ID = "52481ccd-0927-4d17-8cfc-5110fc4aa009";
    private static final String TEST_DB_NAME = "TEST_IAM_RAR_DATABASE";
    private static final int TEST_TENANT_ID = 1234;
    private static final String TEST_TOKEN_ID = "e1fea951-a3b5-4347-bd73-b18b3feecd54";
    private static final String TEST_TYPE = "test_type_v1";

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock;
    private AuthorizationDetailsDAO uut;

    @BeforeClass
    public void setUp() throws SQLException {
        this.uut = new AuthorizationDetailsDAOImpl();
        DAOUtils.initializeDataSource(TEST_DB_NAME, DAOUtils.getFilePath("h2.sql"));
        this.identityDatabaseUtilMock = Mockito.mockStatic(IdentityDatabaseUtil.class);
    }

    @AfterClass
    public void tearDown() throws SQLException {

        if (this.identityDatabaseUtilMock != null && !this.identityDatabaseUtilMock.isClosed()) {
            this.identityDatabaseUtilMock.close();
        }
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws SQLException {
        this.identityDatabaseUtilMock
                .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                .thenReturn(DAOUtils.getConnection(TEST_DB_NAME));
    }

    @Test(priority = 0)
    public void testAddUserConsentedAuthorizationDetails() throws SQLException {

        assertEquals(0, this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID).size());

        this.identityDatabaseUtilMock
                .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                .thenReturn(DAOUtils.getConnection(TEST_DB_NAME));

        AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        AuthorizationDetailsConsentDTO consentDTO =
                new AuthorizationDetailsConsentDTO(TEST_CONSENT_ID, testAuthorizationDetail, true, TEST_TENANT_ID);
        int[] result = uut.addUserConsentedAuthorizationDetails(Collections.singletonList(consentDTO));

        assertEquals(1, result.length);
    }

    @Test(priority = 1)
    public void testGetUserConsentedAuthorizationDetails() throws SQLException {

        Set<AuthorizationDetailsConsentDTO> consentDTOs =
                this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID);

        assertEquals(1, consentDTOs.size());
        consentDTOs.forEach(dto -> {
            assertEquals(TEST_CONSENT_ID, dto.getConsentId());
            assertNotNull(dto.getAuthorizationDetail());
            assertEquals(TEST_TYPE, dto.getAuthorizationDetail().getType());
        });
    }

    @Test(priority = 2)
    public void testDeleteUserConsentedAuthorizationDetails() throws SQLException {

        assertEquals(1, uut.deleteUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID));

        this.identityDatabaseUtilMock
                .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                .thenReturn(DAOUtils.getConnection(TEST_DB_NAME));

        assertEquals(0, this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID).size());
    }

    @Test(priority = 0)
    public void testAddAccessTokenAuthorizationDetails() throws SQLException {
        assertEquals(0, this.uut.getAccessTokenAuthorizationDetails(TEST_TOKEN_ID, TEST_TENANT_ID).size());

        this.identityDatabaseUtilMock
                .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                .thenReturn(DAOUtils.getConnection(TEST_DB_NAME));

        AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        AuthorizationDetailsTokenDTO tokenDTO =
                new AuthorizationDetailsTokenDTO(TEST_TOKEN_ID, testAuthorizationDetail, TEST_TENANT_ID);

        int[] result = uut.addAccessTokenAuthorizationDetails(Collections.singletonList(tokenDTO));

        assertEquals(1, result.length);
    }

    @Test(priority = 1)
    public void testGetAccessTokenAuthorizationDetails() throws SQLException {
        Set<AuthorizationDetailsTokenDTO> tokenDTOs =
                this.uut.getAccessTokenAuthorizationDetails(TEST_TOKEN_ID, TEST_TENANT_ID);

        assertEquals(1, tokenDTOs.size());
        tokenDTOs.forEach(dto -> {
            assertEquals(TEST_TOKEN_ID, dto.getAccessTokenId());
            assertNotNull(dto.getAuthorizationDetail());
            assertEquals(TEST_TYPE, dto.getAuthorizationDetail().getType());
        });
    }

    @Test(priority = 2)
    public void testDeleteAccessTokenAuthorizationDetails() throws SQLException {
        assertEquals(1, uut.deleteAccessTokenAuthorizationDetails(TEST_TOKEN_ID, TEST_TENANT_ID));

        this.identityDatabaseUtilMock
                .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                .thenReturn(DAOUtils.getConnection(TEST_DB_NAME));

        assertEquals(0, this.uut.getAccessTokenAuthorizationDetails(TEST_TOKEN_ID, TEST_TENANT_ID).size());
    }
}
