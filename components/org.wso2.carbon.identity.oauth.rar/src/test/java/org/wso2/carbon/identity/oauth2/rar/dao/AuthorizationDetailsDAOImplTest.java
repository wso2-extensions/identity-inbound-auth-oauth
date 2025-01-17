/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.dao;

import org.apache.commons.lang3.StringUtils;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.api.resource.mgt.util.AuthorizationDetailsTypesUtil;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsCodeDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.util.TestDAOUtils;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_CODE_ID;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_CONSENT_ID;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_DB_NAME;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_TENANT_ID;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.rar.util.TestConstants.TEST_TYPE;
import static org.wso2.carbon.identity.oauth2.rar.util.TestDAOUtils.closeMockedStatic;

/**
 * Test class for {@link AuthorizationDetailsDAO}.
 */
public class AuthorizationDetailsDAOImplTest {

    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock;
    private MockedStatic<AuthorizationDetailsTypesUtil> authorizationDetailsTypesUtilMock;
    private AuthorizationDetailsDAO uut;

    @BeforeClass
    public void setUp() throws SQLException {
        this.uut = new AuthorizationDetailsDAOImpl();
        TestDAOUtils.initializeDataSource(TEST_DB_NAME, TestDAOUtils.getFilePath("h2.sql"));
        this.identityDatabaseUtilMock = Mockito.mockStatic(IdentityDatabaseUtil.class);
        this.authorizationDetailsTypesUtilMock = Mockito.mockStatic(AuthorizationDetailsTypesUtil.class);
    }

    @AfterClass
    public void tearDown() throws SQLException {

        closeMockedStatic(this.identityDatabaseUtilMock);
        closeMockedStatic(this.authorizationDetailsTypesUtilMock);
    }

    @BeforeMethod
    public void setUpBeforeMethod() throws SQLException {

        this.mockIdentityDatabaseUtil();
        this.mockAuthorizationDetailsTypesUtil(true);
    }

    @Test
    public void testAddUserConsentedAuthorizationDetails() throws SQLException {

        assertEquals(0, this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID).size());

        this.mockIdentityDatabaseUtil();

        AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        AuthorizationDetailsConsentDTO consentDTO =
                new AuthorizationDetailsConsentDTO(TEST_CONSENT_ID, testAuthorizationDetail, true, TEST_TENANT_ID);
        int[] result = uut.addUserConsentedAuthorizationDetails(Collections.singleton(consentDTO));

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
    public void testUpdateUserConsentedAuthorizationDetails() throws SQLException {

        final String identifier = UUID.randomUUID().toString();
        Set<AuthorizationDetailsConsentDTO> existingConsentDTOs =
                this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID);

        this.mockIdentityDatabaseUtil();

        AuthorizationDetailsConsentDTO existingDTO = existingConsentDTOs.iterator().next();
        Assert.assertTrue(StringUtils.isEmpty(existingDTO.getAuthorizationDetail().getIdentifier()));

        AuthorizationDetail authorizationDetailToUpdate = existingDTO.getAuthorizationDetail();
        authorizationDetailToUpdate.setIdentifier(identifier);

        AuthorizationDetailsConsentDTO consentDTO = new AuthorizationDetailsConsentDTO(existingDTO.getConsentId(),
                authorizationDetailToUpdate, existingDTO.isConsentActive(), existingDTO.getTenantId());

        int[] result = uut.updateUserConsentedAuthorizationDetails(Collections.singleton(consentDTO));
        assertEquals(1, result.length);

        this.mockIdentityDatabaseUtil();

        Set<AuthorizationDetailsConsentDTO> updatedConsentDTOs =
                this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID);
        AuthorizationDetailsConsentDTO updatedDto = updatedConsentDTOs.iterator().next();

        assertEquals(existingConsentDTOs.size(), updatedConsentDTOs.size());
        assertEquals(existingDTO.getAuthorizationDetail().getType(), updatedDto.getAuthorizationDetail().getType());
        assertEquals(identifier, updatedDto.getAuthorizationDetail().getIdentifier());
    }

    @Test(dependsOnMethods = "testUpdateUserConsentedAuthorizationDetails")
    public void testDeleteUserConsentedAuthorizationDetails() throws SQLException {

        assertEquals(1, uut.deleteUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID));

        this.mockIdentityDatabaseUtil();

        assertEquals(0, this.uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID).size());
    }

    @Test
    public void testAddAccessTokenAuthorizationDetails() throws SQLException {
        assertEquals(0, this.uut.getAccessTokenAuthorizationDetails(TEST_TOKEN_ID, TEST_TENANT_ID).size());

        this.mockIdentityDatabaseUtil();

        AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        AuthorizationDetailsTokenDTO tokenDTO =
                new AuthorizationDetailsTokenDTO(TEST_TOKEN_ID, testAuthorizationDetail, TEST_TENANT_ID);

        int[] result = uut.addAccessTokenAuthorizationDetails(Collections.singleton(tokenDTO));

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

        this.mockIdentityDatabaseUtil();

        assertEquals(0, this.uut.getAccessTokenAuthorizationDetails(TEST_TOKEN_ID, TEST_TENANT_ID).size());
    }

    @Test
    public void testAddOAuth2CodeAuthorizationDetails() throws SQLException {
        assertEquals(0, this.uut.getOAuth2CodeAuthorizationDetails(TEST_CODE_ID, TEST_TENANT_ID).size());

        this.mockIdentityDatabaseUtil();

        AuthorizationDetail testAuthorizationDetail = new AuthorizationDetail();
        testAuthorizationDetail.setType(TEST_TYPE);

        AuthorizationDetailsCodeDTO codeDTO =
                new AuthorizationDetailsCodeDTO(TEST_CODE_ID, testAuthorizationDetail, TEST_TENANT_ID);

        int[] result = uut.addOAuth2CodeAuthorizationDetails(Collections.singleton(codeDTO));

        assertEquals(1, result.length);
    }

    @Test(priority = 1)
    public void testGetOAuth2CodeAuthorizationDetails() throws SQLException {
        Set<AuthorizationDetailsCodeDTO> codeDTOs =
                this.uut.getOAuth2CodeAuthorizationDetails(TEST_AUTHORIZATION_CODE, TEST_TENANT_ID);

        assertEquals(1, codeDTOs.size());
        codeDTOs.forEach(dto -> {
            assertEquals(TEST_CODE_ID, dto.getAuthorizationCodeId());
            assertNotNull(dto.getAuthorizationDetail());
            assertEquals(TEST_TYPE, dto.getAuthorizationDetail().getType());
        });
    }

    @Test(priority = 3, expectedExceptions = {SQLException.class})
    public void shouldThrowSQLException_whenAddingConsentedAuthorizationDetailsFails() throws SQLException {

        try (Connection connectionMock = Mockito.spy(Connection.class)) {

            Mockito.when(connectionMock.prepareStatement(anyString())).thenThrow(SQLException.class);
            identityDatabaseUtilMock
                    .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                    .thenReturn(connectionMock);
            uut.addUserConsentedAuthorizationDetails(Collections.emptySet());
        }
    }

    @Test(priority = 3, expectedExceptions = {SQLException.class})
    public void shouldThrowSQLException_whenGettingConsentedAuthorizationDetailsFails() throws SQLException {

        try (Connection connectionMock = Mockito.spy(Connection.class)) {

            Mockito.when(connectionMock.prepareStatement(anyString())).thenThrow(SQLException.class);
            identityDatabaseUtilMock
                    .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                    .thenReturn(connectionMock);
            uut.getUserConsentedAuthorizationDetails(TEST_CONSENT_ID, TEST_TENANT_ID);
        }
    }

    @Test
    public void testGetConsentIdByUserIdAndAppId() throws SQLException {

        assertNotNull(this.uut.getConsentIdByUserIdAndAppId("valid_user_id", "valid_app_id", TEST_TENANT_ID));
    }

    @Test
    public void shouldReturnNull_whenUserIdOrAppIdInvalid() throws SQLException {

        assertNull(this.uut.getConsentIdByUserIdAndAppId("invalid_user_id", "invalid_app_id", TEST_TENANT_ID));
    }

    private void mockAuthorizationDetailsTypesUtil(boolean isRichAuthorizationRequestsEnabled) {

        this.authorizationDetailsTypesUtilMock
                .when(AuthorizationDetailsTypesUtil::isRichAuthorizationRequestsDisabled)
                .thenReturn(!isRichAuthorizationRequestsEnabled);
    }

    private void mockIdentityDatabaseUtil() throws SQLException {

        this.identityDatabaseUtilMock
                .when(() -> IdentityDatabaseUtil.getDBConnection(any(Boolean.class)))
                .thenReturn(TestDAOUtils.getConnection(TEST_DB_NAME));
    }
}
