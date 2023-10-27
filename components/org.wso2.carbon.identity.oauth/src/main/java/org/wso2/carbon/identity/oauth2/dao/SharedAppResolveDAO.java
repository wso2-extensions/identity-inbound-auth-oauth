/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.GET_SHARED_APP_ID;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_SHARED_APPLICATION;

/**
 * DAO class to resolve shared application.
 */
public class SharedAppResolveDAO {

    public static String resolveSharedApplication(String appResideOrgId, String mainAppId, String orgId)
            throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(GET_SHARED_APP_ID)) {
            preparedStatement.setString(1, appResideOrgId);
            preparedStatement.setString(2, mainAppId);
            preparedStatement.setString(3, orgId);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(1);
                }
                return null;
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(ERROR_CODE_ERROR_RESOLVING_SHARED_APPLICATION.getCode(),
                    ERROR_CODE_ERROR_RESOLVING_SHARED_APPLICATION.getMessage(), e);
        }
    }
}
