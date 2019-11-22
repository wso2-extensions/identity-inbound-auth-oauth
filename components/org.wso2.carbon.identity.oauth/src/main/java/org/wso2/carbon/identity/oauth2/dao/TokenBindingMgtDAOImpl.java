/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.DELETE_TOKEN_BINDING_BY_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_REF_EXISTS;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.STORE_TOKEN_BINDING;

public class TokenBindingMgtDAOImpl implements TokenBindingMgtDAO {

    private static final Log log = LogFactory.getLog(TokenBindingMgtDAOImpl.class);

    @Override
    public Optional<TokenBinding> getTokenBinding(String tokenId) throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                PreparedStatement preparedStatement = connection.prepareStatement(RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID)) {
            preparedStatement.setString(1, tokenId);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    TokenBinding tokenBinding = new TokenBinding(resultSet.getString("TOKEN_BINDING_TYPE"),
                            resultSet.getString("TOKEN_BINDING_REF"), resultSet.getString("TOKEN_BINDING_VALUE"));
                    return Optional.of(tokenBinding);
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Failed to get token binding for the token id: " + tokenId, e);
        }
    }

    @Override
    public boolean isTokenBindingExistsForBindingReference(String tokenBindingReference)
            throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                PreparedStatement preparedStatement = connection.prepareStatement(RETRIEVE_TOKEN_BINDING_REF_EXISTS)) {
            preparedStatement.setString(1, tokenBindingReference);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt("TOTAL") > 0;
                }
                return false;
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Failed to check the existance of token binding reference: " + tokenBindingReference, e);
        }
    }

    @Override
    public void storeTokenBinding(TokenBinding tokenBinding, int tenantId) throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                PreparedStatement preparedStatement = connection.prepareStatement(STORE_TOKEN_BINDING)) {
            preparedStatement.setString(1, tokenBinding.getTokenId());
            preparedStatement.setString(2, tokenBinding.getBindingType());
            preparedStatement.setString(3, tokenBinding.getBindingReference());
            preparedStatement.setString(4, tokenBinding.getBindingValue());
            preparedStatement.setInt(5, tenantId);
            preparedStatement.execute();
        } catch (SQLException e) {
            String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            if (MultitenantConstants.SUPER_TENANT_ID != tenantId) {
                tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            }
            throw new IdentityOAuth2Exception(
                    "Failed to store token binding: " + tokenBinding.toString() + "in tenant: " + tenantDomain, e);
        }
    }

    @Override
    public void deleteTokenBinding(String tokenId) throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                PreparedStatement preparedStatement = connection.prepareStatement(DELETE_TOKEN_BINDING_BY_TOKEN_ID)) {
            preparedStatement.setString(1, tokenId);
            preparedStatement.execute();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Failed to get token binding for the token id: " + tokenId, e);
        }
    }
}
