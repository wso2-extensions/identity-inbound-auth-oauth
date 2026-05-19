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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.TokenMgtUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.DELETE_TOKEN_BINDING_BY_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_REFRESH_TOKEN_BINDING_BY_REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID_AND_BINDING_REF;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_REF_EXISTS;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.STORE_TOKEN_BINDING;

/**
 * Token binding data access object implementation.
 */
public class TokenBindingMgtDAOImpl implements TokenBindingMgtDAO {

    private static final Log log = LogFactory.getLog(TokenBindingMgtDAOImpl.class);
    private static final String TOKEN_BINDING_REF = "binding_ref";
    private static final String TOKEN_BINDING_TYPE = "binding_type";
    private static final String DPOP_TOKEN_BINDING_TYPE = "DPoP";
    private static final String JWK_THUMBPRINT = "jkt";

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
    public Optional<TokenBinding> getTokenBindingByBindingRef(String tokenId, String bindingRef)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Getting token binding for the token id: " + tokenId + " and token binding ref: " + bindingRef);
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement =
                     connection.prepareStatement(RETRIEVE_TOKEN_BINDING_BY_TOKEN_ID_AND_BINDING_REF)) {
            preparedStatement.setString(1, tokenId);
            preparedStatement.setString(2, bindingRef);

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    TokenBinding tokenBinding = new TokenBinding(
                            resultSet.getString("TOKEN_BINDING_TYPE"),
                            bindingRef,
                            resultSet.getString("TOKEN_BINDING_VALUE"));
                    return Optional.of(tokenBinding);
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Failed to get token binding for the token id: " + tokenId + " and " +
                    "token binding ref: " + bindingRef, e);
        }
    }

    @Override
    public boolean isTokenBindingExistsForBindingReference(String tokenBindingReference)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Checking for token binding existence for the binding reference: "
                    + tokenBindingReference);
        }
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
                    "Failed to check the existence of token binding reference: " + tokenBindingReference, e);
        }
    }

    @Override
    public void storeTokenBinding(TokenBinding tokenBinding, int tenantId) throws IdentityOAuth2Exception {

        if (tokenBinding == null) {
            if (log.isDebugEnabled()) {
                log.debug("Token binding information is not available. " +
                        "Returning without proceeding to store token binding information.");
            }
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Storing token binding information" +
                    " accessTokenId: " + tokenBinding.getTokenId() +
                    " bindingType: " + tokenBinding.getBindingType() +
                    " bindingRef: " + tokenBinding.getBindingReference());
        }
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

    @Override
    public Optional<TokenBinding> getBindingFromRefreshToken(String refreshToken, boolean isTokenHashingEnabled)
            throws IdentityOAuth2Exception {

        if (JWTUtils.isJWT(refreshToken)) {
            return getBindingFromRefreshTokenJWT(refreshToken);
        }

        JdbcTemplate jdbcTemplate = new JdbcTemplate(IdentityDatabaseUtil.getDataSource());
        String processedRefreshToken = getProcessedRefreshToken(refreshToken, isTokenHashingEnabled);
        String retrieveTokenBindingQuery = OAuth2Util.isAccessTokenPersistenceEnabled() ?
                RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN :
                RETRIEVE_REFRESH_TOKEN_BINDING_BY_REFRESH_TOKEN;
        try {
            List<TokenBinding> tokenBindingList = jdbcTemplate.executeQuery(retrieveTokenBindingQuery,
                    (resultSet, rowNumber) -> {
                        TokenBinding tokenBinding = new TokenBinding();
                        tokenBinding.setBindingType(resultSet.getString(1));
                        tokenBinding.setBindingValue(resultSet.getString(2));
                        tokenBinding.setBindingReference(resultSet.getString(3));

                        return tokenBinding;
                    },
                    preparedStatement -> {
                        preparedStatement.setString(1, processedRefreshToken);
                        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
                            preparedStatement.setString(2, CERTIFICATE_BASED_TOKEN_BINDER);
                        }
                    });

            return tokenBindingList.isEmpty() ? Optional.empty() : Optional.ofNullable(tokenBindingList.get(0));
        } catch (DataAccessException e) {
            String error = "Error obtaining token binding type using refresh token.";
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private String getProcessedRefreshToken(String refreshToken, boolean isTokenHashingEnabled)
            throws IdentityOAuth2Exception {

        if (isTokenHashingEnabled) {
            TokenPersistenceProcessor hashingPersistenceProcessor = new HashingPersistenceProcessor();
            return hashingPersistenceProcessor.getProcessedRefreshToken(refreshToken);
        }
        TokenPersistenceProcessor persistenceProcessor = OAuthServerConfiguration.getInstance()
                .getPersistenceProcessor();
        return persistenceProcessor.getProcessedRefreshToken(refreshToken);
    }

    private Optional<TokenBinding> getBindingFromRefreshTokenJWT(String refreshToken) throws IdentityOAuth2Exception {

        SignedJWT signedJWT = TokenMgtUtil.parseJWT(refreshToken);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        Object bindingTypeObj = claimsSet.getClaim(TOKEN_BINDING_TYPE);
        Object bindingRefObj = claimsSet.getClaim(TOKEN_BINDING_REF);
        if (bindingTypeObj == null && bindingRefObj == null) {
            return Optional.empty();
        }
        if (bindingTypeObj == null || bindingRefObj == null || StringUtils.isBlank(bindingTypeObj.toString()) ||
                StringUtils.isBlank(bindingRefObj.toString())) {
            throw new IdentityOAuth2Exception("Malformed token binding claims found in the refresh token.");
        }

        String bindingType = bindingTypeObj.toString();
        String bindingReference = bindingRefObj.toString();
        String bindingValue = getTokenBindingValue(claimsSet, bindingType);
        if (isBindingValueRequired(bindingType) && StringUtils.isBlank(bindingValue)) {
            return Optional.empty();
        }
        return Optional.of(new TokenBinding(bindingType, bindingReference, bindingValue));
    }

    private boolean isBindingValueRequired(String bindingType) {

        return CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType)
                || DPOP_TOKEN_BINDING_TYPE.equals(bindingType);
    }

    private String getTokenBindingValue(JWTClaimsSet claimsSet, String bindingType) {

        Object cnfObj = claimsSet.getClaim(OAuthConstants.CNF);
        if (!(cnfObj instanceof Map)) {
            return null;
        }

        Map<?, ?> cnf = (Map<?, ?>) cnfObj;
        Object bindingValue = null;
        if (CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType)) {
            bindingValue = cnf.get(OAuthConstants.X5T_S256);
        } else if (DPOP_TOKEN_BINDING_TYPE.equals(bindingType)) {
            bindingValue = cnf.get(JWK_THUMBPRINT);
        }
        return bindingValue == null ? null : bindingValue.toString();
    }
}
