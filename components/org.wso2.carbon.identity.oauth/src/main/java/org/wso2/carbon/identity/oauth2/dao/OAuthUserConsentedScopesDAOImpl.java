package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeConsentClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeConsentException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeConsentServerException;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * OAuth user consented scopes management data access object implementation.
 */
public class OAuthUserConsentedScopesDAOImpl implements OAuthUserConsentedScopesDAO {

    private static final Log log = LogFactory.getLog(OAuthUserConsentedScopesDAOImpl.class);

    @Override
    public UserApplicationScopeConsentDO getUserConsentForApplication(String userId, String appId, int tenantId)
            throws IdentityOAuth2ScopeConsentException {

        if (log.isDebugEnabled()) {
            log.debug("Get user consented scopes for userId  :" + userId + " and appId: " + appId + " and " +
                    "tenantId : " + tenantId);
        }
        validateUserId(userId);
        validateAppId(appId);
        UserApplicationScopeConsentDO userScopeConsent = new UserApplicationScopeConsentDO(appId);
        List<String> approvedScopes = new ArrayList<>();
        List<String> disapprovedScopes = new ArrayList<>();
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.GET_OAUTH2_USER_CONSENT_FOR_APP)) {
                ps.setString(1, userId);
                ps.setString(2, appId);
                ps.setInt(3, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String scope = rs.getString(1);
                        boolean consent = rs.getBoolean(2);
                        if (consent) {
                            approvedScopes.add(scope);
                        } else {
                            disapprovedScopes.add(scope);
                        }
                    }
                }
            }
            userScopeConsent.setApprovedScopes(approvedScopes);
            userScopeConsent.setDeniedScopes(disapprovedScopes);
            return userScopeConsent;
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving scope consents for  userId  :" + userId + " and appId: " +
                    appId + " and " + "tenantId : " + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new IdentityOAuth2ScopeConsentServerException(msg, e);
        }
    }

    @Override
    public List<UserApplicationScopeConsentDO> getUserConsents(String userId, int tenantId)
            throws IdentityOAuth2ScopeConsentException {

        if (log.isDebugEnabled()) {
            log.debug("Get user consented scopes for user with userId  :" + userId + " in tenantId : " + tenantId);
        }
        validateUserId(userId);
        Map<String, UserApplicationScopeConsentDO> userScopeConsentsMap = new HashMap<>();
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.GET_OAUTH2_USER_CONSENTS)) {
                ps.setString(1, userId);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String appId = rs.getString(1);
                        String scope = rs.getString(2);
                        boolean consent = rs.getBoolean(3);
                        userScopeConsentsMap.putIfAbsent(appId, new UserApplicationScopeConsentDO(appId));
                        if (consent) {
                            userScopeConsentsMap.get(appId).getApprovedScopes().add(scope);
                        } else {
                            userScopeConsentsMap.get(appId).getDeniedScopes().add(scope);
                        }
                    }
                }
            }
            return new ArrayList<>(userScopeConsentsMap.values());
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving scope consents for  userId  :" + userId + " in tenantId : "
                    + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new IdentityOAuth2ScopeConsentServerException(msg, e);
        }
    }

    @Override
    public void addUserConsentForApplication(String userId, int tenantId,
                                             UserApplicationScopeConsentDO userConsent)
            throws IdentityOAuth2ScopeConsentException {

        if (log.isDebugEnabled()) {
            log.debug("Adding scope consents for userId  :" + userId + " and appId: " + userConsent.getAppId() +
                    " and tenantId : " + tenantId + " for approved scopes : " +
                    userConsent.getApprovedScopes().stream().collect(Collectors.joining(", ")) + " and " +
                    "disapproved scopes : " + userConsent.getDeniedScopes().stream()
                    .collect(Collectors.joining(", ")) + ".");
        }
        validateUserId(userId);
        validateUserConsent(userConsent);
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true)) {
            String consentId = generateConsentId();
            deleteUserConsent(conn, userId, userConsent.getAppId(), tenantId);
            addUserConsentInformation(conn, userId, userConsent.getAppId(), tenantId, consentId);
            addUserConsentedScopes(conn, consentId, tenantId, userConsent);
            IdentityDatabaseUtil.commitTransaction(conn);
        } catch (SQLException e) {
            String msg = "Error occurred while adding scope consents for  userId  :" + userId + " and appId: " +
                    userConsent.getAppId() + " and " + "tenantId : " + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new IdentityOAuth2ScopeConsentServerException(msg, e);
        }
    }

    @Override
    public void updateExistingConsentForApplication(String userId, int tenantId,
                                                    UserApplicationScopeConsentDO updatedUserConsents)
            throws IdentityOAuth2ScopeConsentException {

        if (log.isDebugEnabled()) {
            log.debug("Update scope consents for userId  :" + userId + " and appId: "
                    + updatedUserConsents.getAppId() + " and " + "tenantId : " + tenantId + ".");
        }
        validateUserId(userId);
        validateUserConsent(updatedUserConsents);
        UserApplicationScopeConsentDO existingConsent =
                getUserConsentForApplication(userId, updatedUserConsents.getAppId(), tenantId);
        UserApplicationScopeConsentDO consentsToBeUpdated =
                getConsentsToBeUpdated(existingConsent, updatedUserConsents);
        UserApplicationScopeConsentDO consentsToBeAdded =
                getConsentsToBeAdded(consentsToBeUpdated, updatedUserConsents);
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(true)) {
            String consentId = getConsentId(conn, userId, updatedUserConsents.getAppId(), tenantId);
            if (StringUtils.isBlank(consentId)) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to find an existing consent for user : " + userId + ", app : " +
                            updatedUserConsents.getAppId() + " and tenant with id : " + tenantId);
                }
                throw new IdentityOAuth2ScopeConsentException("Unable to find an existing consent for user : " +
                        userId + ", app : " + updatedUserConsents.getAppId() + " and tenant with id : " + tenantId);
            }
            if (CollectionUtils.isNotEmpty(consentsToBeAdded.getApprovedScopes()) ||
                    CollectionUtils.isNotEmpty(consentsToBeAdded.getDeniedScopes())) {
                addUserConsentedScopes(conn, consentId, tenantId, consentsToBeAdded);
            }
            if (CollectionUtils.isNotEmpty(consentsToBeUpdated.getApprovedScopes()) ||
                    CollectionUtils.isNotEmpty(consentsToBeUpdated.getDeniedScopes())) {
                updateUserConsentedScopes(conn, userId, tenantId, consentsToBeUpdated);
            }
            IdentityDatabaseUtil.commitTransaction(conn);
        } catch (SQLException e) {
            String msg = "Error occurred while updating scope consents for  userId  :" + userId + " and appId: " +
                    updatedUserConsents.getAppId() + " and " + "tenantId : " + tenantId + ".";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new IdentityOAuth2ScopeConsentServerException(msg, e);
        }
    }

    @Override
    public void deleteUserConsentOfApplication(String userId, String appId, int tenantId)
            throws IdentityOAuth2ScopeConsentException {

        if (log.isDebugEnabled()) {
            log.debug("Delete scope consents for userId  :" + userId + " and appId: " + appId + " and " +
                    "tenantId : " + tenantId + ".");
        }
        validateUserId(userId);
        validateAppId(appId);
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            deleteUserConsent(conn, userId, appId, tenantId);
        } catch (SQLException e) {
            String msg = "Error occurred while deleting scope consents for  userId  :" + userId + " and appId: " +
                    appId + " and " + "tenantId : " + tenantId + ".";
            throw new IdentityOAuth2ScopeConsentException(msg, e);
        }
    }

    @Override
    public void deleteUserConsents(String userId, int tenantId) throws IdentityOAuth2ScopeConsentException {

        if (log.isDebugEnabled()) {
            log.debug("Revoking all scope consents for user with userId  :" + userId + " in tenantId : "
                    + tenantId + ".");
        }
        validateUserId(userId);
        try (Connection conn = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = conn.prepareStatement(SQLQueries.REMOVE_OAUTH2_USER_CONSENTS)) {
                ps.setString(1, userId);
                ps.setInt(2, tenantId);
                ps.execute();
            }
        } catch (SQLException e) {
            String msg = "Error occurred while deleting user scope consents for  userId  :" + userId + " and "
                    + "tenantId : " + tenantId + ".";
            throw new IdentityOAuth2ScopeConsentServerException(msg, e);
        }
    }

    private UserApplicationScopeConsentDO getConsentsToBeUpdated(UserApplicationScopeConsentDO existingConsent,
                                                                 UserApplicationScopeConsentDO updatedConsent) {
        UserApplicationScopeConsentDO consentToBeUpdated =
                new UserApplicationScopeConsentDO(updatedConsent.getAppId());
        List<String> approvedScopes = new ArrayList<>();
        List<String> disapprovedScopes = new ArrayList<>();
        approvedScopes.addAll(updatedConsent.getApprovedScopes().stream()
                .filter(scope -> existingConsent.getDeniedScopes().contains(scope))
                .collect(Collectors.toSet()));
        disapprovedScopes.addAll(updatedConsent.getDeniedScopes().stream()
                .filter(scope -> existingConsent.getApprovedScopes().contains(scope))
                .collect(Collectors.toSet()));
        consentToBeUpdated.setApprovedScopes(approvedScopes);
        consentToBeUpdated.setDeniedScopes(disapprovedScopes);
        return consentToBeUpdated;
    }

    private UserApplicationScopeConsentDO getConsentsToBeAdded(UserApplicationScopeConsentDO consentToBeUpdated,
                                                               UserApplicationScopeConsentDO updatedConsent) {

        UserApplicationScopeConsentDO consentToBeAdded =
                new UserApplicationScopeConsentDO(updatedConsent.getAppId());
        List<String> approvedScopes = new ArrayList<String>() {{
            addAll(updatedConsent.getApprovedScopes());
        }};
        List<String> disapprovedScopes = new ArrayList<String>() {{
            addAll(updatedConsent.getDeniedScopes());
        }};
        approvedScopes.removeAll(consentToBeUpdated.getApprovedScopes());
        disapprovedScopes.removeAll(consentToBeUpdated.getDeniedScopes());
        consentToBeAdded.setApprovedScopes(approvedScopes);
        consentToBeAdded.setDeniedScopes(disapprovedScopes);
        return consentToBeAdded;
    }

    private void updateUserConsentedScopes(Connection connection, String userId, int tenantId,
                                           UserApplicationScopeConsentDO userConsentsToBeUpdated) throws SQLException {

        try (PreparedStatement ps = connection.prepareStatement(SQLQueries.UPDATE_OAUTH2_USER_CONSENTED_SCOPES)) {
            List<String> approvedScopes = userConsentsToBeUpdated.getApprovedScopes();
            List<String> disapprovedScopes = userConsentsToBeUpdated.getDeniedScopes();
            if (CollectionUtils.isNotEmpty(approvedScopes)) {
                for (String scope : approvedScopes) {
                    ps.setBoolean(1, true);
                    ps.setString(2, scope);
                    ps.setString(3, userId);
                    ps.setString(4, userConsentsToBeUpdated.getAppId());
                    ps.setInt(5, tenantId);
                    ps.addBatch();
                }
            }
            if (CollectionUtils.isNotEmpty(disapprovedScopes)) {
                for (String scope : disapprovedScopes) {
                    ps.setBoolean(1, false);
                    ps.setString(2, scope);
                    ps.setString(3, userId);
                    ps.setString(4, userConsentsToBeUpdated.getAppId());
                    ps.setInt(5, tenantId);
                    ps.addBatch();
                }
            }
            ps.executeBatch();
        }
    }

    private void addUserConsentInformation(Connection connection, String userId, String appId, int tenantId,
                                           String consentId) throws SQLException {

        try (PreparedStatement ps = connection.prepareStatement(SQLQueries.INSERT_OAUTH2_USER_CONSENT)) {
            ps.setString(1, userId);
            ps.setString(2, appId);
            ps.setInt(3, tenantId);
            ps.setString(4, consentId);
            ps.execute();
        }
    }

    private void addUserConsentedScopes(Connection connection, String consentId, int tenantId,
                                        UserApplicationScopeConsentDO userConsentsToBeAdded)
            throws SQLException {

        try (PreparedStatement ps = connection.prepareStatement(SQLQueries.INSERT_OAUTH2_USER_CONSENTED_SCOPE)) {
            List<String> approvedScopes = userConsentsToBeAdded.getApprovedScopes();
            List<String> disapprovedScopes = userConsentsToBeAdded.getDeniedScopes();
            if (CollectionUtils.isNotEmpty(approvedScopes)) {
                for (String scope : approvedScopes) {
                    ps.setString(1, consentId);
                    ps.setString(2, scope);
                    ps.setInt(3, tenantId);
                    ps.setBoolean(4, true);
                    ps.addBatch();
                }
            }
            if (CollectionUtils.isNotEmpty(disapprovedScopes)) {
                for (String scope : disapprovedScopes) {
                    ps.setString(1, consentId);
                    ps.setString(2, scope);
                    ps.setInt(3, tenantId);
                    ps.setBoolean(4, false);
                    ps.addBatch();
                }
            }
            ps.executeBatch();
        }
    }

    private void deleteUserConsent(Connection connection, String userId, String appId, int tenantId)
            throws SQLException {

        try (PreparedStatement ps = connection.prepareStatement(SQLQueries.REMOVE_OAUTH2_USER_CONSENT_FOR_APP)) {
            ps.setString(1, userId);
            ps.setString(2, appId);
            ps.setInt(3, tenantId);
            ps.execute();
        }
    }

    private String generateConsentId() {

        return UUID.randomUUID().toString();
    }

    private String getConsentId(Connection connection, String userId, String appId, int tenantId) throws SQLException {

        String consentId = null;
        try (PreparedStatement ps = connection.prepareStatement(SQLQueries.GET_CONSENT_ID_FOR_CONSENT)) {
            ps.setString(1, userId);
            ps.setString(2, appId);
            ps.setInt(3, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    consentId = rs.getString(1);
                }
            }
        }
        return consentId;
    }

    private void validateUserConsent(UserApplicationScopeConsentDO userConsent)
            throws IdentityOAuth2ScopeConsentClientException {

        if (userConsent == null) {
            if (log.isDebugEnabled()) {
                log.debug("User consent can't be null or empty.");
            }
            throw new IdentityOAuth2ScopeConsentClientException("User consent can't be null or empty.");
        }

        if (StringUtils.isBlank(userConsent.getAppId())) {
            if (log.isDebugEnabled()) {
                log.debug("Application Id can't be null/empty.");
            }
            throw new IdentityOAuth2ScopeConsentClientException("Application Id can't be null/empty.");
        }

        if (CollectionUtils.isEmpty(userConsent.getApprovedScopes())
                && CollectionUtils.isEmpty(userConsent.getDeniedScopes())) {
            if (log.isDebugEnabled()) {
                log.debug("User hasn't approved or disapproved any scopes.");
            }
            throw new IdentityOAuth2ScopeConsentClientException("User hasn't approved or disapproved any scopes.");
        }
    }

    private void validateAppId(String appId) throws IdentityOAuth2ScopeConsentClientException {

        if (StringUtils.isBlank(appId)) {
            if (log.isDebugEnabled()) {
                log.debug("Application Id can't be null/empty.");
            }
            throw new IdentityOAuth2ScopeConsentClientException("Application Id can't be null/empty.");
        }
    }

    private void validateUserId(String userId) throws IdentityOAuth2ScopeConsentClientException {

        if (StringUtils.isBlank(userId)) {
            if (log.isDebugEnabled()) {
                log.debug("User ID can't be empty or null.");
            }
            throw new IdentityOAuth2ScopeConsentClientException("User ID can't be empty or null.");
        }
    }
}
