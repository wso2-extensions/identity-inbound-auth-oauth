package org.wso2.carbon.identity.test.common.testng.realm;

import org.wso2.carbon.user.core.AuthorizationManager;
import org.wso2.carbon.user.core.UserStoreException;

/**
 * Simple In Memory Authorization Manager for mocking.
 */
public class MockAuthorizationManager implements AuthorizationManager {

    @Override
    public boolean isUserAuthorized(String s, String s1, String s2) throws UserStoreException {
        return false;
    }

    @Override
    public boolean isRoleAuthorized(String s, String s1, String s2) throws UserStoreException {
        return false;
    }

    @Override
    public String[] getExplicitlyAllowedUsersForResource(String s, String s1) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getAllowedRolesForResource(String s, String s1) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getDeniedRolesForResource(String s, String s1) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getExplicitlyDeniedUsersForResource(String s, String s1) throws UserStoreException {
        return new String[0];
    }

    @Override
    public void authorizeUser(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void authorizeRole(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void denyUser(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void denyRole(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void clearUserAuthorization(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void clearUserAuthorization(String s) throws UserStoreException {

    }

    @Override
    public void clearRoleAuthorization(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    public void clearRoleActionOnAllResources(String s, String s1) throws UserStoreException {

    }

    @Override
    public void clearRoleAuthorization(String s) throws UserStoreException {

    }

    @Override
    public void clearResourceAuthorizations(String s) throws UserStoreException {

    }

    @Override
    public String[] getAllowedUIResourcesForUser(String s, String s1) throws UserStoreException {
        return new String[0];
    }

    @Override
    public int getTenantId() throws UserStoreException {
        return 0;
    }

    @Override
    public void resetPermissionOnUpdateRole(String s, String s1) throws UserStoreException {

    }

    @Override
    public String[] normalizeRoles(String[] strings) {
        return new String[0];
    }
}
