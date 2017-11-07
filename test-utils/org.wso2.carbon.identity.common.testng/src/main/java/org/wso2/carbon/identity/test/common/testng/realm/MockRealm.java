package org.wso2.carbon.identity.test.common.testng.realm;

import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.AuthorizationManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.claim.ClaimMapping;
import org.wso2.carbon.user.core.profile.ProfileConfiguration;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;

import java.util.Map;

/**
 * Simple user realm for testing.
 */
public class MockRealm implements UserRealm {

    private RealmConfiguration realmConfiguration;
    private AuthorizationManager authorizationManager = new MockAuthorizationManager();
    private UserStoreManager userStoreManager = new MockUserStoreManager();
    private int tenantId;

    @Override
    public void init(RealmConfiguration realmConfiguration, Map<String, ClaimMapping> map,
            Map<String, ProfileConfiguration> map1, int tenantId) throws UserStoreException {
        this.realmConfiguration = realmConfiguration;
        this.tenantId = tenantId;
    }

    @Override
    public void init(RealmConfiguration realmConfiguration, Map<String, Object> map, int tenantId)
            throws UserStoreException {
        this.realmConfiguration = realmConfiguration;
        this.tenantId = tenantId;
    }

    @Override
    public AuthorizationManager getAuthorizationManager() throws UserStoreException {
        return authorizationManager;
    }

    @Override
    public UserStoreManager getUserStoreManager() throws UserStoreException {
        return userStoreManager;
    }

    @Override
    public ClaimManager getClaimManager() throws UserStoreException {
        return null;
    }

    @Override
    public ProfileConfigurationManager getProfileConfigurationManager() throws UserStoreException {
        return null;
    }

    @Override
    public void cleanUp() throws UserStoreException {

    }

    @Override
    public RealmConfiguration getRealmConfiguration() throws UserStoreException {
        return this.realmConfiguration;
    }
}
