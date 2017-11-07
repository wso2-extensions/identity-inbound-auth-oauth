package org.wso2.carbon.identity.test.common.testng.realm;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;

/**
 * Simple In memory tenant manager for mocking.
 */
public class InMemoryTenantManager implements TenantManager {

    private static final String UNIVERSAL_TENANT = "Universe";
    private static final int UNIVERSAL_TENANT_ID = Short.MAX_VALUE;
    private Tenant universalTenant;

    public InMemoryTenantManager() {
        universalTenant = new Tenant();
        universalTenant.setId(UNIVERSAL_TENANT_ID);
        universalTenant.setDomain(UNIVERSAL_TENANT);
    }

    @Override
    public int addTenant(Tenant tenant) throws org.wso2.carbon.user.api.UserStoreException {
        return 0;
    }

    @Override
    public void updateTenant(Tenant tenant) throws org.wso2.carbon.user.api.UserStoreException {

    }

    @Override
    public Tenant getTenant(int i) throws org.wso2.carbon.user.api.UserStoreException {
        return new Tenant();
    }

    @Override
    public Tenant[] getAllTenants() throws org.wso2.carbon.user.api.UserStoreException {
        return new Tenant[] { universalTenant };
    }

    @Override
    public Tenant[] getAllTenantsForTenantDomainStr(String s) throws org.wso2.carbon.user.api.UserStoreException {
        return new Tenant[] { universalTenant };
    }

    @Override
    public String getDomain(int i) throws org.wso2.carbon.user.api.UserStoreException {
        return UNIVERSAL_TENANT;
    }

    @Override
    public int getTenantId(String s) throws org.wso2.carbon.user.api.UserStoreException {
        return UNIVERSAL_TENANT_ID;
    }

    @Override
    public void activateTenant(int i) throws org.wso2.carbon.user.api.UserStoreException {

    }

    @Override
    public void deactivateTenant(int i) throws org.wso2.carbon.user.api.UserStoreException {

    }

    @Override
    public boolean isTenantActive(int i) throws org.wso2.carbon.user.api.UserStoreException {
        return false;
    }

    @Override
    public void deleteTenant(int i) throws org.wso2.carbon.user.api.UserStoreException {

    }

    @Override
    public void deleteTenant(int i, boolean b) throws org.wso2.carbon.user.api.UserStoreException {

    }

    @Override
    public String getSuperTenantDomain() throws UserStoreException {
        return null;
    }

    @Override
    public void setBundleContext(BundleContext bundleContext) {

    }

    @Override
    public void initializeExistingPartitions() {

    }
}
