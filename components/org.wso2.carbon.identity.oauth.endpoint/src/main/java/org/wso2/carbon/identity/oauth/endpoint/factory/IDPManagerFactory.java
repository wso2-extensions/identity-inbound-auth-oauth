package org.wso2.carbon.identity.oauth.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.idp.mgt.IdpManager;

/**
 * Factory Beans serves as a factory for creating other beans within the IOC container. This factory bean is used to
 * instantiate the IDP Management service type of object inside the container.
 */
public class IDPManagerFactory extends AbstractFactoryBean<IdpManager> {

    private IdpManager idpManager;

    @Override
    public Class<IdpManager> getObjectType() {

        return IdpManager.class;
    }

    @Override
    protected IdpManager createInstance() throws Exception {

        if (this.idpManager != null) {
            return idpManager;
        } else {
            IdpManager idpManager = (IdpManager) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getOSGiService(IdpManager.class, null);
            if (idpManager != null) {
                this.idpManager = idpManager;
            }
            return idpManager;
        }
    }
}
