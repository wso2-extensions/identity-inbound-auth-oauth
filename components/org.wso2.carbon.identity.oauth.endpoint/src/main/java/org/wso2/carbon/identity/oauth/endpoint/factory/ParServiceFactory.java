package org.wso2.carbon.identity.oauth.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.identity.oauth.par.api.ParAuthServiceImpl;

public class ParServiceFactory extends AbstractFactoryBean<ParAuthServiceImpl> {
    @Override
    public Class<?> getObjectType() {
        return null;
    }

    @Override
    protected ParAuthServiceImpl createInstance() throws Exception {
        return null;
    }
}
