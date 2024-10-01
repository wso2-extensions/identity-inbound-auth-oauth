package org.wso2.carbon.identity.oauth2.fga;

import org.springframework.beans.factory.config.AbstractFactoryBean;

public class AccessControlFactory extends AbstractFactoryBean<AccessControlHandler> {
    private static AccessControlHandler accessControlHandler;

    @Override
    public Class<?> getObjectType() {
        return null;
    }

    @Override
    public AccessControlHandler createInstance() throws Exception {
        if(accessControlHandler == null){
            accessControlHandler = new TopazAuthzHandler();
        }
        return accessControlHandler;
    }
}
