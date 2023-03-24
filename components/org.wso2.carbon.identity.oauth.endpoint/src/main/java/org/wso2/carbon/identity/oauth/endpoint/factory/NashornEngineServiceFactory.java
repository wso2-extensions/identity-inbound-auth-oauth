package org.wso2.carbon.identity.oauth.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.token.extension.JsBaseExtensionBuilderFactory;

public class NashornEngineServiceFactory extends AbstractFactoryBean<JsBaseExtensionBuilderFactory> {

    private JsBaseExtensionBuilderFactory jsExtensionBuilderFactory;

    @Override
    public Class<JsBaseExtensionBuilderFactory> getObjectType() {

        return JsBaseExtensionBuilderFactory.class;
    }

    @Override
    protected JsBaseExtensionBuilderFactory createInstance() throws Exception {

        if (this.jsExtensionBuilderFactory != null) {
            return this.jsExtensionBuilderFactory;
        } else {
            JsBaseExtensionBuilderFactory nashornEngineService = (JsBaseExtensionBuilderFactory) PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiService(JsBaseExtensionBuilderFactory.class, null);
            if (nashornEngineService != null) {
                this.jsExtensionBuilderFactory = nashornEngineService;
            }
            return nashornEngineService;
        }
    }

}
