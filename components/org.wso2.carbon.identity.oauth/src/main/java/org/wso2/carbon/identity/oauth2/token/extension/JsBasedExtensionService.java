package org.wso2.carbon.identity.oauth2.token.extension;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Component;

@Component(
        name = "identity.token.extension.component",
        immediate = true
)
public class JsBasedExtensionService {

    private static final Log log = LogFactory.getLog(JsBasedExtensionService.class);
    private BundleContext bundleContext;

    public void activate() {

        log.info("JsBasedExtensionService activated");
    }

    public void deactivate() {

        log.info("JsBasedExtensionService deactivated");
    }
}
