package org.wso2.carbon.identity.oauth.par.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.oauth.par.ValidateCallbackURL;
import org.wso2.carbon.identity.oauth.par.ValidateCallbackURLImpl;


@Component(
        name = "validate.callback.URL",
        immediate = true
)

public class ValidateCallbackURLServiceComponent {
    private static final Log log = LogFactory.getLog(ValidateCallbackURLServiceComponent.class);

    @Activate
    protected void activate(ComponentContext componentContext) {
        try {
            ValidateCallbackURL callbackURL = new ValidateCallbackURLImpl();

            componentContext.getBundleContext().registerService(ValidateCallbackURL.class, callbackURL, null);
            log.info("PAR validation Success");
        }
        catch (Throwable e){
            log.error("Activation Fail PAR validation");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        log.info("Greeting card producer bundle is deactivated");
    }
}
