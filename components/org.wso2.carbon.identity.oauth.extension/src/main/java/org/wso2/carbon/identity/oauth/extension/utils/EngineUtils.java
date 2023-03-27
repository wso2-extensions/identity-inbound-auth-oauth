package org.wso2.carbon.identity.oauth.extension.utils;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;
import org.wso2.carbon.identity.oauth.extension.engine.impl.JSEngineImpl;
import org.wso2.carbon.identity.oauth.extension.engine.impl.OpenJdkJSEngineImpl;

import static org.wso2.carbon.identity.oauth.extension.utils.Constants.JDK_SCRIPT_CLASS_NAME;
import static org.wso2.carbon.identity.oauth.extension.utils.Constants.OPENJDK_SCRIPT_CLASS_NAME;

/**
 * Utility class for JSEngine.
 */
public class EngineUtils {

    /**
     * Get the JSEngine based on the configuration.
     *
     * @return JSEngine instance.
     */
    public static JSEngine getEngineFromConfig() {

        String scriptEngineName = IdentityUtil.getProperty(FrameworkConstants.SCRIPT_ENGINE_CONFIG);
        if (scriptEngineName != null) {
            if (StringUtils.equalsIgnoreCase(FrameworkConstants.OPENJDK_NASHORN, scriptEngineName)) {
                return OpenJdkJSEngineImpl.getInstance();
            }
        }
        return getEngineBasedOnAvailability();
    }

    private static JSEngine getEngineBasedOnAvailability() {

        try {
            Class.forName(OPENJDK_SCRIPT_CLASS_NAME);
            return OpenJdkJSEngineImpl.getInstance();
        } catch (ClassNotFoundException e) {
            try {
                Class.forName(JDK_SCRIPT_CLASS_NAME);
                return JSEngineImpl.getInstance();
            } catch (ClassNotFoundException classNotFoundException) {
                return null;
            }
        }
    }
}
