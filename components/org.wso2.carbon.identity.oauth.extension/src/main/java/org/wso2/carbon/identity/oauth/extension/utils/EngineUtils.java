/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.utils;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.graaljs.JsGraalGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;
import org.wso2.carbon.identity.oauth.extension.engine.impl.GraalVMJSEngineImpl;
import org.wso2.carbon.identity.oauth.extension.engine.impl.JSEngineImpl;
import org.wso2.carbon.identity.oauth.extension.engine.impl.OpenJdkJSEngineImpl;

import static org.wso2.carbon.identity.oauth.extension.utils.Constants.GRAALJS_SCRIPTER_CLASS_NAME;
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
            if (StringUtils.equalsIgnoreCase(FrameworkConstants.GRAAL_JS, scriptEngineName)) {
                return OpenJdkJSEngineImpl.getInstance();
            } else if (StringUtils.equalsIgnoreCase(FrameworkConstants.OPENJDK_NASHORN, scriptEngineName)) {
                return OpenJdkJSEngineImpl.getInstance();
            }
        }
        return getEngineBasedOnAvailability();
    }

    private static JSEngine getEngineBasedOnAvailability() {

        try {
            Class.forName(GRAALJS_SCRIPTER_CLASS_NAME);
            return new GraalVMJSEngineImpl();
        } catch (ClassNotFoundException e) {
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
}
