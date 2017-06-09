/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.util;

import org.wso2.carbon.identity.oauth.dcr.DCRRuntimeException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.handler.RegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.handler.UnRegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;

import java.util.List;

public class HandlerManager {

    private static volatile HandlerManager instance = new HandlerManager();

    private HandlerManager() {
    }

    public static HandlerManager getInstance() {
        return instance;
    }

    public RegistrationHandler getRegistrationHandler(DCRMessageContext dcrMessageContext) {
        List<RegistrationHandler> registrationHandlers =
                DCRDataHolder.getInstance().getRegistrationHandlerList();
        if (registrationHandlers != null && registrationHandlers.size() > 0) {
            return registrationHandlers.get(0);
        }
        throw DCRRuntimeException.error("Cannot find AuthenticationHandler to handle this request");
    }

    public UnRegistrationHandler getUnRegistrationHandler(DCRMessageContext dcrMessageContext) {
        List<UnRegistrationHandler> unRegistrationHandlers =
                DCRDataHolder.getInstance().getUnRegistrationHandlerList();
        if (unRegistrationHandlers != null && unRegistrationHandlers.size() > 0) {
            return unRegistrationHandlers.get(0);
        }
        throw DCRRuntimeException.error("Cannot find AuthenticationHandler to handle this request");
    }

}
