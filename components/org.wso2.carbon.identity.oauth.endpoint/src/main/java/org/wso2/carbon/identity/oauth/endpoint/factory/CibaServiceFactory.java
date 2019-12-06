/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthService;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;

/**
 * This class is used to register CibaAuthService as a factory bean.
 */
public class CibaServiceFactory extends AbstractFactoryBean<CibaAuthServiceImpl> {

    private CibaAuthServiceImpl cibaAuthService;

    @Override
    public Class<CibaAuthServiceImpl> getObjectType() {

        return CibaAuthServiceImpl.class;
    }

    @Override
    protected CibaAuthServiceImpl createInstance() throws Exception {

        if (cibaAuthService != null) {
            return cibaAuthService;
        } else {
            CibaAuthServiceImpl cibaAuthService = (CibaAuthServiceImpl)
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().
                            getOSGiService(CibaAuthService.class, null);
            if (cibaAuthService != null) {
                this.cibaAuthService = cibaAuthService;
            }
            return cibaAuthService;
        }
    }
}
