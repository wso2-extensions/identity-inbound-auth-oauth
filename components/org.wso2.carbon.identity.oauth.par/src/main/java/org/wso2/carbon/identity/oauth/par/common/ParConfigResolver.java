/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.common;

import org.apache.axiom.om.OMElement;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;

import javax.xml.namespace.QName;

public class ParConfigResolver {

    private static final String PAR = "PAR";
    private static final IdentityConfigParser configParser = IdentityConfigParser.getInstance();
    private static final OMElement oauthElem = configParser.getConfigElement("OAuth");

    private static final OMElement parConfig = oauthElem.getFirstChildWithName(new QName(IdentityCoreConstants.
            IDENTITY_DEFAULT_NAMESPACE, PAR));

    private static long EXPIRES_IN_VALUE;

    /**
     * Get the value of expires_in from Par Configuration in identity.xml, if not found, return default value.
     *
     * @return value of expires_in
     */
    public static long getExpiresInValue() {
        if (parConfig.getAttributeValue(new QName(PAR)) != null) {
            EXPIRES_IN_VALUE = Long.parseLong(parConfig.getAttributeValue(new QName(PAR)));
        } else {
            EXPIRES_IN_VALUE = ParConstants.EXPIRES_IN_DEFAULT_VALUE;
        }
        return EXPIRES_IN_VALUE;
    }
}
