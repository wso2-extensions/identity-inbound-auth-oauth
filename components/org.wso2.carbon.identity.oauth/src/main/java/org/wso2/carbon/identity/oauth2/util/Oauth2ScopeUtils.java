/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;

public class Oauth2ScopeUtils {

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                error, String data)
            throws IdentityOAuth2ScopeServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), errorDescription);
    }

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                     error, String data, Throwable e)
            throws IdentityOAuth2ScopeServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), errorDescription, e);
    }

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                   error, Throwable e)
            throws IdentityOAuth2ScopeServerException {

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), error.getMessage(), e);
    }

    public static IdentityOAuth2ScopeClientException generateClientException(Oauth2ScopeConstants.ErrorMessages
                                                                                error, String data)
            throws IdentityOAuth2ScopeClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(IdentityOAuth2ScopeClientException.class, error.getCode(), errorDescription);
    }

    public static IdentityOAuth2ScopeClientException generateClientException(Oauth2ScopeConstants.ErrorMessages error,
                                                                             String data,
                                                                             Throwable e)
            throws IdentityOAuth2ScopeClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(IdentityOAuth2ScopeClientException.class, error.getCode(), errorDescription, e);
    }

    public static int getTenantID() {
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }
}
