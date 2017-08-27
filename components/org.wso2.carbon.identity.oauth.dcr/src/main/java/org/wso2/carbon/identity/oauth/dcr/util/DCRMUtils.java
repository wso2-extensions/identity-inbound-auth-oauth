/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;

import java.net.URI;
import java.net.URISyntaxException;

public class DCRMUtils {

    private static final Log log = LogFactory.getLog(DCRMUtils.class);

    public static boolean isRedirectionUriValid(String redirectUri) {

        if (log.isDebugEnabled()) {
            log.debug("Validating uri: " + redirectUri);
        }
        
        if (IdentityUtil.isBlank(redirectUri)) {
            log.error("The redirection URI is either null or blank.");
            return false;
        }

        try {
            //Trying to parse the URI, just to verify the URI syntax is correct.
            URI redirectURL = new URI(redirectUri);
        } catch (URISyntaxException e) {
            String errorMessage = "The redirection URI: " + redirectUri + ", is not a valid URI.";
            log.error(errorMessage, e);
            return false;
        }
        return true;
    }

    public static DCRMServerException generateServerException(DCRMConstants.ErrorMessages
                                                                                     error, String data, Throwable e)
            throws DCRMServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                DCRMServerException.class, error.getCode(), errorDescription, e);
    }

    public static DCRMServerException generateServerException(DCRMConstants.ErrorMessages error, String data)
            throws DCRMServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                DCRMServerException.class, error.getCode(), errorDescription);
    }

    public static DCRMClientException generateClientException(DCRMConstants.ErrorMessages error,
                                                              String data,
                                                              Throwable e)
            throws DCRMClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(DCRMClientException.class, error.getCode(), errorDescription, e);
    }

    public static DCRMClientException generateClientException(DCRMConstants.ErrorMessages error,
                                                              String data)
            throws DCRMClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(DCRMClientException.class, error.getCode(), errorDescription);
    }
}
