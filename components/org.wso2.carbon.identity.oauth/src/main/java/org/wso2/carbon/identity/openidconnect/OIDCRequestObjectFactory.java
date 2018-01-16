/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

/**
 * According to the OIDC spec requestObject is passed as a query param value of request/request_uri parameters. This is
 * associated with OIDC authorization request. This class is used to select the corresponding builder class and build the
 * request object according to the parameter.
 */
public class OIDCRequestObjectFactory {

    private static final Log log = LogFactory.getLog(OIDCRequestObjectFactory.class);
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    private static final String REQUEST_PARAM_VALUE_BUILDER = "request_param_value_builder";
    private static final String REQUEST_URI_PARAM_VALUE_BUILDER = "request_uri_param_value_builder";

    /**
     * Fetch and invoke the matched request builder class based on the identity.xml configurations.
     * Build and validate the Request Object extracted from request information
     *
     * @param oauthRequest authorization request
     * @throws RequestObjectException
     */
    public static void buildRequestObject(OAuthAuthzRequest oauthRequest,
                                          OAuth2Parameters oAuth2Parameters,
                                          RequestObject requestObject) throws RequestObjectException {
        /*
          So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
          parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
          The values for these parameters MUST match those in the Request Object, if present
         */
        RequestObjectBuilder requestObjectBuilder;
        if (isRequestParameter(oauthRequest)) {
            requestObjectBuilder = getRequestObjectBuilder(REQUEST_PARAM_VALUE_BUILDER);
            buildRequestObject(oauthRequest, oAuth2Parameters, requestObject, requestObjectBuilder, REQUEST);
        } else if (isRequestUri(oauthRequest)) {
            requestObjectBuilder = getRequestObjectBuilder(REQUEST_URI_PARAM_VALUE_BUILDER);
            buildRequestObject(oauthRequest, oAuth2Parameters, requestObject, requestObjectBuilder,
                    REQUEST_URI);

        } else {
            // Unsupported request object type.
            return;
        }
        RequestObjectValidator requestObjectValidator = OAuthServerConfiguration.getInstance()
                .getRequestObjectValidator();
        if (requestObject.isSigned()) {
            if (!requestObjectValidator.validateSignature(requestObject, oAuth2Parameters.getClientId())) {
                throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Request Object signature verification failed.");

            }
        }
        if (!requestObjectValidator.validateRequestObject(requestObject, oAuth2Parameters)) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid Request Object parameters " +
                    "found  in the request.");

        }
    }

    private static void buildRequestObject(OAuthAuthzRequest oauthRequest, OAuth2Parameters oAuth2Parameters,
                                           RequestObject requestObject, RequestObjectBuilder requestObjectBuilder,
                                           String requestObjParam) throws RequestObjectException {
        String error = "Unable to build the OIDC Request Object from:";
        if (requestObjectBuilder != null) {
            requestObjectBuilder.buildRequestObject(oauthRequest.getParam(requestObjParam), oAuth2Parameters,
                    requestObject);
            if (log.isDebugEnabled()) {
                log.debug("Request Object extracted from the request: " + oauthRequest.getParam(requestObjParam));
            }
        } else {
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, error + requestObjParam);
        }
    }


    private static RequestObjectBuilder getRequestObjectBuilder(String requestParamValueBuilder) {
        return OAuthServerConfiguration.getInstance().getRequestObjectBuilders().get(requestParamValueBuilder);
    }

    private static boolean isRequestUri(OAuthAuthzRequest oAuthAuthzRequest) {
        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST_URI));
    }

    private static boolean isRequestParameter(OAuthAuthzRequest oAuthAuthzRequest) {
        return StringUtils.isNotBlank(oAuthAuthzRequest.getParam(REQUEST));
    }
}
