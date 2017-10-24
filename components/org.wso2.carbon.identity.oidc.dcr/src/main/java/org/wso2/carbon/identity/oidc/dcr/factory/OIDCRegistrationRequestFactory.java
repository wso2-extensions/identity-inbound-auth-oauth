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

package org.wso2.carbon.identity.oidc.dcr.factory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.oauth.dcr.factory.RegistrationRequestFactory;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequestProfile;
import org.wso2.carbon.identity.oidc.dcr.util.OIDCDCRConstants;

import java.util.regex.Matcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;

/**
 * OIDCRegistrationRequestFactory build the request for DCR Registry Request.
 */
public class OIDCRegistrationRequestFactory extends RegistrationRequestFactory {

    private static Log log = LogFactory.getLog(OIDCRegistrationRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws
            FrameworkRuntimeException {

        boolean canHandle = false;
        if (request != null) {
            Matcher matcher = OIDCDCRConstants.OIDC_DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.matches() && HttpMethod.POST.equals(request.getMethod())) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by OIDCRegistrationRequestFactory.");
        }
        return canHandle;
    }


    @Override
    public OIDCRegistrationRequest.OIDCRegistrationRequestBuilder create(HttpServletRequest request,
                                                                         HttpServletResponse response)
            throws FrameworkClientException {

        if (log.isDebugEnabled()) {
            log.debug("create RegistrationRequest.RegistrationRequestBuilder by OIDCRegistrationRequestFactory.");
        }
        OIDCRegistrationRequest.OIDCRegistrationRequestBuilder registerRequestBuilder = new
                OIDCRegistrationRequest.OIDCRegistrationRequestBuilder(request, response);


        create(registerRequestBuilder, request, response);

        return registerRequestBuilder;

    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws FrameworkClientException {

        OIDCRegistrationRequest.OIDCRegistrationRequestBuilder registerRequestBuilder = null;
        if (builder instanceof OIDCRegistrationRequest.OIDCRegistrationRequestBuilder) {
            registerRequestBuilder =
                    (OIDCRegistrationRequest.OIDCRegistrationRequestBuilder) builder;
            OIDCRegistrationRequestProfile oidcRegistrationRequestProfile = new OIDCRegistrationRequestProfile();
            registerRequestBuilder.setRegistrationRequestProfile(oidcRegistrationRequestProfile);

            super.create(registerRequestBuilder, request, response);
        } else {
            // This else part will not be reached from application logic.
            log.error("Can't create registerRequestBuilder. builder is not an instance of " +
                    "OIDCRegistrationRequest.OIDCRegistrationRequestBuilder");
        }
    }

    @Override
    protected void parseJson(JSONObject jsonData, RegistrationRequest.RegistrationRequestBuilder requestBuilder)
            throws FrameworkClientException {
        super.parseJson(jsonData, requestBuilder);
        RegistrationRequestProfile registrationRequestProfile = requestBuilder.getRegistrationRequestProfile();
        if (registrationRequestProfile instanceof OIDCRegistrationRequestProfile) {
            OIDCRegistrationRequestProfile oidcRegistrationRequestProfile = (OIDCRegistrationRequestProfile)
                    registrationRequestProfile;
            oidcRegistrationRequestProfile.setSectorIdentifierUri((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.SECTOR_IDENTIFIER_URI));
            oidcRegistrationRequestProfile.setSubjectType((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.SUBJECT_TYPE));
            oidcRegistrationRequestProfile.setIdTokenSignedResponseAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.ID_TOKEN_SIGNED_RESPONSE_ALG));
            oidcRegistrationRequestProfile.setIdTokenEncryptedResponseAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ALG));
            oidcRegistrationRequestProfile.setIdTokenEncryptedResponseEnc((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ENC));
            oidcRegistrationRequestProfile.setUserinfoSignedResponseAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.USERINFO_SIGNED_RESPONSE_ALG));
            oidcRegistrationRequestProfile.setUserinfoencryptedResponseAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.USERINFO_ENCRYPTED_RESPONSE_ALG));
            oidcRegistrationRequestProfile.setUserinfoEncryptedResponseEnc((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.USERINFO_ENCRYPTED_RESPONSE_ENC));
            oidcRegistrationRequestProfile.setRequestObjectSigningAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.REQUEST_OBJECT_SIGNING_ALG));
            oidcRegistrationRequestProfile.setRequestObjectEncryptionAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.REQUEST_OBJECT_ENCRYPTION_ALG));
            oidcRegistrationRequestProfile.setRequestObjectEncryptionEnc((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.REQUEST_OBJECT_ENCRYPTION_ENC));
            oidcRegistrationRequestProfile.setTokenEndpointAuthSigningAlg((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.TOKEN_ENDPOINT_AUTH_SIGNING_ALG));
            oidcRegistrationRequestProfile.setDefaultMaxAge((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.DEFAULT_MAX_AGE));
            oidcRegistrationRequestProfile.setRequireAuthTime((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.REQUIRE_AUTH_TIME));
            oidcRegistrationRequestProfile.setDefaultAcrValues((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.DEFAULT_ACR_VALUES));
            oidcRegistrationRequestProfile.setInitiateLoginUri((String) jsonData.get(OIDCRegistrationRequest
                    .OIDCRegistrationRequestConstants.INITIATE_LOGIN_URI));
            Object obj = jsonData.get(OIDCRegistrationRequest.OIDCRegistrationRequestConstants.REQUEST_URIS);
            if (obj instanceof JSONArray) {
                JSONArray requestURIs = (JSONArray) obj;
                for (Object requestURI : requestURIs) {
                    oidcRegistrationRequestProfile.getRequestUris().add(requestURI.toString());
                }
            } else if (obj instanceof String) {
                oidcRegistrationRequestProfile.getRequestUris().add((String) obj);
            }
        }
    }
}
