/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.introspection;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.triggerOnIntrospectionExceptionListeners;

/**
 * Rest implementation of OAuth2 introspection endpoint.
 */
@Path("/introspect")
@Consumes({MediaType.APPLICATION_FORM_URLENCODED})
@Produces(MediaType.APPLICATION_JSON)
public class OAuth2IntrospectionEndpoint {

    private static final Log log = LogFactory.getLog(OAuth2IntrospectionEndpoint.class);
    private static final String DEFAULT_TOKEN_TYPE_HINT = "bearer";
    private static final String DEFAULT_TOKEN_TYPE = "Bearer";
    private static final String JWT_TOKEN_TYPE = "JWT";
    private static final String INVALID_INPUT = "Invalid input";

    private static final String ACCESS_TOKEN_HINT = "access_token";

    /**
     * Token introspection endpoint.
     *
     * @param token          access token or refresh token
     * @param tokenTypeHint  hint for the type of the token submitted for introspection
     * @param requiredClaims comma separated list of claims to be returned in JWT
     * @return
     */
    @POST
    public Response introspect(@FormParam("token") String token, @FormParam("token_type_hint") String tokenTypeHint,
                               @FormParam("required_claims") String requiredClaims) {

        OAuth2TokenValidationRequestDTO introspectionRequest;
        OAuth2IntrospectionResponseDTO introspectionResponse;

        if (log.isDebugEnabled()) {
            log.debug("Token type hint: " + tokenTypeHint);
        }

        if (StringUtils.isBlank(token)) {
            introspectionResponse = new OAuth2IntrospectionResponseDTO();
            introspectionResponse.setError(INVALID_INPUT);
            triggerOnIntrospectionExceptionListeners(null, introspectionResponse);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                        .inputParam("token type hint", tokenTypeHint)
                        .inputParam("required claims", requiredClaims)
                        .resultMessage("'token' parameter cannot be empty.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return Response.status(Response.Status.BAD_REQUEST).
                    entity("{\"error\": \"" + INVALID_INPUT + "\"}").build();
        }

        String[] claimsUris = null;
        if (StringUtils.isNotEmpty(requiredClaims)) {
            claimsUris = requiredClaims.split(",");
        } else if (requiredClaims != null && requiredClaims.length() == 0) {
            claimsUris = new String[0];
        }

        // validate the access token against the OAuth2TokenValidationService OSGi service.
        introspectionRequest = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2Token = introspectionRequest.new OAuth2AccessToken();

        if (tokenTypeHint == null || StringUtils.equals(tokenTypeHint, ACCESS_TOKEN_HINT)) {
            oAuth2Token.setTokenType(DEFAULT_TOKEN_TYPE_HINT);
        } else {
            oAuth2Token.setTokenType(tokenTypeHint);
        }

        oAuth2Token.setIdentifier(token);
        introspectionRequest.setAccessToken(oAuth2Token);
        introspectionRequest.setRequiredClaimURIs(claimsUris);

        OAuth2TokenValidationService tokenService = (OAuth2TokenValidationService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2TokenValidationService.class);

        introspectionResponse = tokenService.buildIntrospectionResponse(introspectionRequest);

        if (introspectionResponse.getError() != null) {
            if (log.isDebugEnabled()) {
                log.debug("The error why token is made inactive: " + introspectionResponse.getError());
            }
            return Response.status(Response.Status.OK).entity("{\"active\":false}").build();
        }

        IntrospectionResponseBuilder respBuilder = new IntrospectionResponseBuilder()
                .setActive(introspectionResponse.isActive())
                .setNotBefore(introspectionResponse.getNbf())
                .setScope(introspectionResponse.getScope())
                .setUsername(introspectionResponse.getUsername())
                .setTokenType(introspectionResponse.getTokenType())
                .setClientId(introspectionResponse.getClientId())
                .setIssuedAt(introspectionResponse.getIat())
                .setExpiration(introspectionResponse.getExp())
                .setAuthorizedUserType(introspectionResponse.getAut());

        if (StringUtils.equalsIgnoreCase(introspectionResponse.getTokenType(), JWT_TOKEN_TYPE)) {
            respBuilder.setAudience(introspectionResponse.getAud())
                    .setJwtId(introspectionResponse.getJti())
                    .setSubject(introspectionResponse.getSub())
                    .setTokenType(introspectionResponse.getTokenType())
                    .setIssuer(introspectionResponse.getIss());
        }

        //provide jwt in the response only if claims are requested
        if (introspectionResponse.getUserContext() != null && requiredClaims != null) {
            respBuilder.setTokenString(introspectionResponse.getUserContext());
        }

        // Provide token binding related info which required to validate the token.
        if (StringUtils.isNotBlank(introspectionResponse.getBindingType()) && StringUtils
                .isNotBlank(introspectionResponse.getBindingReference())) {
            String bindingType = introspectionResponse.getBindingType();
            respBuilder.setBindingType(bindingType);
            respBuilder.setBindingReference(introspectionResponse.getBindingReference());
            if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType) &&
                    StringUtils.isNotBlank(introspectionResponse.getCnfBindingValue())) {
                respBuilder.setCnfBindingValue(introspectionResponse.getCnfBindingValue());
            }
        }

        // Retrieve list of registered IntrospectionDataProviders.
        List<Object> introspectionDataProviders = PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiServices(IntrospectionDataProvider.class, null);

        for (Object dataProvider : introspectionDataProviders) {
            if (dataProvider instanceof IntrospectionDataProvider) {

                if (dataProvider instanceof AbstractIdentityHandler &&
                        !((AbstractIdentityHandler) dataProvider).isEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("%s data provider is not enabled.",
                                ((AbstractIdentityHandler) dataProvider).getName()));
                    }
                    continue;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Executing introspection data provider: " + dataProvider.getClass().getName());
                }
                try {
                    respBuilder.setAdditionalData(
                            (((IntrospectionDataProvider) dataProvider).getIntrospectionData(
                                    introspectionRequest, introspectionResponse)));
                } catch (IdentityOAuth2Exception e) {
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                                OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                OAuthConstants.LogConstants.ActionIDs.GENERATE_INTROSPECTION_RESPONSE)
                                .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                                .resultMessage("System error occurred.")
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                    }
                    log.error("Error occurred while processing additional token introspection data.", e);

                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity("{\"error\": \"Error occurred while building the introspection " +
                                    "response.\"}")
                            .build();
                }
            }
        }

        try {
            return Response.ok(respBuilder.build(), MediaType.APPLICATION_JSON).status(Response.Status.OK).build();
        } catch (JSONException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.GENERATE_INTROSPECTION_RESPONSE)
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("System error occurred.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            log.error("Error occurred while building the json response.", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\": \"Error occurred while building the json response.\"}").build();
        }
    }
}
