/*
 *  Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.client.attestation.filter;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.impl.MetadataMap;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.client.attestation.mgt.services.ClientAttestationService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MultivaluedMap;

import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.ATTESTATION_HEADER;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.CLIENT_ATTESTATION_CONTEXT;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.CLIENT_ID;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.DIRECT;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.RESPONSE_MODE;

/**
 * This interceptor, ClientAttestationProxy, is responsible for handling incoming JAX-RS messages related to
 * client attestation. It checks for attestation information in the HTTP request and validates it to establish
 * the client's authenticity and context.
 *
 * It operates at the "PRE_INVOKE" phase, allowing it to access the message body and parameters.
 *
 * The interceptor performs the following tasks:
 * 1. Extracts the HttpServletRequest from the incoming JAX-RS message.
 * 2. Retrieves the attestation header from the HTTP request.
 * 3. Extracts content parameters from the message.
 * 4. Validates attestation for API-based authentication requests.
 * 5. Sets the client attestation context in the HTTP request for further processing.
 *
 */
public class ClientAttestationProxy extends AbstractPhaseInterceptor<Message> {

    private static final Log LOG = LogFactory.getLog(ClientAttestationProxy.class);
    private static final String HTTP_REQUEST = "HTTP.REQUEST";

    private ClientAttestationService clientAttestationService;


    public ClientAttestationProxy() {

        // Since the body is consumed and body parameters are available at this phase we use "PRE_INVOKE"
        super(Phase.PRE_INVOKE);
    }

    public ClientAttestationService getClientAttestationService() {

        return clientAttestationService;
    }

    public void setClientAttestationService(ClientAttestationService clientAttestationService) {

        this.clientAttestationService = clientAttestationService;
    }

    /**
     * Handles the incoming JAX-RS message for the purpose of OAuth2 client authentication.
     * It extracts the HttpServletRequest from the incoming message, retrieves the attestation header
     * from the HTTP request, and extracts content parameters from the message.
     *
     * If the incoming request is determined to be an API-based authentication request, it proceeds to:
     * 1. Validate the attestation header to establish client authenticity and obtain a client
     *    attestation context.
     * 2. Set the client attestation context in the HTTP request for further processing.
     *
     * @param message JAX-RS message
     */
    @Override
    public void handleMessage(Message message) {
        // Extract the HttpServletRequest from the incoming message
        HttpServletRequest request = (HttpServletRequest) message.get(HTTP_REQUEST);
        // Retrieve the attestation header from the HTTP request
        String attestationHeader = request.getHeader(ATTESTATION_HEADER);
        // Extract the content parameters from the message
        MultivaluedMap<String, String> bodyContentParams = getContentParams(message);

        // Check if this is an API-based authentication request
        if (isApiBasedAuthnRequest(bodyContentParams)) {
            // Validate the attestation header and obtain client attestation context
            ClientAttestationContext clientAttestationContext =
                    clientAttestationService.validateAttestation(attestationHeader,
                    getClientId(bodyContentParams), getTenantDomain());
            // Set the client attestation context in the HTTP request
            setContextToRequest(request, clientAttestationContext);
        }
    }

    private String getClientId(MultivaluedMap<String, String> bodyContentParams) {

        // Retrieve the client ID from the MultivaluedMap
        return bodyContentParams.getFirst(CLIENT_ID);
    }

    /**
     * Checks if the authentication request is API-based, based on the provided request parameters.
     *
     * @param bodyContentParams Multivalued map containing request parameters.
     * @return True if the request uses API-based authentication; false otherwise.
     */
    private boolean isApiBasedAuthnRequest(MultivaluedMap<String, String> bodyContentParams) {
        // Retrieve the 'response_mode' parameter from the request.
        String responseMode = bodyContentParams.getFirst(RESPONSE_MODE);

        // Check if 'response_mode' is not null and equals 'DIRECT' (case-insensitive).
        if (responseMode != null) {
            return responseMode.equalsIgnoreCase(DIRECT);
        } else {
            // If 'response_mode' is not provided, it's not an API-based authentication request.
            return false;
        }
    }

    /**
     * Retrieve body content as a MultivaluedMap.
     *
     * @param message JAX-RS incoming message
     * @return Body parameters of the incoming request message
     */
    protected MultivaluedMap<String, String> getContentParams(Message message) {
        MultivaluedMap<String, String> contentMap = new MetadataMap<>();
        List<Object> contentList = message.getContent(List.class);
        contentList.stream()
                .filter(item -> item instanceof MetadataMap)
                .map(item -> (MetadataMap<String, String>) item)
                .forEach(metadataMap -> contentMap.putAll(metadataMap));
        return contentMap;
    }

    private String getTenantDomain() {

        return Optional.ofNullable(IdentityTenantUtil.getTenantDomainFromContext())
                .filter(StringUtils::isNotBlank)
                .orElseGet(() -> PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
    }

    /**
     * Sets the Client Attestation context to the HttpServletRequest's attributes.
     *
     * @param request                   The HttpServletRequest to which the context should be added.
     * @param clientAttestationContext  The Client Attestation context to be added to the request.
     */
    private void setContextToRequest(HttpServletRequest request, ClientAttestationContext clientAttestationContext) {
        // Check if DEBUG logging is enabled before logging
        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting Client Attestation context to request");
        }
        // Add the Client Attestation context as an attribute to the HttpServletRequest
        request.setAttribute(CLIENT_ATTESTATION_CONTEXT, clientAttestationContext);
    }
}
