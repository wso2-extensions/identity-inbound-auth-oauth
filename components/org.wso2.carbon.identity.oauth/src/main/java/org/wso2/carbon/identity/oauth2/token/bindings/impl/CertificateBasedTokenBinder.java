/*
 * Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER;

/**
 * This class provides the certificate based token binder implementation.
 */
public class CertificateBasedTokenBinder extends AbstractTokenBinder {

    private static final Log log = LogFactory.getLog(CertificateBasedTokenBinder.class);

    @Override
    public String getBindingType() {

        return CERTIFICATE_BASED_TOKEN_BINDER;
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        Set<String> supportedGrantTypes = OAuthServerConfiguration.getInstance().getSupportedGrantTypes().keySet();
        return supportedGrantTypes.stream().collect(Collectors.toList());
    }

    @Override
    public String getDisplayName() {

        return "Certificate Based";
    }

    @Override
    public String getDescription() {

        return "Bind the TLS certificate to the token.";
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        // Returning null as the TLS certificate cannot be obtained in this flow.
        return null;
    }

    @Override
    public String getTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        String cnfValue = generateCnfHashValue(request);
        if (StringUtils.isNotBlank(cnfValue)) {
            return cnfValue;
        } else {
            throw new OAuthSystemException("Error occurred while generating cnf hash value.");
        }
    }

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        return Optional.ofNullable(generateCnfHashValue(oAuth2AccessTokenReqDTO.getHttpServletRequestWrapper()));
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue) {

        // Not required.
    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {

        // Not required.
    }

    @Override
    public boolean isValidTokenBinding(Object request, String bindingReference) {

        String cnfValue = generateCnfHashValue((HttpServletRequest) request);
        if (StringUtils.isNotBlank(cnfValue)) {
            return StringUtils.equals(bindingReference, OAuth2Util.getTokenBindingReference(cnfValue));
        }
        return false;
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        String refreshToken = oAuth2AccessTokenReqDTO.getRefreshToken();
        try {
            Optional<TokenBinding> tokenBinding = OAuthTokenPersistenceFactory.getInstance().getTokenBindingMgtDAO()
                    .getBindingFromRefreshToken(refreshToken, OAuth2Util.isHashEnabled());
            String cnfValue = generateCnfHashValue(oAuth2AccessTokenReqDTO.getHttpServletRequestWrapper());

            if (tokenBinding.isPresent() && CERTIFICATE_BASED_TOKEN_BINDER.equals(tokenBinding.get().getBindingType())
                    && StringUtils.isNotBlank(cnfValue)) {
                return StringUtils.equals(cnfValue, tokenBinding.get().getBindingValue()) &&
                        StringUtils.equals(bindingReference, tokenBinding.get().getBindingReference());
            }
            return false;
        } catch (IdentityOAuth2Exception e) {
            return false;
        }
    }

    private String generateCnfHashValue(HttpServletRequest request) {

        Base64URL certThumbprint;
        X509Certificate certificate = null;
        String headerName = Optional.ofNullable(IdentityUtil.getProperty(OAuthConstants.MTLS_AUTH_HEADER))
                .orElse(OAuthConstants.CONFIG_NOT_FOUND);

        String certificateInHeader = request.getHeader(headerName);
        Object certObject = Optional.ofNullable(request.getAttribute(OAuthConstants.JAVAX_SERVLET_REQUEST_CERTIFICATE))
                .orElse(null);

        if (StringUtils.isNotBlank(certificateInHeader)) {
            try {
                certificate = parseCertificate(certificateInHeader);
            } catch (CertificateException e) {
                /* Adding a debug log as these errors cannot be thrown as per the TokenBinder interface implementation.
                   But null checks have been performed where these methods are being executed. */
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while extracting the certificate from the request header.", e);
                }
                return null;
            }
        } else if (certObject instanceof X509Certificate) {
            certificate = (X509Certificate) certObject;
        } else if (certObject instanceof X509Certificate[] && ((X509Certificate[]) certObject).length > 0) {
            List<X509Certificate> x509Certificates = Arrays.asList((X509Certificate[]) certObject);
            certificate = x509Certificates.get(0);
        }

        if (certificate != null) {
            certThumbprint = X509CertUtils.computeSHA256Thumbprint(certificate);
            return certThumbprint.toString();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("TLS certificate not found in the request.");
            }
            return null;
        }
    }

    private X509Certificate parseCertificate(String content) throws CertificateException {

        byte[] decodedContent = java.util.Base64.getDecoder().decode(StringUtils.trim(content
                .replaceAll(OAuthConstants.BEGIN_CERT, StringUtils.EMPTY)
                .replaceAll(OAuthConstants.END_CERT, StringUtils.EMPTY)
        ));

        return (X509Certificate) CertificateFactory.getInstance(Constants.X509)
                .generateCertificate(new ByteArrayInputStream(decodedContent));
    }
}
