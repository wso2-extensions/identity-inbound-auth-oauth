/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.List;

/**
 * @deprecated use {@link DefaultOIDCClaimsCallbackHandler} instead.
 */
@Deprecated
public class SAMLAssertionClaimsCallback extends DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private final static Log log = LogFactory.getLog(SAMLAssertionClaimsCallback.class);

    private static String userAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenReqMessageContext) {
        // reading the token set in the same grant
        Assertion assertion = (Assertion) tokenReqMessageContext.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);
        if (assertion != null) {
            if (log.isDebugEnabled()) {
                log.debug("SAML Assertion found in OAuthTokenReqMessageContext to process claims.");
            }
            addSubjectClaimFromAssertion(jwtClaimsSet, assertion);
            addCustomClaimsFromAssertion(jwtClaimsSet, assertion);
        } else {
            super.handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
        }
    }

    private void addCustomClaimsFromAssertion(JWTClaimsSet jwtClaimsSet, Assertion assertion) {
        List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

        if (CollectionUtils.isNotEmpty(attributeStatementList)) {
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    setAttributeValuesAsClaim(jwtClaimsSet, attribute);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No <AttributeStatement> elements found in the SAML Assertion to process claims.");
            }
        }
    }

    private void addSubjectClaimFromAssertion(JWTClaimsSet jwtClaimsSet, Assertion assertion) {
        // Process <Subject> element in the SAML Assertion and populate subject claim in the JWTClaimSet.
        if (assertion.getSubject() != null) {
            String subject = assertion.getSubject().getNameID().getValue();
            if (log.isDebugEnabled()) {
                log.debug("Setting subject: " + subject + " found in <NameID> of the SAML Assertion.");
            }
            jwtClaimsSet.setSubject(subject);
        }
    }

    private void setAttributeValuesAsClaim(JWTClaimsSet jwtClaimsSet, Attribute attribute) {
        List<XMLObject> values = attribute.getAttributeValues();
        if (values != null) {
            List<String> attributeValues = getNonEmptyAttributeValues(attribute, values);
            if (log.isDebugEnabled()) {
                log.debug("Claim: " + attribute.getName() + " Value: " + attributeValues + " set in the JWTClaimSet.");
            }
            String joinedAttributeString = StringUtils.join(attributeValues, userAttributeSeparator);
            jwtClaimsSet.setClaim(attribute.getName(), joinedAttributeString);
        }
    }

    private List<String> getNonEmptyAttributeValues(Attribute attribute, List<XMLObject> values) {
        String attributeName = attribute.getName();
        List<String> attributeValues = new ArrayList<>();
        // Iterate the attribute values and combine them with the multi attribute separator to
        // form a single claim value.
        // Eg: value1 and value2 = value1,,,value2 (multi-attribute separator = ,,,)
        for (int i = 0; i < values.size(); i++) {
            Element value = attribute.getAttributeValues().get(i).getDOM();
            // Get the attribute value
            String attributeValue = value.getTextContent();
            if (StringUtils.isBlank(attributeValue)) {
                log.warn("Ignoring empty attribute value found for attribute: " + attributeName);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("AttributeValue: " + attributeValue + " found for Attribute: " + attributeName + ".");
                }
                attributeValues.add(attributeValue);
            }
        }
        return attributeValues;
    }
}
