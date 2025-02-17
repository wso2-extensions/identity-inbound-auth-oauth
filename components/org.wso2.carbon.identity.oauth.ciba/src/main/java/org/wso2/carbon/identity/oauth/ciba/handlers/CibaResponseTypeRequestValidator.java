package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.wso2.carbon.identity.oauth2.authz.validators.AbstractResponseTypeRequestValidator;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.RESPONSE_TYPE_VALUE;

/**
 * Ciba response type request validator.
 */
public class CibaResponseTypeRequestValidator extends AbstractResponseTypeRequestValidator {

    public CibaResponseTypeRequestValidator() {

    }

    @Override
    public String getResponseType() {

        return RESPONSE_TYPE_VALUE;
    }
}
