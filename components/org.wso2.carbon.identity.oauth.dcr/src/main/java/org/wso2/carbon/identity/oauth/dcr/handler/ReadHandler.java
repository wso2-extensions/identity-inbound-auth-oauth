package org.wso2.carbon.identity.oauth.dcr.handler;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse.IdentityResponseBuilder;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.ReadRequest;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

public class ReadHandler extends AbstractDCRHandler {


  @Override
  public IdentityResponseBuilder handle(DCRMessageContext dcrMessageContext) throws DCRException {

    RegistrationResponse.DCRRegisterResponseBuilder dcrReadResponseBuilder = null;

    ReadRequest readRequest = (ReadRequest) dcrMessageContext.getIdentityRequest();

    RegistrationResponseProfile registrationResponseProfile =
        DCRManagementService.getInstance().readOAuthApplication(readRequest.getConsumerKey(), readRequest.getUserId());

    dcrReadResponseBuilder = new RegistrationResponse.DCRRegisterResponseBuilder();
    dcrReadResponseBuilder.setRegistrationResponseProfile(registrationResponseProfile);

    return dcrReadResponseBuilder;
  }
}
