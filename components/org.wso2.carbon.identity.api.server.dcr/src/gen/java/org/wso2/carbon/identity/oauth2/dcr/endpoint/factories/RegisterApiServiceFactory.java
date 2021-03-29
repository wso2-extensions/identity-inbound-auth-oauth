package org.wso2.carbon.identity.oauth2.dcr.endpoint.factories;

import org.wso2.carbon.identity.oauth2.dcr.endpoint.RegisterApiService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.impl.RegisterApiServiceImpl;

public class RegisterApiServiceFactory {

   private final static RegisterApiService service = new RegisterApiServiceImpl();

   public static RegisterApiService getRegisterApi()
   {
      return service;
   }
}
