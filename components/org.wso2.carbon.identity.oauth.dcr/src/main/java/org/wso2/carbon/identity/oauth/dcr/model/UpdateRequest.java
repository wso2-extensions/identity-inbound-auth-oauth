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

package org.wso2.carbon.identity.oauth.dcr.model;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

public class UpdateRequest extends IdentityRequest {

  private UpdateRequestProfile updateRequestProfile;

  public UpdateRequest(UpdateRequestBuilder builder) throws FrameworkClientException {

    super(builder);
    this.updateRequestProfile = builder.updateRequestProfile;
  }

  public UpdateRequestProfile getUpdateRequestProfile() {
    return updateRequestProfile;
  }

  public static class UpdateRequestBuilder extends IdentityRequestBuilder {

    private UpdateRequestProfile updateRequestProfile;

    public UpdateRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
      super(request, response);
    }

    public UpdateRequestProfile getUpdateRequestProfile() {
      return updateRequestProfile;
    }

    public UpdateRequestBuilder setUpdateRequestProfile(UpdateRequestProfile updateRequestProfile) {
      this.updateRequestProfile = updateRequestProfile;
      return this;
    }

    @Override
    public UpdateRequest build() throws FrameworkRuntimeException, FrameworkClientException{
      return new UpdateRequest(this);
    }
  }

  public static class UpdateRequestConstant extends IdentityRequestConstants {
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_NAME = "client_name";
    public final static String REDIRECT_URIS = "redirect_uris";
    public final static String GRANT_TYPES = "grant_types";

  }
}
