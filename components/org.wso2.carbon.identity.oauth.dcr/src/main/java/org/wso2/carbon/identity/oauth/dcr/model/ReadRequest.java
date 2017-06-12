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

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

/**
 * DCR Request data for Read an OAuth application
 */
public class ReadRequest extends IdentityRequest {

  private String consumerKey;
  private String username;

  public ReadRequest(ReadRequestBuilder builder) throws FrameworkClientException {
    super(builder);
    this.consumerKey = builder.consumerKey;
    this.username = builder.username;
  }

  public String getConsumerKey() {
    return consumerKey;
  }

  public String getUsername() {
    return username;
  }

  public static class ReadRequestBuilder extends IdentityRequestBuilder{

    private String consumerKey;
    private String username;

    public void setConsumerKey(String consumerKey) {
      this.consumerKey = consumerKey;
    }

    public void setUsername(String username) {
      this.username = username;
    }

    @Override
    public ReadRequest build() throws FrameworkClientException {
      return new ReadRequest(this);
    }
  }
}
