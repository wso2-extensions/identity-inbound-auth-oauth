package org.wso2.carbon.identity.oauth.dcr.model;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

/**
 * DCR Request data for Read an OAuth application
 */
public class ReadRequest extends IdentityRequest {

  private String consumerKey;
  private String userId;

  public ReadRequest(ReadRequestBuilder builder) throws FrameworkClientException {
    super(builder);
    this.consumerKey = builder.consumerKey;
    this.userId = builder.userId;
  }

  public String getConsumerKey() {
    return consumerKey;
  }

  public String getUserId() {
    return userId;
  }

  public static class ReadRequestBuilder extends IdentityRequestBuilder{

    private String consumerKey;
    private String userId;

    public void setConsumerKey(String consumerKey) {
      this.consumerKey = consumerKey;
    }

    public void setUserId(String userId) {
      this.userId = userId;
    }

    @Override
    public ReadRequest build() throws FrameworkClientException {
      return new ReadRequest(this);
    }
  }
}
