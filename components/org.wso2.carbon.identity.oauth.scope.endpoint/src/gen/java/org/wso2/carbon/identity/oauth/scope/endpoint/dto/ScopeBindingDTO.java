package org.wso2.carbon.identity.oauth.scope.endpoint.dto;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class ScopeBindingDTO  {
  
  
  
  private String bindingType = null;
  
  
  private List<String> binding = new ArrayList<String>();

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("bindingType")
  public String getBindingType() {
    return bindingType;
  }
  public void setBindingType(String bindingType) {
    this.bindingType = bindingType;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("binding")
  public List<String> getBinding() {
    return binding;
  }
  public void setBinding(List<String> binding) {
    this.binding = binding;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ScopeBindingDTO {\n");
    
    sb.append("  bindingType: ").append(bindingType).append("\n");
    sb.append("  binding: ").append(binding).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
