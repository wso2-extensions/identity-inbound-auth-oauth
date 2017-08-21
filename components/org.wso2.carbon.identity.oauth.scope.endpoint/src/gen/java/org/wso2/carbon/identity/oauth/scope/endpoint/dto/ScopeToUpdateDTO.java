package org.wso2.carbon.identity.oauth.scope.endpoint.dto;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class ScopeToUpdateDTO  {
  
  
  
  private String description = null;
  
  
  private List<String> bindings = new ArrayList<String>();

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("description")
  public String getDescription() {
    return description;
  }
  public void setDescription(String description) {
    this.description = description;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("bindings")
  public List<String> getBindings() {
    return bindings;
  }
  public void setBindings(List<String> bindings) {
    this.bindings = bindings;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ScopeToUpdateDTO {\n");
    
    sb.append("  description: ").append(description).append("\n");
    sb.append("  bindings: ").append(bindings).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
