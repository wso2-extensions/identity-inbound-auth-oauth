package org.wso2.carbon.identity.oauth.scope.endpoint.dto;

import java.util.ArrayList;
import java.util.List;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeBindingDTO;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class ScopeToUpdateDTO  {
  
  
  @NotNull
  private String displayName = null;
  
  
  private String description = null;
  
  
  private List<String> bindings = new ArrayList<String>();
  
  
  private List<ScopeBindingDTO> scopeBindings = new ArrayList<ScopeBindingDTO>();

  
  /**
   **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty("displayName")
  public String getDisplayName() {
    return displayName;
  }
  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  
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

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("scopeBindings")
  public List<ScopeBindingDTO> getScopeBindings() {
    return scopeBindings;
  }
  public void setScopeBindings(List<ScopeBindingDTO> scopeBindings) {
    this.scopeBindings = scopeBindings;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ScopeToUpdateDTO {\n");
    
    sb.append("  displayName: ").append(displayName).append("\n");
    sb.append("  description: ").append(description).append("\n");
    sb.append("  bindings: ").append(bindings).append("\n");
    sb.append("  scopeBindings: ").append(scopeBindings).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
