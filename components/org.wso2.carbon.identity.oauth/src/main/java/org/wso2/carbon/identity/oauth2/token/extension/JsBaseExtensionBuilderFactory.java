package org.wso2.carbon.identity.oauth2.token.extension;

import javax.script.ScriptEngine;

public interface JsBaseExtensionBuilderFactory {

    void init();

    ScriptEngine createEngine();

    Object executeScript(ScriptEngine engine, String script);

}
