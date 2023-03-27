package org.wso2.carbon.identity.oauth.extension.engine;

import java.util.List;
import java.util.Map;

import javax.script.ScriptEngine;
import javax.script.ScriptException;

/**
 * This interface is used to evaluate the javascripts.
 */
public interface JSEngine {

    JSEngine createEngine() throws ScriptException;

    ScriptEngine getEngine() throws ScriptException;

    JSEngine addBindings(Map<String, Object> bindings);

    JSEngine evalScript(String script) throws ScriptException;

    JSEngine invokeFunction(String functionName, Object... args) throws ScriptException, NoSuchMethodException;

    Map<String, Object> getJSObjects(List<String> bindings);
}
