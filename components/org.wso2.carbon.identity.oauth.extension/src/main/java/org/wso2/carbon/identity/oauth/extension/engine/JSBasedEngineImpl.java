package org.wso2.carbon.identity.oauth.extension.engine;

import jdk.nashorn.api.scripting.NashornScriptEngineFactory;
import jdk.nashorn.api.scripting.ScriptObjectMirror;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.script.Bindings;
import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

public class JSBasedEngineImpl implements JSBasedEngine {

    private final ScriptEngine engine;
    private static final String[] NASHORN_ARGS = {"--no-java", "--no-deprecation-warning"};
    private static final String REMOVE_FUNCTIONS = "var quit=function(){Log.error('quit function is restricted.')};" +
            "var exit=function(){Log.error('exit function is restricted.')};" +
            "var print=function(){Log.error('print function is restricted.')};" +
            "var echo=function(){Log.error('echo function is restricted.')};" +
            "var readFully=function(){Log.error('readFully function is restricted.')};" +
            "var readLine=function(){Log.error('readLine function is restricted.')};" +
            "var load=function(){Log.error('load function is restricted.')};" +
            "var loadWithNewGlobal=function(){Log.error('loadWithNewGlobal function is restricted.')};" +
            "var $ARG=null;var $ENV=null;var $EXEC=null;" +
            "var $OPTIONS=null;var $OUT=null;var $ERR=null;var $EXIT=null;" +
            "Object.defineProperty(this, 'engine', {});";

    private static final JSBasedEngine jsBasedEngineInstance = new JSBasedEngineImpl();
    private static final Log log = LogFactory.getLog(JSBasedEngineImpl.class);
    public JSBasedEngineImpl() {

        NashornScriptEngineFactory factory = new NashornScriptEngineFactory();
        this.engine = factory.getScriptEngine(NASHORN_ARGS);
    }

    /**
     * Returns an instance to log the javascript errors.
     *
     * @return jsBasedEngineInstance instance.
     */
    public static JSBasedEngine getInstance() {

        return jsBasedEngineInstance;
    }

    @Override
    public JSBasedEngine createEngine() throws ScriptException {

        Bindings bindings = engine.createBindings();
        engine.setBindings(bindings, ScriptContext.GLOBAL_SCOPE);
        engine.setBindings(engine.createBindings(), ScriptContext.ENGINE_SCOPE);
        engine.eval(REMOVE_FUNCTIONS);
        return jsBasedEngineInstance;
    }

    @Override
    public JSBasedEngine addBindings(Map<String, Object> bindings) {

        engine.getBindings(javax.script.ScriptContext.ENGINE_SCOPE).putAll(bindings);
        return jsBasedEngineInstance;
    }

    @Override
    public JSBasedEngine evalScript(String script) throws ScriptException {

        engine.eval(script);
        return jsBasedEngineInstance;
    }

    @Override
    public JSBasedEngine invokeFunction(String functionName, Object... args) throws ScriptException, NoSuchMethodException {

        Object scriptObj = engine.get(functionName);
        if (scriptObj != null && ((ScriptObjectMirror) scriptObj).isFunction()) {
            Invocable invocable = (Invocable) engine;
            invocable.invokeFunction(functionName, args);
            return jsBasedEngineInstance;
        }
        log.debug("Function " + functionName + " is not defined in the script.");
        return jsBasedEngineInstance;
    }

    @Override
    public Map<String, Object> getJSObjects(List<String> objectNames) {

        Map<String, Object> jsObjects = new HashMap<>();
        for (String objectName : objectNames) {
            if(engine.get(objectName) != null) {
                jsObjects.put(objectName, engine.get(objectName));
            }
        }
        return jsObjects;
    }

    @Override
    public ScriptEngine getEngine() {

        return engine;
    }
}
