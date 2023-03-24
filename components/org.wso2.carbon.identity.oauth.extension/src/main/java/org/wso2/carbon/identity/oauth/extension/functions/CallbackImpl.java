package org.wso2.carbon.identity.oauth.extension.functions;

import com.google.gson.Gson;
import jdk.nashorn.api.scripting.JSObject;
import jdk.nashorn.api.scripting.ScriptObjectMirror;
import org.wso2.carbon.identity.oauth.extension.engine.JSBasedEngine;

import java.util.HashMap;
import java.util.Map;

import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

public class CallbackImpl implements Callback {

    JSBasedEngine jsBasedEngine;
    public CallbackImpl(JSBasedEngine jsBasedEngine) {
        this.jsBasedEngine = jsBasedEngine;
    }
    @Override
    public void accept(Map<String, Object> eventHandlers, Map<String, Object> data, String outCome) {

        try {
            String source = eventHandlers.get(outCome).toString();
            Gson gson = new Gson();
            String json = gson.toJson(data);
            ScriptObjectMirror obj = (ScriptObjectMirror) jsBasedEngine.getEngine().eval("(" + json + ")");

            apply(jsBasedEngine.getEngine(), source, obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Object apply(ScriptEngine scriptEngine, String source, Object... params) {

        Compilable compilable = (Compilable) scriptEngine;
        try {
            CompiledScript compiledScript = compilable.compile(source);
            JSObject jsObject = (JSObject) compiledScript.eval();
            if (jsObject instanceof ScriptObjectMirror) {
                ScriptObjectMirror scriptObjectMirror = (ScriptObjectMirror) jsObject;
                if (!scriptObjectMirror.isFunction()) {

                }
                return scriptObjectMirror.call(null, params);
            }
        } catch (ScriptException e) {

        }
        return null;
    }
}
