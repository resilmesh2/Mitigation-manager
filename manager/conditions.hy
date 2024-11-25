;; All macros here are designed to run within
;; manager.model.Condition.is_met, so keep that in mind
(import hy [gensym])
(import manager.state [get_state_manager])
(import manager.isim [get_isim_manager])

(defmacro prepare-function [#* body]
  "Create an async function wrapping Hy code.

The function will take in the following arguments:
- `parameters: dict`: The object's parameters, as parsed by the `parameters()` method.
- `alert: Alert`: The alert.

Additionally, the function will have access to the following local variables:
- `log: Logger`: The Sanic logger.
- `state_manager: StateManager`: The state manager.
- `isim_manager: IsimManager`: The ISIM manager.

Finally, the function will also have access to all macros defined in `manager.conditions`."
  `(do
     (defn :async result [parameters alert log]
       (import manager.config [log])
       (let [state_manager (hy.I.manager/state.get_state_manager)
             isim_manager (hy.I.manager/isim.get_isim_manager)]
         ~@body))
     result))
