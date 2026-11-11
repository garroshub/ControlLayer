"""AgentDojo dispatch bridge with policy and taint gates."""
from __future__ import annotations
import json
from collections.abc import Mapping
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from control_layer.progent import Rule, enforce
from control_layer.enhanced import strict_rules
from control_layer.enhanced3 import CumulativeTaint, semantic_flag
from control_layer.enhanced5 import SemanticCumulative, StagedStore, TrackedReturns, endpoint_taint_check, grant_flag, is_endpoint, ref_flag

class GuardedRuntime(FunctionsRuntime):

    def __init__(self, functions, policy_only=False):
        from agentdojo.functions_runtime import FunctionsRuntime
        FunctionsRuntime.__init__(self, functions)
        names = list(self.functions)
        self.rules = strict_rules([Rule(name, 'allow') for name in names])
        self.read_tools = frozenset((name for name in names if name.startswith(('get_', 'list_', 'search_', 'view_', 'read_', 'browse_', 'check_', 'find_', 'retrieve_')) or name in ('cart_total', 'view_available_discounts')))
        self.policy_only = policy_only
        self.trusted_literals = set()
        self.tracked = TrackedReturns()
        self.staged = StagedStore()
        self.cumulative = CumulativeTaint()
        self.semantic_cumulative = SemanticCumulative()
        self.audit = []

    def _untrusted_args(self, args: Mapping) -> dict:
        return {key: value for key, value in args.items() if not (isinstance(value, str) and (key, value) in self.trusted_literals)}

    @staticmethod
    def _has_nested(value):
        if isinstance(value, FunctionCall):
            return True
        if isinstance(value, Mapping):
            return any((GuardedRuntime._has_nested(v) for v in value.values()))
        if isinstance(value, (list, tuple)):
            return any((GuardedRuntime._has_nested(v) for v in value))
        return False

    def decide(self, function: str, args: Mapping) -> tuple[bool, str]:
        try:
            allowed, _rule, _fallback = enforce(self.rules, function, dict(args))
        except Exception:
            return (False, 'invalid_policy_arguments')
        if not allowed:
            return (False, 'frozen_policy')
        if self.policy_only or not is_endpoint(function):
            return (True, 'allowed')
        task_origin = False
        if grant_flag(function, task_origin):
            return (False, 'grant')
        untrusted = self._untrusted_args(args)
        blocked, _reason = endpoint_taint_check(self.tracked, untrusted, task_origin)
        if blocked:
            return (False, 'taint')
        flagged, _reason = ref_flag(untrusted)
        if flagged:
            return (False, 'ref')
        flagged, _reason = semantic_flag(self.tracked.texts(), untrusted)
        if flagged:
            return (False, 'semantic')
        if self.semantic_cumulative.projected_block(self.tracked.texts(), untrusted):
            return (False, 'semantic_cumulative')
        if self.cumulative.fraction_after(self.tracked.texts(), untrusted) >= 0.5:
            return (False, 'cumulative')
        return (True, 'allowed')

    def run_function(self, env, function, kwargs, raise_on_error=False):
        if not isinstance(kwargs, Mapping) or self._has_nested(kwargs):
            return self._block(function, 'nested_or_invalid_call', raise_on_error)
        if function not in self.functions:
            return self._block(function, 'unknown_tool', raise_on_error)
        try:
            args = self.functions[function].parameters.model_validate(dict(kwargs)).model_dump()
        except Exception:
            return self._block(function, 'validation_failed', raise_on_error)
        allowed, reason = self.decide(function, args)
        if not allowed:
            return self._block(function, reason, raise_on_error)
        result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
        if error is None:
            if not self.policy_only and is_endpoint(function):
                untrusted = self._untrusted_args(args)
                self.semantic_cumulative.add(self.tracked.texts(), untrusted)
                self.cumulative.add(self.tracked.texts(), untrusted)
            if function in self.read_tools:
                serialized = json.dumps(result.model_dump() if hasattr(result, 'model_dump') else result, ensure_ascii=False, default=str)
                self.tracked.add_sensitive(serialized)
            if not self.policy_only:
                self.staged.observe_write(function, args)
                serialized = json.dumps(result, ensure_ascii=False, default=str)
                readback = self.staged.observe_read(function, args, serialized)
                if readback is not None:
                    self.tracked.add_readback(readback)
        return (result, error)

    def _block(self, function: str, reason: str, raise_on_error: bool):
        self.audit.append({'tool': function, 'gate': reason})
        if raise_on_error:
            raise PermissionError('ControlLayerDenied: ' + reason)
        return ('', 'ControlLayerDenied: ' + reason)
