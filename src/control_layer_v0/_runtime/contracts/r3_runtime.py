"""Protected URL and rescheduling contracts."""
from control_layer_v0._runtime.contracts.url_contract import compile_url_read
from control_layer_v0._runtime.contracts.reschedule_contract import bind_reschedule, parse_reschedule
from control_layer_v0._runtime.scope.v3_runtime import CandidateV3Mixin, v2
from agentdojo.functions_runtime import FunctionsRuntime

class CandidateR3Mixin(CandidateV3Mixin):

    def setup_candidate(self, prompt, *args, **kwargs):
        super().setup_candidate(prompt, *args, **kwargs)
        self._r3_url_contract = compile_url_read(prompt)
        self._r3_url_checks = []
        self._r3_reschedule_intent = parse_reschedule(prompt)
        self._r3_reschedule_consumed = False
        self._r3_reschedule_checks = []
        self._r3_host_reads = []

    def _reschedule_allowed(self, arguments):
        if self._r3_reschedule_intent is None or self._r3_reschedule_consumed:
            return False
        env = self._current_env
        if env is None or 'search_calendar_events' not in self.functions:
            return False
        events, error = FunctionsRuntime.run_function(self, env, 'search_calendar_events', {'query': self._r3_reschedule_intent.title}, raise_on_error=False)
        self._r3_host_reads.append({'tool': 'search_calendar_events', 'succeeded': error is None})
        if error is not None or not isinstance(events, list):
            return False
        rows = [event.model_dump(mode='json') for event in events if hasattr(event, 'model_dump')]
        contract, evidence = bind_reschedule(self._r3_reschedule_intent, rows)
        return contract.check('reschedule_calendar_event', arguments, evidence)[0]

    def decide(self, function, arguments):
        if function == 'reschedule_calendar_event':
            allowed = self._reschedule_allowed(arguments)
            reason = 'r3_reschedule_not_authorized'
            if allowed:
                inherited, inherited_reason = super().decide(function, arguments)
                allowed = inherited or inherited_reason in ('taint', 'semantic', 'safe_replan')
                reason = 'r3_source_bound_reschedule' if allowed else inherited_reason
            self._r3_reschedule_checks.append({'tool': function, 'allowed': allowed, 'reason': reason})
            return (allowed, reason)
        if function != 'get_webpage':
            return super().decide(function, arguments)
        allowed, _ = self._r3_url_contract.check(function, arguments)
        if allowed:
            allowed, reason = v2.CandidateV2Mixin.decide(self, function, arguments)
        else:
            reason = 'r3_web_destination_not_authorized'
        self._r3_url_checks.append({'tool': function, 'allowed': allowed, 'reason': reason})
        return (allowed, reason)

    def run_function(self, env, function, kwargs, raise_on_error=False):
        result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
        if function == 'reschedule_calendar_event' and error is None:
            self._r3_reschedule_consumed = True
        return (result, error)

    def candidate_metrics(self):
        result = super().candidate_metrics()
        result['r3_url_contract_checks'] = list(self._r3_url_checks)
        result['r3_reschedule_contract_checks'] = list(self._r3_reschedule_checks)
        result['r3_host_reads'] = list(self._r3_host_reads)
        result['r3_reschedule_grant_consumed'] = self._r3_reschedule_consumed
        result['r3_inherited_diagnostic_note'] = 'Inherited DENY/SAFE_REPLAN records are intermediate guard evaluations and may be superseded by an exact R3 reschedule contract. Final decisions are in R3 contract checks; actual base-runtime events establish execution.'
        result['r3_url_contract_scope'] = 'Bounded full-command and explicit-URL post-summary forms. Grant is read-only; fetched URLs and arbitrary compound requests cannot mint authority. HTTP redirect transport is not implemented.'
        return result
