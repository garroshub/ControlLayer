"""One-use source-bound invitation authorization."""
import re
from control_layer_v0._runtime.invitation.invitation import compile_invitation, bind_invitation
from control_layer_v0._runtime.contracts.r3_runtime import CandidateR3Mixin
from control_layer_v0._runtime.scope.v3_runtime import v2
from agentdojo.functions_runtime import FunctionsRuntime

def membership_requested(prompt):
    outside_quotes = re.sub('(["\']).*?\\1', '', prompt)
    if re.search("\\b(?:do not|don't|never)\\s+(?:add|join)\\b", outside_quotes, re.I):
        return False
    return bool(re.search('\\b(?:add|join)\\b', outside_quotes, re.I) and re.search('\\bchannels?\\b', outside_quotes, re.I))

class CandidateR5Mixin(CandidateR3Mixin):

    def setup_candidate(self, prompt, *args, **kwargs):
        super().setup_candidate(prompt, *args, **kwargs)
        self._r5_invitation = compile_invitation(prompt)
        self._r5_invitation_consumed = False
        self._r5_invitation_checks = []
        self._r5_host_reads = 0

    def decide(self, function, arguments):
        if function == 'add_user_to_channel' and (not membership_requested(self._trusted_user_scope.prompt)):
            return (False, 'r5_channel_membership_not_requested')
        intent = self._r5_invitation
        if function == 'get_webpage' and intent is not None:
            if intent.read_contract().check(function, arguments)[0]:
                return v2.CandidateV2Mixin.decide(self, function, arguments)
            return (False, 'r5_invitation_source_not_authorized')
        if function != 'invite_user_to_slack':
            return super().decide(function, arguments)
        allowed = False
        if intent is not None and (not self._r5_invitation_consumed) and (self._current_env is not None):
            source_allowed, _ = v2.CandidateV2Mixin.decide(self, 'get_webpage', {'url': intent.url})
            if not source_allowed:
                self._r5_invitation_checks.append({'tool': function, 'allowed': False, 'reason': 'r5_host_source_read_denied'})
                return (False, 'r5_host_source_read_denied')
            self._r5_host_reads += 1
            source, error = FunctionsRuntime.run_function(self, self._current_env, 'get_webpage', {'url': intent.url}, raise_on_error=False)
            contract = bind_invitation(intent, source) if error is None else None
            allowed = bool(contract and contract.check(function, arguments)[0])
        reason = 'r5_invitation_not_bound'
        if allowed:
            inherited, inherited_reason = super().decide(function, arguments)
            allowed = inherited or inherited_reason in ('taint', 'semantic', 'safe_replan')
            reason = 'r5_source_bound_invitation' if allowed else inherited_reason
        self._r5_invitation_checks.append({'tool': function, 'allowed': allowed, 'reason': reason})
        return (allowed, reason)

    def run_function(self, env, function, kwargs, raise_on_error=False):
        value, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
        if function == 'invite_user_to_slack' and error is None:
            self._r5_invitation_consumed = True
        return (value, error)

    def candidate_metrics(self):
        result = super().candidate_metrics()
        result.update(r5_invitation_consumed=self._r5_invitation_consumed, r5_invitation_checks=list(self._r5_invitation_checks), r5_host_source_reads=self._r5_host_reads, r5_scope='Bounded named invitation only. Host source parsing is not website ownership/content integrity or email delivery verification. Channel floor can only deny; inherited gates remain.')
        return result
