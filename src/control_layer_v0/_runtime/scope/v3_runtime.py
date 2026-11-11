"""Scoped runtime checks and deterministic recovery feedback."""
from __future__ import annotations
import ast
import copy
import hashlib
import json
import time
from control_layer_v0._runtime.scoping.scoped_decision import TrustedTaskScope
from control_layer_v0._runtime.scope.checks import address_fields_match, judge_state, password_authorized, url_authorized
from control_layer_v0._runtime.scope.core import RecoveryBudget
from control_layer_v0._runtime.provenance import runtime as v2

class V3Scope(TrustedTaskScope):

    def __init__(self, prompt, judge=None):
        super().__init__(prompt)
        self.judge = judge
        self.judgments = []

    def supports_calendar(self, arguments):
        if super().supports_calendar(arguments):
            return True
        if self.last_predicate_failures != ['description_not_anchored']:
            return False
        without_description = dict(arguments, description='')
        if not super().supports_calendar(without_description):
            return False
        state = {'trusted_request': self.prompt, 'source_evidence': {'subject': arguments.get('title', '')}, 'proposed_text': arguments.get('description', '')}
        if judge_state('transformation', state) != 'yes':
            return False
        if self.judge is None:
            return True
        tick = time.perf_counter()
        error = None
        try:
            answer = self.judge('transformation', copy.deepcopy(state))
            choice = answer['choice']
            if choice not in ('yes', 'no', 'uncertain'):
                raise ValueError('Invalid judge choice')
        except Exception as exc:
            choice = 'uncertain'
            error = type(exc).__name__
        self.judgments.append({'kind': 'transformation', 'choice': choice, 'error_type': error, 'seconds': time.perf_counter() - tick, 'input_sha256': hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()})
        return choice == 'yes'

    def supports_update_user_info(self, arguments):
        if not super().supports_update_user_info(arguments):
            return False
        fields = {k: v for k, v in arguments.items() if v is not None and str(v).strip()}
        named_files = {q for q in self.quotes if q.endswith('.txt')}
        for read in self.reads:
            if read.function != 'read_file':
                continue
            try:
                args = ast.literal_eval(read.argument_hint)
                if not isinstance(args, dict) or args.get('file_path') not in named_files:
                    continue
                body = json.loads(read.serialized)
            except (ValueError, SyntaxError, TypeError):
                continue
            if isinstance(body, dict):
                body = body.get('content')
            if isinstance(body, str) and address_fields_match(body, fields):
                return True
        return False

class CandidateV3Mixin(v2.CandidateV2Mixin):

    def setup_candidate(self, prompt, variant='full', judge=None, **kwargs):
        super().setup_candidate(prompt, variant, **kwargs)
        self._trusted_user_scope = V3Scope(prompt, judge=judge)
        self._v3_decisions = []
        self._v3_recovery = RecoveryBudget(limit=2)

    def run_function(self, env, function, kwargs, raise_on_error=False):
        result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
        if error is not None:
            action = self._v3_recovery.next(function, copy.deepcopy(kwargs), str(error), 0)
            if action == 'stop':
                message = 'ControlLayerRecoveryExhausted: stop retrying this failed operation; report the unmet constraint.'
                return (result, message)
        return (result, error)

    def decide(self, function, arguments):
        prompt = self._trusted_user_scope.prompt
        reason = None
        if function == 'update_password' and (not password_authorized(prompt, arguments)):
            reason = 'v3_password_not_authorized'
        elif function == 'get_webpage' and (not url_authorized(prompt, str(arguments.get('url', '')))):
            reason = 'v3_web_destination_not_authorized'
        elif function == 'update_user_info' and (not self._trusted_user_scope.supports_update_user_info(arguments)):
            reason = 'v3_complete_address_not_bound'
        if reason:
            self._v3_decisions.append({'tool': function, 'allowed': False, 'reason': reason})
            return (False, reason)
        return super().decide(function, arguments)

    def candidate_metrics(self):
        result = super().candidate_metrics()
        result['v3_decisions'] = self._v3_decisions
        result['v3_judgments'] = self._trusted_user_scope.judgments
        result['v3_recovery_history'] = [{'tool': event['tool'], 'action': event['action'], 'remaining': event['remaining'], 'failure_signature_sha256': hashlib.sha256(json.dumps([event['arguments'], event['reason']], sort_keys=True, default=str).encode()).hexdigest()} for event in self._v3_recovery.history]
        result['v3_recovery_limitations'] = 'Bounded feedback only; hard pipeline termination remains controlled by the existing agent turn budget.'
        result['v3_scope_limitations'] = 'Explicit webpage URLs and named-file address updates; general task parsing and redirect transport enforcement are not implemented.'
        return result
