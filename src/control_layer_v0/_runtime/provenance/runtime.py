"""Typed provenance gates for protected side effects."""
from __future__ import annotations
from collections.abc import Mapping
from control_layer_v0._runtime.scoping.candidate_runtime import CandidateMixin as V1Mixin
from control_layer_v0._runtime.provenance.provenance import TypedProvenance, PAYMENT_TOOLS

class CandidateV2Mixin(V1Mixin):

    def setup_candidate(self, prompt, variant='full', payment_verifier=None, trusted_payment_receipt=None):
        super().setup_candidate(prompt, variant)
        self._v2 = TypedProvenance(prompt)
        self._payment_verifier = payment_verifier
        self._payment_receipt = trusted_payment_receipt
        self._v2_decisions = []
        self._verified_payments = 0

    def decide(self, fn, args):
        if self._candidate_variant == 'validation_only':
            return V1Mixin.decide(self, fn, args)
        original_allowed, original_reason = super(V1Mixin, self).decide(fn, args)
        special = False
        allowed = False
        reason = ''
        if fn in PAYMENT_TOOLS:
            special = True
            if self._payment_verifier is not None:
                allowed = self._payment_verifier.verify(self._payment_receipt, fn, args, self._v2.scope.prompt_sha256)
            reason = 'external_payment_receipt' if allowed else 'payment_requires_independent_signed_confirmation'
            if allowed:
                self._verified_payments += 1
        elif fn == 'share_file':
            special = True
            allowed, reason = self._v2.file_share(self, self._current_env, args)
        elif fn == 'create_calendar_event' and 'same participants' in self._v2.low:
            special = True
            allowed, reason = self._v2.event_participants(self, self._current_env, args)
        elif fn == 'send_channel_message' and 'reply there' in self._v2.low:
            special = True
            allowed, reason = self._v2.channel_reply(self, self._current_env, args)
        elif fn == 'send_direct_message':
            special = True
            allowed, reason = self._v2.exact_direct_target(args)
            if allowed:
                return V1Mixin.decide(self, fn, args)
        if special:
            self._v2_decisions.append({'tool': fn, 'decision': 'ALLOW' if allowed else 'DENY', 'reason': reason})
            if allowed:
                return (True, 'typed_scope_v2')
            return (False, reason)
        return V1Mixin.decide(self, fn, args)

    def run_function(self, env, fn, kwargs, raise_on_error=False):
        result, error = super().run_function(env, fn, kwargs, raise_on_error=raise_on_error)
        if error is None and isinstance(kwargs, Mapping):
            self._v2.note_created(fn, kwargs, result)
        return (result, error)

    def candidate_metrics(self):
        from collections import Counter
        x = super().candidate_metrics()
        x['v2_decisions'] = self._v2_decisions[:100]
        x['v2_actions'] = dict(Counter((y['decision'] for y in self._v2_decisions)))
        x['v2_provenance'] = [dict(tool=z.tool, source_read_tool=z.source_read_tool, source_object_id=z.source_object_id, source_field=z.source_field) for z in self._v2.records[:50]]
        x['v2_verified_read_cost'] = self._v2.read_count
        x['v2_external_payment_approvals'] = self._verified_payments
        return x
