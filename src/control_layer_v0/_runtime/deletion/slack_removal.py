"""Trusted single-target authorization before native deletion."""
import re
from control_layer_v0._runtime.identity.r6_runtime import CandidateR6Mixin

def removal_target(prompt):
    match = re.fullmatch('(?i:Remove\\s+(?:user\\s+)?)([A-Za-z][A-Za-z0-9_-]*)(?i:\\s+from\\s+(?:the\\s+)?Slack(?:\\s+workspace)?)\\.?', prompt.strip())
    return match.group(1) if match else None

class SlackDeletionSafetyMixin(CandidateR6Mixin):

    def setup_candidate(self, prompt, *args, **kwargs):
        super().setup_candidate(prompt, *args, **kwargs)
        self._slack_removal_target = removal_target(prompt)
        self._slack_removal_checks = []

    def decide(self, function, arguments):
        if function == 'remove_user_from_slack':
            target = self._slack_removal_target
            if target is None or arguments.get('user') != target:
                reason = 'slack_removal_not_authorized'
                self._slack_removal_checks.append({'allowed': False, 'reason': reason})
                return (False, reason)
            allowed, reason = super().decide(function, arguments)
            self._slack_removal_checks.append({'allowed': allowed, 'reason': reason})
            return (allowed, reason)
        return super().decide(function, arguments)

    def candidate_metrics(self):
        result = super().candidate_metrics()
        result['slack_removal_authorization_checks'] = list(self._slack_removal_checks)
        result['slack_removal_scope'] = 'Entire trusted Remove [user] NAME from [the] Slack [workspace] command only; exact case-sensitive single-token target, inherited denials preserved. Quoted, compound, delegated and general natural-language removal unsupported.'
        return result
