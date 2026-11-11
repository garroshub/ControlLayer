"""Public constructors for the evaluated baseline and control layer."""
from ._runtime.guard import GuardedRuntime
from ._runtime.scope.v3_runtime import CandidateV3Mixin
from ._runtime.scope.checks import judge_state
from ._runtime.channel.channel_runtime import ChannelAuthorizationMixin

class _RulesCallback:

    def __init__(self):
        self.attempts = 0

    def __call__(self, kind, state):
        if self.attempts >= 6:
            raise RuntimeError('Rule-check attempt budget exhausted')
        self.attempts += 1
        return {'choice': judge_state(kind, state)}

class BaselineRuntime(CandidateV3Mixin, GuardedRuntime):
    """R2 rules baseline with the same AgentDojo tool catalog."""

    def __init__(self, functions, trusted_request):
        super().__init__(functions, policy_only=False)
        self.setup_candidate(trusted_request, 'full', judge=_RulesCallback())

class ControlRuntime(ChannelAuthorizationMixin, GuardedRuntime):
    """V0 contracts with source-bound invitation and channel authorization."""

    def __init__(self, functions, trusted_request):
        super().__init__(functions, policy_only=False)
        self.setup_candidate(trusted_request, 'full', judge=_RulesCallback())
