"""Actor-only native execution and application-state observation."""
from collections.abc import Mapping
import copy
import hashlib
import json
import time

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()

def snapshot(env):
    return json.loads(env.model_dump_json())

class RuntimeObservation:

    def __init__(self, is_actor, password_checker=None):
        self.is_actor = is_actor
        self.password_checker = password_checker
        self.events = []
        self.first_state = None
        self.final_state = None
        self.non_actor_calls = 0
        self.actor_queries = 0

    def _before(self, env):
        state = snapshot(env)
        if self.first_state is None:
            self.first_state = copy.deepcopy(state)
        return state

    def function(self, original, runtime, env, function, kwargs, raise_on_error=False):
        if not self.is_actor(runtime):
            self.non_actor_calls += 1
            return original(runtime, env, function, kwargs, raise_on_error=raise_on_error)
        before = self._before(env)
        arguments = copy.deepcopy(dict(kwargs)) if isinstance(kwargs, Mapping) else {'invalid_argument_type': type(kwargs).__name__}
        password_ok = None
        if function == 'update_password' and 'password' in arguments:
            scope = getattr(runtime, '_trusted_user_scope', None)
            if scope is not None and self.password_checker is not None:
                password_ok = self.password_checker(scope.prompt, dict(kwargs))
            arguments['password'] = {'redacted_sha256': fingerprint(arguments['password'])}
        event = {'tool': function, 'arguments': arguments, 'success': False, 'state_changed': False, 'before_sha256': fingerprint(before), 'runtime_role': 'actor', 'independent_payment_approvals': getattr(runtime, '_verified_payments', None)}
        if password_ok is not None:
            event['trusted_password_authorized'] = password_ok
        tick = time.perf_counter()
        try:
            result = original(runtime, env, function, kwargs, raise_on_error=raise_on_error)
            event['success'] = result[1] is None
            event['error_type'] = str(result[1]).split(':', 1)[0][:80] if result[1] is not None else None
            return result
        except Exception as exc:
            event['error_type'] = type(exc).__name__
            raise
        finally:
            self.final_state = snapshot(env)
            event['after_sha256'] = fingerprint(self.final_state)
            event['state_changed'] = event['before_sha256'] != event['after_sha256']
            event['seconds'] = time.perf_counter() - tick
            self.events.append(event)

    def query(self, original, pipeline, request, runtime, *args, **kwargs):
        actor = self.is_actor(runtime)
        env = args[0] if args else kwargs.get('env')
        if actor and env is not None:
            self.actor_queries += 1
            self._before(env)
        try:
            result = original(pipeline, request, runtime, *args, **kwargs)
            if actor:
                self.final_state = snapshot(result[2])
            return result
        except Exception as exc:
            if actor:
                final_env = getattr(exc, 'task_environment', env)
                if final_env is not None:
                    self.final_state = snapshot(final_env)
            raise

    def report(self):
        return {'events': self.events, 'initial_state': self.first_state, 'final_state': self.final_state, 'state_capture_available': self.first_state is not None, 'non_actor_calls_excluded': self.non_actor_calls, 'actor_queries': self.actor_queries}
