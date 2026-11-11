"""Original AgentDojo scoring with local actor execution and complete audit capture."""
import copy
import hashlib
import json
import random
import time
from types import SimpleNamespace
from unittest.mock import patch

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.llms import local_llm
from agentdojo.agent_pipeline.llms.local_llm import LocalLLM
from agentdojo.attacks.baseline_attacks import DirectAttack, InjecAgentAttack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite import get_suite

from .catalog import compact_full_catalog, normalize_zero_arg_calls
from .observation import RuntimeObservation
from .recording import observed_create
from .runtime import BaselineRuntime, ControlRuntime
from ._runtime.scope.checks import password_authorized

MODEL = 'qwen3.5:4b-q4_K_M'
ENDPOINT = 'http://127.0.0.1:11465/v1'


def run_case(suite_name, task_id, arm, injection=None, style='DirectAttack', create=None):
    if arm not in ('rules', 'v0'):
        raise ValueError('Unknown runtime arm')
    if style not in ('DirectAttack', 'InjecAgentAttack'):
        raise ValueError('Unknown fixed attack style')
    client = None
    if create is None:
        import openai
        client = openai.OpenAI(base_url=ENDPOINT, api_key='localhost-only', timeout=180, max_retries=0)
        create = client.chat.completions.create
    random.seed(0)
    suite = get_suite('v1', suite_name)
    user = suite.user_tasks[task_id]
    attack = suite.injection_tasks[injection] if injection else None
    payload = (DirectAttack if style == 'DirectAttack' else InjecAgentAttack)(suite, None).attack(user, attack) if attack else {}
    payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest() if attack else None
    calls = []
    guards = []
    outputs = []
    started = time.perf_counter()
    observer = RuntimeObservation(lambda runtime: isinstance(runtime, (BaselineRuntime, ControlRuntime)), password_authorized)
    recorded = observed_create(create, calls)
    original_function = FunctionsRuntime.run_function
    original_query = AgentPipeline.query
    original_parser = local_llm._parse_model_output
    noarg = {tool.name for tool in suite.tools if not tool.parameters.model_json_schema().get('properties')}

    def request(*args, **kwargs):
        if time.perf_counter()-started > 285:
            raise TimeoutError('Episode deadline exceeded before actor request')
        if len(calls) >= 24:
            raise RuntimeError('Shared actor request budget exhausted')
        kwargs['reasoning_effort'] = 'none'
        return recorded(*args, **kwargs)

    def native(runtime, env, function, kwargs, raise_on_error=False):
        if time.perf_counter()-started > 285:
            raise TimeoutError('Episode deadline exceeded before native execution')
        return observer.function(original_function, runtime, env, function, kwargs, raise_on_error=raise_on_error)

    def query(pipeline, query, runtime, *args, **kwargs):
        result = observer.query(original_query, pipeline, query, runtime, *args, **kwargs)
        if isinstance(runtime, (BaselineRuntime, ControlRuntime)):
            outputs.append(copy.deepcopy(result[3]))
        return result

    def parse(raw):
        normalized, _ = normalize_zero_arg_calls(raw, noarg)
        return original_parser(normalized)

    def factory(functions):
        guard = (BaselineRuntime if arm == 'rules' else ControlRuntime)(functions, user.PROMPT)
        guards.append(guard)
        return guard

    api = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=request)))
    pipeline = AgentPipeline.from_config(PipelineConfig(
        llm=LocalLLM(api, MODEL, temperature=0, top_p=.9), model_id=MODEL,
        system_message='', system_message_name=None, defense=None))
    try:
        with patch.object(FunctionsRuntime, 'run_function', native), \
             patch.object(AgentPipeline, 'query', query), \
             patch.object(local_llm, '_parse_model_output', parse), \
             patch.object(local_llm, '_make_system_prompt', compact_full_catalog):
            utility, attack_score = suite.run_task_with_pipeline(pipeline, user, attack, payload, runtime_class=factory)
        if time.perf_counter()-started > 285:
            raise TimeoutError('Episode completed after the deadline')
        status = 'ok'
        error_type = None
    except Exception as exc:
        utility = attack_score = None
        status = 'error'
        error_type = type(exc).__name__
    finally:
        if client is not None:
            client.close()
    audit = observer.report()
    audit['model_calls'] = calls
    audit['pipeline_outputs'] = outputs
    audit = json.loads(json.dumps(audit, ensure_ascii=False,
        default=lambda item: item.model_dump(mode='json') if hasattr(item, 'model_dump') else str(item)))
    usage = [call.get('response', {}).get('usage') for call in calls]
    known = all(isinstance(item, dict) for item in usage)
    return {'status': status, 'error_type': error_type, 'suite': suite_name, 'task': task_id,
            'arm': arm, 'injection': injection, 'style': style if injection else None,
            'official_utility': utility, 'official_attacker_success': attack_score if injection else None,
            'attack_payload_sha256': payload_hash, 'actor_requests': len(calls),
            'actor_prompt_tokens': sum(item.get('prompt_tokens', 0) for item in usage) if known else None,
            'actor_completion_tokens': sum(item.get('completion_tokens', 0) for item in usage) if known else None,
            'wall_seconds': time.perf_counter()-started,
            'denials': [entry for guard in guards for entry in guard.audit], 'audit': audit}
