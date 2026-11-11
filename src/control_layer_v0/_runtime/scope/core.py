"""Host-created grants, field bindings and recovery budgets."""
from __future__ import annotations
import copy
import json
import time
from dataclasses import dataclass, field
from typing import Callable

def normalize(value):
    return ' '.join(str(value).casefold().split())

@dataclass(frozen=True)
class FieldBinding:
    argument: str
    object_id: str
    source_field: str
    value: str

@dataclass(frozen=True)
class Grant:
    tool: str
    exact_arguments: dict
    bindings: tuple[FieldBinding, ...] = ()
    reminders: dict = field(default_factory=dict)

class ControlLayer:

    def __init__(self, grants, judge: Callable | None=None):
        self.grants = copy.deepcopy(tuple(grants))
        self.judge = judge
        self.audit = []
        self.judgments = []

    def check(self, tool, arguments, evidence=None):
        evidence = evidence or {}
        for grant in self.grants:
            if tool != grant.tool:
                continue
            fields = set(grant.exact_arguments) | {b.argument for b in grant.bindings} | set(grant.reminders)
            if set(arguments) != fields:
                continue
            if any((arguments[key] != value for key, value in grant.exact_arguments.items())):
                continue
            if any((evidence.get((b.object_id, b.source_field)) != b.value or normalize(arguments[b.argument]) != normalize(b.value) for b in grant.bindings)):
                continue
            if any((normalize(arguments[key]) not in {f'reminder about {normalize(subject)}.', f'a reminder for {normalize(subject)}.', f'{normalize(subject)} reminder', f'please remember {normalize(subject)}.'} for key, subject in grant.reminders.items())):
                continue
            for key, subject in grant.reminders.items():
                if self.judge is None:
                    continue
                state = {'source_evidence': {'subject': subject}, 'proposed_text': arguments[key]}
                started = time.perf_counter()
                error = None
                try:
                    choice = self.judge('transformation', state)
                    if choice not in ('yes', 'no', 'uncertain'):
                        raise ValueError('Invalid judge label')
                except (ValueError, TimeoutError, OSError) as exc:
                    choice = 'uncertain'
                    error = str(exc)
                self.judgments.append({'kind': 'transformation', 'state': state, 'choice': choice, 'seconds': time.perf_counter() - started, 'error': error})
                if choice != 'yes':
                    return (False, 'semantic_support_missing')
            return (True, 'trusted_contract_matches')
        return (False, 'no_matching_trusted_contract')

    def execute(self, tool, arguments, executor, evidence=None):
        arguments = copy.deepcopy(arguments)
        allowed, reason = self.check(tool, arguments, copy.deepcopy(evidence))
        event = {'tool': tool, 'arguments': arguments, 'allowed': allowed, 'reason': reason, 'executed': False, 'succeeded': False}
        self.audit.append(event)
        if not allowed:
            raise PermissionError(reason)
        event['executed'] = True
        result = executor(tool, copy.deepcopy(arguments))
        event['succeeded'] = True
        return result

class RecoveryBudget:

    def __init__(self, limit=2):
        if limit < 0:
            raise ValueError('Negative recovery budget')
        self.limit = limit
        self.used = 0
        self.seen = set()
        self.history = []

    def next(self, tool, arguments, reason, evidence_version):
        signature = json.dumps([tool, arguments, reason, evidence_version], sort_keys=True)
        action = 'stop' if self.used >= self.limit or signature in self.seen else 'repair'
        self.seen.add(signature)
        self.used += int(action == 'repair')
        self.history.append({'tool': tool, 'arguments': copy.deepcopy(arguments), 'reason': reason, 'evidence_version': evidence_version, 'action': action, 'remaining': self.limit - self.used})
        return action
