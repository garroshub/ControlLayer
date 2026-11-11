"""Policy and taint enforcement primitives."""
import json
import re
try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

class Rule:

    def __init__(self, tool, effect, conditions=None, priority=0, fallback='error'):
        assert effect in ('allow', 'forbid')
        assert fallback in ('error', 'terminate', 'ask_user')
        self.tool = tool
        self.effect = effect
        self.conditions = conditions or {}
        self.priority = priority
        self.fallback = fallback

    def to_dict(self):
        return {'tool': self.tool, 'effect': self.effect, 'conditions': self.conditions, 'priority': self.priority, 'fallback': self.fallback}

    @classmethod
    def from_dict(cls, d):
        return cls(d['tool'], d['effect'], d.get('conditions', {}), d.get('priority', 0), d.get('fallback', 'error'))

def _check_schema(value, schema):
    if not isinstance(schema, dict):
        return False
    if 'const' in schema and value != schema['const']:
        return False
    if 'enum' in schema and value not in schema['enum']:
        return False
    t = schema.get('type')
    if t == 'string' and (not isinstance(value, str)):
        return False
    if t == 'integer' and (not isinstance(value, int)):
        return False
    if t == 'number' and (not isinstance(value, (int, float))):
        return False
    if t == 'boolean' and (not isinstance(value, bool)):
        return False
    if 'pattern' in schema:
        if not isinstance(value, str):
            return False
        if re.search(schema['pattern'], value) is None:
            return False
    if 'minimum' in schema and (not (isinstance(value, (int, float)) and value >= schema['minimum'])):
        return False
    if 'maximum' in schema and (not (isinstance(value, (int, float)) and value <= schema['maximum'])):
        return False
    if 'minLength' in schema and (not (isinstance(value, str) and len(value) >= schema['minLength'])):
        return False
    if 'maxLength' in schema and (not (isinstance(value, str) and len(value) <= schema['maxLength'])):
        return False
    return True

def rule_matches(rule, args):
    for arg, schema in rule.conditions.items():
        if arg not in args:
            return False
        if not _check_schema(args[arg], schema):
            return False
    return True

def enforce(rules, tool, args):
    relevant = [r for r in rules if r.tool == tool]
    relevant.sort(key=lambda r: (-r.priority, 0 if r.effect == 'forbid' else 1))
    try:
        for rule in relevant:
            if rule_matches(rule, args):
                if rule.effect == 'allow':
                    return (True, rule, None)
                return (False, rule, rule.fallback)
    except Exception:
        return (False, None, 'error')
    return (False, None, 'error')

def _value_sort(v):
    if isinstance(v, bool):
        return 'boolean'
    if isinstance(v, int):
        return 'integer'
    if isinstance(v, float):
        return 'number'
    if isinstance(v, str):
        return 'string'
    return None

def _arg_type(rules, arg):
    for r in rules:
        schema = r.conditions.get(arg)
        if isinstance(schema, dict):
            t = schema.get('type')
            if t in ('string', 'integer', 'number', 'boolean'):
                return t
            if 'enum' in schema and schema['enum']:
                s = _value_sort(schema['enum'][0])
                if s is not None:
                    return s
            if 'const' in schema:
                s = _value_sort(schema['const'])
                if s is not None:
                    return s
            if 'pattern' in schema:
                return 'string'
            if 'minimum' in schema or 'maximum' in schema:
                return 'integer'
    return 'string'

def _canonical_sort(schema):
    if not isinstance(schema, dict):
        return None
    t = schema.get('type')
    if t in ('string', 'integer', 'number', 'boolean'):
        return t
    if 'enum' in schema and schema['enum']:
        sorts = {_value_sort(v) for v in schema['enum']}
        sorts.discard(None)
        if len(sorts) == 1:
            return sorts.pop()
        return 'conflict'
    if 'const' in schema:
        return _value_sort(schema['const'])
    if 'pattern' in schema:
        return 'string'
    if 'minimum' in schema or 'maximum' in schema:
        return 'integer'
    return None

def _sort_conflict(rules, tool):
    args = set()
    for r in rules:
        if r.tool == tool:
            args.update(r.conditions.keys())
    for a in args:
        sorts = set()
        for r in rules:
            if r.tool == tool:
                s = _canonical_sort(r.conditions.get(a))
                if s is not None:
                    sorts.add(s)
        if len(sorts) > 1 or 'conflict' in sorts:
            return True
    return False

def _schema_to_z3(schema, var, bool_vars):
    parts = []
    if 'const' in schema:
        if isinstance(schema['const'], (list, dict)):
            key = ('const_json', json.dumps(schema['const'], sort_keys=True, default=str))
            if key not in bool_vars:
                bool_vars[key] = z3.Bool('c_%d' % len(bool_vars))
            parts.append(bool_vars[key])
        else:
            parts.append(var == schema['const'])
    if 'enum' in schema:
        if any((isinstance(v, (list, dict)) for v in schema['enum'])):
            key = ('enum_json', json.dumps(schema['enum'], sort_keys=True, default=str))
            if key not in bool_vars:
                bool_vars[key] = z3.Bool('e_%d' % len(bool_vars))
            parts.append(bool_vars[key])
        else:
            parts.append(z3.Or([var == v for v in schema['enum']]))
    if 'pattern' in schema:
        key = ('pattern', schema['pattern'])
        if key not in bool_vars:
            bool_vars[key] = z3.Bool('pat_%d' % len(bool_vars))
        parts.append(bool_vars[key])
    if 'minimum' in schema:
        parts.append(var >= schema['minimum'])
    if 'maximum' in schema:
        parts.append(var <= schema['maximum'])
    if 'minLength' in schema:
        parts.append(z3.Length(var) >= schema['minLength'])
    if 'maxLength' in schema:
        parts.append(z3.Length(var) <= schema['maxLength'])
    if not parts:
        return z3.BoolVal(True)
    return z3.And(parts)

def _allowed_formula(rules, tool, var_map, present_map, bool_vars):
    allows = [r for r in rules if r.tool == tool and r.effect == 'allow']
    forbids = [r for r in rules if r.tool == tool and r.effect == 'forbid']
    disjuncts = []
    for allow in allows:
        parts = [present_map[a] for a in allow.conditions]
        parts += [_schema_to_z3(s, var_map[a], bool_vars) for a, s in allow.conditions.items()]
        cond = z3.And(parts) if parts else z3.BoolVal(True)
        blockers = []
        for f in forbids:
            if f.priority >= allow.priority:
                fparts = [present_map[a] for a in f.conditions]
                fparts += [_schema_to_z3(s, var_map[a], bool_vars) for a, s in f.conditions.items()]
                blockers.append(z3.And(fparts) if fparts else z3.BoolVal(True))
        if blockers:
            cond = z3.And(cond, z3.Not(z3.Or(blockers)))
        disjuncts.append(cond)
    if not disjuncts:
        return z3.BoolVal(False)
    return z3.Or(disjuncts)

def is_narrowing(old_rules, new_rules):
    if not HAS_Z3:
        old_set = {(r.tool, r.effect, json.dumps(r.conditions, sort_keys=True)) for r in old_rules}
        new_set = {(r.tool, r.effect, json.dumps(r.conditions, sort_keys=True)) for r in new_rules}
        return new_set.issubset(old_set)
    tools = {r.tool for r in old_rules} | {r.tool for r in new_rules}
    for tool in tools:
        try:
            if _sort_conflict(old_rules + new_rules, tool):
                return False
            args = set()
            for r in old_rules + new_rules:
                if r.tool == tool:
                    args.update(r.conditions.keys())
            var_map = {}
            present_map = {}
            for a in args:
                t = _arg_type(old_rules + new_rules, a)
                if t == 'integer' or t == 'number':
                    var_map[a] = z3.Int('arg_%s' % a)
                elif t == 'boolean':
                    var_map[a] = z3.Bool('arg_%s' % a)
                else:
                    var_map[a] = z3.String('arg_%s' % a)
                present_map[a] = z3.Bool('present_%s' % a)
            bool_vars = {}
            old_f = _allowed_formula(old_rules, tool, var_map, present_map, bool_vars)
            new_f = _allowed_formula(new_rules, tool, var_map, present_map, bool_vars)
            solver = z3.Solver()
            solver.add(z3.And(new_f, z3.Not(old_f)))
            if solver.check() != z3.unsat:
                return False
        except Exception:
            return False
    return True

def apply_update(current_rules, proposed_rules, origin, approver):
    if is_narrowing(current_rules, proposed_rules):
        return (proposed_rules, 'narrowing_auto', 'Z3: new allowed set is subset of old')
    if approver(origin, proposed_rules):
        return (proposed_rules, 'expansion_approved', 'expansion approved by approver')
    return (current_rules, 'expansion_denied', 'expansion denied by approver')
