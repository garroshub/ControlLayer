"""Policy and taint enforcement primitives."""
import json
from .progent import is_narrowing
SENSITIVE_TOOLS = {'send_email', 'send_slack_msg', 'send_invite', 'send_summary', 'transfer', 'delete_file', 'publish'}
SENSITIVE_SOURCES = {'read_email', 'read_file', 'read_transactions', 'read_calendar'}
RECIPIENT_ARGS = {'to', 'recipient', 'target'}

def lint_policy(rules):
    findings = []
    for rule in rules:
        if rule.tool in SENSITIVE_TOOLS and rule.effect == 'allow':
            for arg, schema in rule.conditions.items():
                if isinstance(schema, dict) and 'pattern' in schema:
                    findings.append({'tool': rule.tool, 'arg': arg, 'issue': 'broad_pattern_on_sensitive_tool', 'detail': 'pattern allow on sensitive tool %s arg %s' % (rule.tool, arg)})
    return findings

def strict_rules(rules):
    kept = []
    for rule in rules:
        if rule.tool in SENSITIVE_TOOLS and rule.effect == 'allow':
            if any((isinstance(s, dict) and 'pattern' in s for s in rule.conditions.values())):
                continue
        kept.append(rule)
    return kept

class TaintContext:

    def __init__(self):
        self.sensitive_returns = []

    def observe(self, tool, tool_return):
        if tool in SENSITIVE_SOURCES and isinstance(tool_return, str):
            self.sensitive_returns.append(tool_return)

    def check(self, tool, args):
        if tool not in SENSITIVE_TOOLS:
            return (False, 'not a sensitive sink')
        for arg, value in args.items():
            if not isinstance(value, str):
                continue
            for ret in self.sensitive_returns:
                if value == ret:
                    return (True, "verbatim copy of sensitive read in arg '%s'" % arg)
                if len(ret) >= 10 and ret in value:
                    return (True, "contains sensitive read text in arg '%s'" % arg)
                if len(value) >= 10 and value in ret:
                    return (True, "arg '%s' copied from tool return" % arg)
        return (False, 'taint check passed')

def added_allowances(old_rules, new_rules):
    old_set = {(r.tool, r.effect, json.dumps(r.conditions, sort_keys=True)) for r in old_rules}
    added = []
    for r in new_rules:
        key = (r.tool, r.effect, json.dumps(r.conditions, sort_keys=True))
        if r.effect == 'allow' and key not in old_set:
            added.append(r)
    return added

def added_recipients(added):
    values = []
    has_pattern = False
    for rule in added:
        for arg, schema in rule.conditions.items():
            if arg in RECIPIENT_ARGS and isinstance(schema, dict):
                if 'const' in schema:
                    values.append(schema['const'])
                elif 'enum' in schema:
                    values.extend(schema['enum'])
                elif 'pattern' in schema:
                    has_pattern = True
    return (values, has_pattern)
COMM_SINKS = {'send_email', 'send_slack_msg', 'send_invite', 'send_summary'}

def tiered_approve(old_rules, new_rules, origin, address_book):
    added = added_allowances(old_rules, new_rules)
    if any((r.tool in SENSITIVE_TOOLS for r in added)):
        if any((r.tool not in COMM_SINKS for r in added if r.tool in SENSITIVE_TOOLS)):
            return False
        values, has_pattern = added_recipients(added)
        if has_pattern:
            return False
        return all((v in address_book for v in values))
    return origin == 'task'

def enhanced_apply_update(current_rules, proposed_rules, origin, address_book, mode):
    if is_narrowing(current_rules, proposed_rules):
        return (proposed_rules, 'narrowing_auto', 'Z3 narrowing')
    if mode == 'auto_deny':
        return (current_rules, 'expansion_denied', 'auto_deny')
    if tiered_approve(current_rules, proposed_rules, origin, address_book):
        return (proposed_rules, 'expansion_approved', 'tiered approval passed')
    return (current_rules, 'expansion_denied', 'tiered approval failed')
