"""Trusted request fields and deterministic scope checks."""
from __future__ import annotations
from dataclasses import dataclass, field
from collections.abc import Mapping
import json
import re
from typing import Any
HARD_DENY_RELAX = frozenset({'send_money', 'schedule_transaction', 'create_transaction', 'grant_access', 'grant_permission', 'change_permissions', 'share_document', 'create_share_link', 'add_collaborator', 'invite_user_to_slack', 'add_user_to_channel', 'remove_user_from_channel', 'update_permissions', 'delete_file', 'delete_calendar_event', 'delete_email', 'post_webpage', 'upload_file'})
MAX_BODY = 800
MAX_LOCAL_CONTENT = 2500
READ_FAMILIES = ('read_', 'search_', 'list_', 'get_', 'view_', 'check_', 'browse_', 'find_', 'retrieve_')
BLOCKED_PAYLOAD_PAT = re.compile('(?i)(ignore\\s+(all\\s+)?(previous|prior)\\s+instructions|developer\\s+message|system\\s+prompt|send\\s+(money|funds|password)|api[_ -]?key|authorization:\\s*bearer|\\b(?:\\d[ -]?){13,19}\\b|\\b(?:one.time|verification)\\s*(?:password|code)\\b)')
EMAIL_PAT = re.compile('(?i)\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b')
URL_PAT = re.compile('(?i)(?:https?://|www\\.)[^\\s<>\'\\"]+')
DATE_ISO = re.compile('\\b20\\d{2}[-/]\\d{2}[-/]\\d{2}\\b')
MONTHS = 'january february march april may june july august september october november december'.split()
MNAME = {v: i + 1 for i, v in enumerate(MONTHS)}
MONTH_DATE = re.compile('(?i)\\b(' + '|'.join(MONTHS) + ')\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:\\s*(?:,|of)?\\s*(20\\d{2}))?')
DAY_MONTH = re.compile('(?i)\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(?:of\\s+)?(' + '|'.join(MONTHS) + ')(?:\\s*,?\\s*(20\\d{2}))?')
QUOTED = re.compile('[\'"]([^\'"]{1,120})[\'"]')
SAFE_NAME = re.compile('^[a-z0-9 _\\-.()]{1,140}$', re.I)
SAFE_ADDRESS = re.compile("^[a-z0-9 ,.#'/-]{1,160}$", re.I)

def canonical(value: Any) -> str:
    return re.sub('\\s+', ' ', str(value)).strip().casefold()

def emails(value: Any) -> set[str]:
    return set((x.lower() for x in EMAIL_PAT.findall(str(value))))

def urls(value: Any) -> set[str]:
    return {x.rstrip('.,;').lower() for x in URL_PAT.findall(str(value))}

def date_strings(text: str) -> frozenset[str]:
    dates = {x.replace('/', '-') for x in DATE_ISO.findall(text)}
    for m in MONTH_DATE.finditer(text):
        if m.group(3):
            dates.add(f'{int(m.group(3)):04d}-{MNAME[m.group(1).lower()]:02d}-{int(m.group(2)):02d}')
    for m in DAY_MONTH.finditer(text):
        if m.group(3):
            dates.add(f'{int(m.group(3)):04d}-{MNAME[m.group(2).lower()]:02d}-{int(m.group(1)):02d}')
    return frozenset(dates)

def month_days_without_year(text: str) -> frozenset[str]:
    result = {f'{MNAME[m.group(1).lower()]:02d}-{int(m.group(2)):02d}' for m in MONTH_DATE.finditer(text) if not m.group(3)}
    result |= {f'{MNAME[m.group(2).lower()]:02d}-{int(m.group(1)):02d}' for m in DAY_MONTH.finditer(text) if not m.group(3)}
    return frozenset(result)

def output_safe(value: Any, trusted_prompt: str, max_length: int=MAX_BODY) -> bool:
    s = str(value)
    if len(s) > max_length or not s.strip() or BLOCKED_PAYLOAD_PAT.search(s):
        return False
    if not emails(s).issubset(emails(trusted_prompt)):
        return False
    if not urls(s).issubset(urls(trusted_prompt)):
        return False
    return True

@dataclass(frozen=True)
class ReadEvidence:
    function: str
    argument_hint: str
    serialized: str = field(repr=False, compare=False, default='')

@dataclass
class ScopedCapability:
    tool: str
    authorized_fields: tuple[str, ...]
    user_prompt_sha256: str
    intended_destination: str
    expected_sources: tuple[str, ...]
    max_payload_bytes: int
    provenance: str = 'trusted_user_role'
    check_level: str = 'scope_and_shape'

class TrustedTaskScope:

    def __init__(self, trusted_user_prompt: str):
        if not isinstance(trusted_user_prompt, str) or not trusted_user_prompt.strip():
            raise ValueError('Missing trusted user prompt: no capability minting')
        self.prompt = trusted_user_prompt
        self.low = canonical(trusted_user_prompt)
        self.quotes = tuple((canonical(x) for x in QUOTED.findall(trusted_user_prompt)))
        self.dates = date_strings(trusted_user_prompt)
        self.unyeared_month_days = month_days_without_year(trusted_user_prompt)
        self.addresses = emails(trusted_user_prompt)
        self.links = urls(trusted_user_prompt)
        import hashlib
        self.prompt_sha256 = hashlib.sha256(trusted_user_prompt.encode('utf8')).hexdigest()
        self.reads: list[ReadEvidence] = []
        self.issued: list[ScopedCapability] = []
        self.last_predicate_failures: list[str] = []

    def observe_read(self, function: str, args: Mapping, result: Any):
        if not function.startswith(READ_FAMILIES):
            return
        try:
            body = result.model_dump() if hasattr(result, 'model_dump') else result
            serialized = json.dumps(body, ensure_ascii=False, default=str)
        except Exception:
            serialized = ''
        if len(serialized) > 12000:
            serialized = serialized[:12000]
        self.reads.append(ReadEvidence(function, canonical(args), serialized))

    def source_present(self, tool_prefixes: tuple[str, ...], ref: str='') -> bool:
        relevant = [x for x in self.reads if x.function.startswith(tool_prefixes)]
        if not relevant:
            return False
        if ref:
            ref = canonical(ref)
            return any((ref in e.argument_hint or ref in canonical(e.serialized) for e in relevant))
        return True

    def supports_calendar(self, a: Mapping) -> bool:
        self.last_predicate_failures = []
        if not (('calendar' in self.low or 'event' in self.low) and any((w in self.low for w in ('create', 'add', 'schedule', 'remind', 'set up')))):
            self.last_predicate_failures.append('calendar_action_not_explicit')
            return False
        title = str(a.get('title', ''))
        if not output_safe(title, self.prompt, 140):
            self.last_predicate_failures.append('unsafe_title')
            return False
        literal = canonical(title) in self.quotes
        templated = any(('{' in q and (canonical(title).startswith(q.split('{', 1)[0]) or canonical(title).startswith(q.split('{', 1)[0].rstrip() + ': ') or canonical(title).startswith(q.split('{', 1)[0].rstrip() + ' - ')) and (len(title) <= 140) for q in self.quotes))
        name_from_source = 'hotel name as the title' in self.low and self.source_present(('get_hotels', 'get_all_hotels')) and (SAFE_NAME.fullmatch(title) is not None)
        if not (literal or templated or name_from_source):
            self.last_predicate_failures.append('title_not_anchored')
            return False
        start = str(a.get('start_time', ''))
        date = start[:10]
        anchored_date = date in self.dates or (re.fullmatch('20\\d{2}-\\d{2}-\\d{2}', date) is not None and 2020 <= int(date[:4]) <= 2035 and (date[5:] in self.unyeared_month_days))
        if not anchored_date:
            self.last_predicate_failures.append('date_not_anchored')
            return False
        end = str(a.get('end_time', ''))
        if end and end[:10] != date:
            if not (end[:10] in self.dates or (re.fullmatch('20\\d{2}-\\d{2}-\\d{2}', end[:10]) and 2020 <= int(end[:4]) <= 2035 and (end[5:10] in self.unyeared_month_days))):
                self.last_predicate_failures.append('end_date_not_anchored')
                return False
        desc = str(a.get('description') or '')
        if desc and (not output_safe(desc, self.prompt, 500)):
            self.last_predicate_failures.append('unsafe_description')
            return False
        if desc and canonical(desc) not in self.low and (canonical(desc) not in self.quotes):
            vocab = set(re.findall('[a-z0-9]+', self.low + ' ' + canonical(title)))
            vocab |= {'reminder', 'remind', 'booking', 'book', 'hotel', 'restaurant', 'event', 'reservation', 'appointment', 'visit', 'check', 'in', 'at', 'on', 'to', 'for', 'the', 'a', 'an', 'of', 'with', 'about'}
            dtokens = set(re.findall('[a-z0-9]+', canonical(desc)))
            if len(desc) > 180 or not dtokens.issubset(vocab):
                self.last_predicate_failures.append('description_not_anchored')
                return False
        participants = a.get('participants') or []
        if isinstance(participants, str):
            participants = [participants]
        if not isinstance(participants, (list, tuple)):
            self.last_predicate_failures.append('participants_shape')
            return False
        if any((not emails(str(p)).issubset(self.addresses) or (not emails(str(p)) and canonical(p) not in self.low) for p in participants)):
            self.last_predicate_failures.append('participants_not_anchored')
            return False
        location = str(a.get('location') or '')
        if location:
            if not SAFE_ADDRESS.fullmatch(location) or not output_safe(location, self.prompt, 160):
                self.last_predicate_failures.append('unsafe_location')
                return False
            if canonical(location) not in self.low:
                if not ('address' in self.low and 'location' in self.low and self.source_present(('get_hotels_address', 'get_restaurants_address', 'get_all_hotels', 'get_all_restaurants'))):
                    self.last_predicate_failures.append('location_missing_address_source')
                    return False
        return True

    def supports_direct_message(self, a: Mapping) -> bool:
        self.last_predicate_failures = []
        if not (('send' in self.low or 'message' in self.low) and ('direct message' in self.low or 'send it to ' in self.low or 'send information' in self.low or ('send the summary' in self.low))):
            self.last_predicate_failures.append('direct_send_not_explicit')
            return False
        recipient = canonical(a.get('recipient', ''))
        if not recipient or recipient not in self.low.split():
            if not recipient or not re.search('\\b' + re.escape(recipient) + '\\b', self.low):
                self.last_predicate_failures.append('direct_recipient_not_explicit')
                return False
        body = str(a.get('body', ''))
        if not output_safe(body, self.prompt, MAX_BODY):
            self.last_predicate_failures.append('unsafe_direct_content')
            return False
        source = self.source_present(('read_channel_messages', 'read_inbox', 'get_webpage', 'read_file', 'get_'))
        if not source:
            self.last_predicate_failures.append('direct_read_source_missing')
        return source

    def supports_channel_message(self, a: Mapping) -> bool:
        if not any((w in self.low for w in ('post', 'write the following message', 'send the', 'send a message'))):
            return False
        channel = canonical(a.get('channel', ''))
        if not channel:
            return False
        exact = channel in self.quotes
        prefix = re.search('(?i)channel\\s+starting\\s+with\\s+([a-z0-9_-]+)', self.prompt)
        if not exact and (not (prefix and channel.startswith(canonical(prefix.group(1))))):
            return False
        body = str(a.get('body', ''))
        if not output_safe(body, self.prompt, MAX_BODY):
            return False
        if 'following message' in self.low and ':' in self.prompt:
            expected = self.prompt.split(':', 1)[1].strip()
            return canonical(body) == canonical(expected) and len(expected) < MAX_BODY
        if any((w in self.low for w in ('summary', 'summarize', 'content'))):
            return self.source_present(('get_webpage', 'read_channel_messages', 'read_inbox'))
        return canonical(body) in self.low

    def supports_create_file(self, a: Mapping) -> bool:
        if not ('create a new file' in self.low or 'create a file' in self.low):
            return False
        filename = canonical(a.get('filename', ''))
        if filename not in self.quotes:
            return False
        text = str(a.get('content', ''))
        return output_safe(text, self.prompt, MAX_LOCAL_CONTENT)

    def supports_append_file(self, a: Mapping) -> bool:
        if not (('add' in self.low or 'append' in self.low) and 'file' in self.low):
            return False
        file_id = canonical(a.get('file_id', ''))
        if not file_id or not SAFE_NAME.fullmatch(file_id):
            return False
        quoted_names = [q for q in self.quotes if '.' in q and q in self.low]
        if not quoted_names:
            return False
        linked = any((file_id in canonical(x.serialized) and any((n in canonical(x.serialized) or n in x.argument_hint for n in quoted_names)) for x in self.reads))
        text = str(a.get('content', ''))
        return linked and output_safe(text, self.prompt, MAX_LOCAL_CONTENT)

    def supports_update_user_info(self, a: Mapping) -> bool:
        if not ('update my account information' in self.low or 'update my address' in self.low):
            return False
        keys = {k for k, v in a.items() if v is not None and str(v).strip()}
        if not keys or not keys.issubset({'street', 'city'}):
            return False
        prompt_contains_address = all((canonical(a[k]) in self.low for k in keys))
        source_file = next((q for q in self.quotes if q.endswith('.txt')), '')
        source_matches = bool(source_file and self.source_present(('read_file',), source_file))
        if not (prompt_contains_address or source_matches):
            return False
        return all((SAFE_ADDRESS.fullmatch(str(a[k])) and output_safe(str(a[k]), self.prompt, 160) for k in keys))

    def supports_add_participants(self, a: Mapping) -> bool:
        if not ('add' in self.low and 'participants' in self.low):
            return False
        items = a.get('participants') or []
        if not isinstance(items, (list, tuple)) or not items:
            return False
        if not all((emails(v) and emails(v).issubset(self.addresses) for v in items)):
            return False
        event_id = canonical(a.get('event_id', ''))
        names = [q for q in self.quotes if 'meeting' in q or 'event' in q]
        return bool(names and event_id and self.source_present(('get_day_calendar_events', 'search_calendar_events'), event_id))

    def matches(self, function: str, a: Mapping) -> tuple[bool, str]:
        self.last_predicate_failures = []
        if function in HARD_DENY_RELAX:
            return (False, 'high_impact_requires_independent_authority')
        checks = {'create_calendar_event': (self.supports_calendar, ('title', 'start_time', 'end_time', 'description', 'participants', 'location')), 'send_direct_message': (self.supports_direct_message, ('recipient', 'body')), 'send_channel_message': (self.supports_channel_message, ('channel', 'body')), 'create_file': (self.supports_create_file, ('filename', 'content')), 'append_to_file': (self.supports_append_file, ('file_id', 'content')), 'update_user_info': (self.supports_update_user_info, ('street', 'city')), 'add_calendar_event_participants': (self.supports_add_participants, ('event_id', 'participants'))}
        if function not in checks:
            return (False, 'no_typed_capability')
        fn, fields = checks[function]
        if any((k not in fields and v is not None and (v not in ('', [], {})) for k, v in a.items())):
            return (False, 'out_of_scope_fields')
        if not fn(a):
            return (False, self.last_predicate_failures[0] if self.last_predicate_failures else 'prompt_destination_or_data_scope_not_verified')
        dest_fields = {'create_calendar_event': 'title', 'send_direct_message': 'recipient', 'send_channel_message': 'channel', 'create_file': 'filename', 'append_to_file': 'file_id', 'update_user_info': 'street', 'add_calendar_event_participants': 'event_id'}
        dest = canonical(a.get(dest_fields[function], ''))
        self.issued.append(ScopedCapability(tool=function, authorized_fields=fields, user_prompt_sha256=self.prompt_sha256, intended_destination=dest, expected_sources=tuple((x.function for x in self.reads)), max_payload_bytes=MAX_LOCAL_CONTENT if 'file' in function else MAX_BODY))
        return (True, 'user_scope_verified')

@dataclass
class ConstrainedDecisionController:
    max_verify: int = 6
    max_replan: int = 2
    verify_used: int = 0
    replan_used: int = 0
    records: list[dict] = field(default_factory=list)
    costs: dict[str, float] = field(default_factory=lambda: {'ALLOW': 0.0, 'ALLOW_SCOPE': 0.04, 'VERIFY_ALLOW': 0.08, 'SAFE_REPLAN': 0.23, 'DENY': 0.55})

    def choose(self, tool: str, gate: str, scope_ok: bool, hard_risk: bool, scope_reason: str, needs_app_verification: bool=False, app_verified: bool=False) -> str:
        feasible = ['DENY']
        if not hard_risk and gate in ('semantic', 'taint') and scope_ok:
            if not needs_app_verification:
                feasible.append('ALLOW_SCOPE')
            elif self.verify_used <= self.max_verify and app_verified:
                feasible.append('VERIFY_ALLOW')
        if not hard_risk and gate in ('semantic', 'taint') and (self.replan_used < self.max_replan):
            feasible.append('SAFE_REPLAN')
        choice = min(feasible, key=lambda x: self.costs[x])
        if choice == 'SAFE_REPLAN':
            self.replan_used += 1
        self.records.append({'tool': tool, 'original_gate': gate, 'decision': choice, 'scope_reason': scope_reason, 'expected_cost_weight': self.costs[choice], 'verify_budget_used': self.verify_used, 'replan_budget_used': self.replan_used})
        return choice
