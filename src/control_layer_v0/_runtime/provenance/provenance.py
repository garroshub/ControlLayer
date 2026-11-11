"""Application-backed identity and destination binding."""
from __future__ import annotations
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
import hashlib, hmac, json, re
from agentdojo.functions_runtime import FunctionsRuntime
from control_layer_v0._runtime.scoping.scoped_decision import TrustedTaskScope, canonical, emails, output_safe
PAYMENT_TOOLS = {'send_money', 'schedule_transaction', 'update_scheduled_transaction'}

def dump(value):
    if hasattr(value, 'model_dump'):
        return value.model_dump(mode='json')
    if isinstance(value, list):
        return [dump(x) for x in value]
    return value

def read_app(runtime, env, tool, kwargs):
    if env is None or not tool.startswith(('read_', 'get_', 'search_', 'list_')) or tool not in runtime.functions:
        return None
    try:
        value, error = FunctionsRuntime.run_function(runtime, env, tool, kwargs, raise_on_error=False)
        return dump(value) if error is None else None
    except Exception:
        return None

class PaymentConfirmationVerifier:

    def __init__(self, secret: bytes, session_id: str, now: int | None=None):
        if not isinstance(secret, bytes) or len(secret) < 32 or (not session_id):
            raise ValueError('Missing external verification authority')
        self.secret = secret
        self.session_id = session_id
        self.now = now
        self.used = set()

    @staticmethod
    def cents(amount):
        try:
            value = Decimal(str(amount))
            if not value.is_finite() or value <= 0 or value.as_tuple().exponent < -2:
                return None
            return int(value * 100)
        except (InvalidOperation, TypeError, ValueError):
            return None

    def verify(self, receipt, action, args, prompt_hash, consume=True):
        if not isinstance(receipt, Mapping) or action not in ('send_money', 'schedule_transaction'):
            return False
        names = {'action', 'recipient', 'amount_cents', 'subject', 'date', 'recurring', 'prompt_sha256', 'session_id', 'nonce', 'issued_at', 'expires_at', 'signature'}
        if set(receipt) != names:
            return False
        now = self.now if self.now is not None else int(datetime.now(timezone.utc).timestamp())
        try:
            issued, expiry = (int(receipt['issued_at']), int(receipt['expires_at']))
            amount = self.cents(args.get('amount'))
            nonce = str(receipt['nonce'])
            if amount is None or not issued <= now < expiry or expiry - issued > 300 or (issued < now - 300) or (not re.fullmatch('[0-9a-f]{32,64}', nonce)) or (nonce in self.used) or (receipt['action'] != action) or (receipt['recipient'] != args.get('recipient')) or (not re.fullmatch('[A-Z]{2}[A-Z0-9]{12,34}', str(args.get('recipient', '')))) or (receipt['amount_cents'] != amount) or (receipt['subject'] != args.get('subject')) or (receipt['date'] != args.get('date')) or (receipt['recurring'] is not (args.get('recurring') if action == 'schedule_transaction' else False)) or (receipt['prompt_sha256'] != prompt_hash) or (receipt['session_id'] != self.session_id):
                return False
            unsigned = {k: receipt[k] for k in names if k != 'signature'}
            sig = hmac.new(self.secret, json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, str(receipt['signature'])):
                return False
        except (KeyError, TypeError, ValueError):
            return False
        if consume:
            self.used.add(nonce)
        return True

@dataclass(frozen=True)
class ProvenanceRecord:
    tool: str
    trusted_prompt_hash: str
    source_read_tool: str
    source_object_id: str
    source_field: str
    derived_target: str

class TypedProvenance:

    def __init__(self, prompt):
        self.scope = TrustedTaskScope(prompt)
        self.prompt = prompt
        self.low = canonical(prompt)
        self.created = {}
        self.records = []
        self.read_count = 0
        self.read_budget = 6

    def read(self, runtime, env, tool, args):
        if self.read_count >= self.read_budget:
            return None
        self.read_count += 1
        return read_app(runtime, env, tool, args)

    def record(self, tool, read_tool, source_id, field, target):
        self.records.append(ProvenanceRecord(tool, self.scope.prompt_sha256, read_tool, str(source_id), field, str(target)))
        return (True, 'typed_provenance_verified')

    def note_created(self, function, args, result):
        if function != 'create_file':
            return
        d = dump(result)
        if isinstance(d, dict):
            file_id = str(d.get('id_', ''))
            file_name = canonical(d.get('filename', ''))
            if file_id and file_name == canonical(args.get('filename', '')) and (file_name in self.scope.quotes):
                self.created[file_id] = file_name

    def event_participants(self, runtime, env, args):
        if 'same participants' not in self.low:
            return (False, 'participant_delegation_missing')
        match = re.search('same participants as (?:the\\s+)?[\'\\"]([^\'\\"]+)[\'\\"]\\s+(?:event\\s+)?on\\s+(20\\d{2}-\\d{2}-\\d{2})', self.low)
        if not match:
            return (False, 'event_source_date_missing')
        source, date = (match.group(1), match.group(2))
        people = args.get('participants')
        if not isinstance(people, list) or not people or any((not emails(p) for p in people)):
            return (False, 'participant_shape_or_email_invalid')
        normalized = {canonical(p) for p in people}
        if len(normalized) != len(people):
            return (False, 'duplicate_participants')
        if not self.scope.supports_calendar({**args, 'participants': None}):
            return (False, 'calendar_nonparticipant_scope_invalid')
        events = self.read(runtime, env, 'search_calendar_events', {'query': source, 'date': date})
        if not isinstance(events, list):
            return (False, 'event_lookup_failed')
        exact = [e for e in events if isinstance(e, dict) and canonical(e.get('title', '')) == source and (str(e.get('start_time', ''))[:10] == date)]
        if len(exact) != 1:
            return (False, 'ambiguous_source_event')
        event = exact[0]
        if not event.get('id_') or not isinstance(event.get('participants'), list):
            return (False, 'invalid_source_event')
        expected = {canonical(e) for e in event['participants']}
        if not expected or normalized != expected:
            return (False, 'participant_set_not_exact_source')
        return self.record('create_calendar_event', 'search_calendar_events', event['id_'], 'participants', ','.join(sorted(expected)))

    def file_share(self, runtime, env, args):
        if not ('share the document' in self.low or 'share the file' in self.low):
            return (False, 'file_share_not_in_user_prompt')
        target = canonical(args.get('email', ''))
        if target not in self.scope.addresses:
            return (False, 'share_email_not_explicit')
        if args.get('permission') not in ('r', 'read'):
            return (False, 'read_permission_only')
        if 'read permission' not in self.low and 'read access' not in self.low:
            return (False, 'read_only_scope_missing')
        fid = str(args.get('file_id', ''))
        expected = self.created.get(fid)
        if not expected:
            return (False, 'file_was_not_created_in_task')
        file = self.read(runtime, env, 'get_file_by_id', {'file_id': fid})
        if not isinstance(file, dict) or str(file.get('id_', '')) != fid or canonical(file.get('filename', '')) != expected:
            return (False, 'created_file_identity_not_verified')
        return self.record('share_file', 'get_file_by_id', fid, 'filename', target)

    def channel_reply(self, runtime, env, args):
        m = re.search('where\\s+([a-z][a-z0-9_.-]+)\\s+asked\\s+about\\s+(.+?)\\s+and\\s+reply\\s+there\\b', self.low)
        if 'reply there' not in self.low or m is None:
            return (False, 'dynamic_reply_not_delegated')
        sender, topic = (m.group(1), m.group(2))
        body = str(args.get('body', ''))
        if not output_safe(body, self.prompt, 800):
            return (False, 'unsafe_reply_body')
        vocabulary = set(re.findall('[a-z0-9]+', self.low)) | {'i', 've', 'seen', 'saw', 'spotted', 'found', 'it', 'in', 'the', 'meeting', 'room', 'at', 'is', 'was', 'there', 'yes', 'your', 'coffee', 'mug', 'you', 'can', 'find', 'left', 'one', 'by', 'a'}
        if not set(re.findall('[a-z0-9]+', canonical(body))).issubset(vocabulary):
            return (False, 'reply_not_derived_from_user_text')
        channel = str(args.get('channel', ''))
        if not channel or len(channel) > 100:
            return (False, 'channel_missing')
        messages = self.read(runtime, env, 'read_channel_messages', {'channel': channel})
        if not isinstance(messages, list):
            return (False, 'channel_read_failed')
        matches = [m for m in messages if isinstance(m, dict) and canonical(m.get('sender', '')) == sender and (topic in canonical(m.get('body', '')))]
        if not matches:
            return (False, 'sender_topic_absent')
        return self.record('send_channel_message', 'read_channel_messages', channel, 'sender/topic', channel)

    def exact_direct_target(self, args):
        recipient = canonical(args.get('recipient', ''))
        if not re.fullmatch('[a-z][a-z0-9_.-]{1,50}', recipient):
            return (False, 'direct_target_invalid')
        if not (re.search('\\bto\\s+' + re.escape(recipient) + '\\b', self.low) and any((word in self.low for word in ('send', 'direct message')))):
            return (False, 'direct_target_not_in_trusted_user_prompt')
        return (True, 'direct_target_explicit')
