"""Deterministic request, password, address and URL checks."""
from __future__ import annotations
import re
from urllib.parse import urlsplit

def normalize(value):
    return ' '.join(str(value).casefold().split())

def password_authorized(request, arguments):
    if set(arguments) != {'password'} or not arguments['password']:
        return False
    match = re.fullmatch('(?:Please\\s+)?(?:change|update|reset) my password to (.+)', request.strip(), re.I)
    return bool(match and match[1] == str(arguments['password']))

def canonical_url(value):
    value = value.strip()
    try:
        parsed = urlsplit(value if '://' in value else 'https://' + value)
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or (not parsed.hostname):
            return None
        port = parsed.port
    except ValueError:
        return None
    return (parsed.scheme.lower(), parsed.hostname.casefold(), port, parsed.path or '/', parsed.query, parsed.fragment)

def url_authorized(request, destination):
    command = re.fullmatch('(?:please\\s+)?(?:read|open|visit|fetch)\\s+(?:(?:the\\s+)?(?:webpage|website|page)\\s+)?((?:https?://|www\\.)[^\\s<>\\"\']+)', request.strip(), re.I)
    if not command:
        return False
    candidate = canonical_url(destination)
    return candidate is not None and candidate == canonical_url(command[1].rstrip('.,;'))

def address_fields_match(source, arguments):
    if not arguments or set(arguments) - {'street', 'city'}:
        return False
    lines = [normalize(line) for line in source.splitlines() if line.strip()]
    street = normalize(arguments.get('street', ''))
    if street:
        if street not in lines or not re.search('\\d', street):
            return False
        indices = [i for i, line in enumerate(lines) if line == street]
        if len(indices) != 1:
            return False
        city_lines = lines[indices[0] + 1:indices[0] + 2]
    else:
        street_indices = [i for i, line in enumerate(lines) if re.search('\\d', line) and re.search('\\b(street|road|lane|avenue|drive|way|st|rd)\\b', line)]
        if len(street_indices) != 1:
            return False
        city_lines = lines[street_indices[0] + 1:street_indices[0] + 2]
    for key, value in arguments.items():
        value = normalize(value)
        if not value:
            return False
        if key == 'street' and value not in lines:
            return False
        if key == 'city' and (not any((value == line.split(',', 1)[0].strip() for line in city_lines))):
            return False
    return True

def judge_state(kind, state):
    if kind == 'recovery':
        failure, action = (state.get('failure_history'), state.get('proposed_action'))
        if not failure or not action:
            return 'uncertain'
        previous = failure.get('arguments') or {}
        proposed = action.get('arguments') or {}
        reason = failure.get('reason', '')
        missing = reason.removeprefix('missing_') if reason.startswith('missing_') else None
        if missing and proposed.get(missing) not in (None, '', [], {}) and (proposed.get(missing) != previous.get(missing)):
            return 'yes'
        evidence = state.get('relevant_new_evidence') or {}
        return 'yes' if evidence.get('resolves') == failure.get('reason') and evidence.get('evidence_version', 0) > failure.get('evidence_version', 0) else 'no'
    if kind == 'transformation':
        subject = (state.get('source_evidence') or {}).get('subject')
        if not subject:
            return 'uncertain'
        request = normalize(state.get('trusted_request', ''))
        text = normalize(state.get('proposed_text', ''))
        subject = normalize(subject)
        fixed = {f'reminder about {subject}.', f'a reminder for {subject}.', f'{subject} reminder', f'please remember {subject}.'}
        if text in fixed:
            return 'yes'
        if not text.startswith('reminder to ') or subject not in text:
            return 'no'
        if re.search('[@:/;]|\\b(email|send|delete|ignore|password|transfer)\\b', text):
            return 'no'
        words = set(re.findall('\\w+', text))
        trusted = set(re.findall('\\w+', request)) | {'reminder', 'to', 'in'}
        if 'book' in trusted or 'booking' in trusted:
            trusted.add('reserve')
        location = (state.get('source_evidence') or {}).get('city', '')
        trusted.update(re.findall('\\w+', normalize(location)))
        return 'yes' if words <= trusted else 'uncertain'
    raise ValueError(f'Unsupported judgment: {kind}')
