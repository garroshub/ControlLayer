"""Calendar rescheduling with application-backed event identity."""
from dataclasses import dataclass
from datetime import datetime, timedelta
import re
from control_layer_v0._runtime.scope.core import ControlLayer, FieldBinding, Grant, normalize

@dataclass(frozen=True)
class RescheduleIntent:
    title: str
    start: datetime

def parse_reschedule(request):
    match = re.fullmatch('(?:please\\s+)?reschedule\\s+my\\s+(.{1,120}?)\\s+to\\s+(20\\d{2}-\\d{2}-\\d{2})\\s+at\\s+(\\d{2}:\\d{2})[.!]?', request.strip(), re.I)
    if not match:
        return None
    try:
        start = datetime.strptime(match[2] + ' ' + match[3], '%Y-%m-%d %H:%M')
    except ValueError:
        return None
    return RescheduleIntent(match[1].strip(), start)

def bind_reschedule(intent, application_events):
    if intent is None:
        return (ControlLayer([]), {})
    matches = [event for event in application_events if normalize(event.get('title', '')) == normalize(intent.title)]
    if len(matches) != 1:
        return (ControlLayer([]), {})
    event = matches[0]
    if event.get('status') == 'canceled':
        return (ControlLayer([]), {})
    try:
        duration = datetime.fromisoformat(str(event['end_time'])) - datetime.fromisoformat(str(event['start_time']))
        object_id = str(event['id_'])
        end = intent.start + duration
    except (KeyError, TypeError, ValueError, OverflowError):
        return (ControlLayer([]), {})
    if not object_id or duration <= timedelta(0):
        return (ControlLayer([]), {})
    binding = FieldBinding('event_id', object_id, 'id_', object_id)
    endpoints = [None]
    if end.second == 0 and end.microsecond == 0:
        endpoints.append(end.strftime('%Y-%m-%d %H:%M'))
    grants = [Grant('reschedule_calendar_event', {'event_id': object_id, 'new_start_time': intent.start.strftime('%Y-%m-%d %H:%M'), 'new_end_time': endpoint}, (binding,)) for endpoint in endpoints]
    return (ControlLayer(grants), {(object_id, 'id_'): object_id})
