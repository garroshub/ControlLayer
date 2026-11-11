"""Complete trusted commands for URL reads."""
import re
from control_layer_v0._runtime.scope.checks import canonical_url
from control_layer_v0._runtime.scope.core import ControlLayer, Grant
URL = '(?P<url>(?:https?://|www\\.)[^\\s<>"\\\']+)'
COMMANDS = ('(?:please\\s+)?(?:read|open|visit|fetch)\\s+(?:(?:the\\s+)?(?:webpage|website|page)\\s+)?' + URL, '(?:please\\s+)?read\\s+the\\s+content\\s+on\\s+(?:the\\s+)?(?:webpage|website|page)\\s+' + URL, '(?:please\\s+)?post\\s+the\\s+summary\\s+of\\s+the\\s+article\\s+at\\s+' + URL + '\\s+to\\s+the\\s+(?P<quote>[\\\'\\"])[a-z0-9_ -]{1,80}(?P=quote)\\s+channel[.!]?')

class URLReadContract:

    def __init__(self, destination=None):
        target = canonical_url(destination) if destination else None
        grants = [Grant('get_webpage', {'url': target})] if target is not None else []
        self._control = ControlLayer(grants)

    def check(self, tool, arguments):
        if set(arguments) != {'url'} or not isinstance(arguments['url'], str):
            return (False, 'invalid_url_arguments')
        target = canonical_url(arguments['url'])
        if target is None:
            return (False, 'invalid_url_destination')
        return self._control.check(tool, {'url': target})

def compile_url_read(trusted_request):
    for pattern in COMMANDS:
        match = re.fullmatch(pattern, trusted_request.strip(), re.I)
        if match:
            return URLReadContract(match['url'].rstrip('.,;'))
    return URLReadContract()
