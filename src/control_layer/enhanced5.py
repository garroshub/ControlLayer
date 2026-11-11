"""Policy and taint enforcement primitives."""
import re
from control_layer.enhanced import SENSITIVE_TOOLS
from control_layer.enhanced3 import content_tokens, normalize_text
_LOCAL_WRITE_TOOLS = {'write_file', 'copy_file', 'create_draft', 'save_note'}
GRANT_TOOLS = {'add_collaborator', 'grant_access', 'share_document', 'create_share_link', 'change_permissions'}

def is_endpoint(tool):
    if tool in SENSITIVE_TOOLS or tool in GRANT_TOOLS:
        return True
    if tool.startswith(('read_', 'search_', 'list_', 'get_')):
        return False
    if tool in _LOCAL_WRITE_TOOLS:
        return False
    return True

def effective_task_call(step, trace):
    return bool(step.get('is_task_call')) and trace.get('plan_origin') != 'tool_output'
_POINTER_PATTERNS = [re.compile('https?://\\S+', re.IGNORECASE), re.compile('\\bmsg_\\d+\\b', re.IGNORECASE), re.compile('\\bevt_\\d+\\b', re.IGNORECASE), re.compile('\\b[A-Z]{2,}-\\d+\\b', re.IGNORECASE), re.compile('/shared/\\S+', re.IGNORECASE)]

def internal_pointers(text):
    out = []
    for pat in _POINTER_PATTERNS:
        for m in pat.findall(text):
            if 'public' not in m.lower():
                out.append(m)
    return out

def ref_flag(args):
    for value in args.values():
        if not isinstance(value, str):
            continue
        if internal_pointers(value) or internal_pointers(normalize_text(value)):
            return (True, 'internal pointer in arg')
    return (False, 'no internal pointer')

class TrackedReturns:

    def __init__(self):
        self.items = []

    def add_sensitive(self, text):
        if isinstance(text, str) and text not in [t for t, _ in self.items]:
            self.items.append((text, 'sensitive'))

    def add_readback(self, text):
        if isinstance(text, str) and text not in [t for t, _ in self.items]:
            self.items.append((text, 'readback'))

    def texts(self):
        return [t for t, _ in self.items]

    def kinds(self):
        return [k for _, k in self.items]

def _containment_match(value, ret):
    if value == ret:
        return True
    if len(ret) >= 10 and ret in value:
        return True
    if len(value) >= 10 and value in ret:
        return True
    return False

def endpoint_taint_check(tracked, args, effective_task):
    matched_kinds = set()
    for value in args.values():
        if not isinstance(value, str):
            continue
        for text, kind in tracked.items:
            if _containment_match(value, text) or _containment_match(normalize_text(value), normalize_text(text)):
                matched_kinds.add(kind)
    if not matched_kinds:
        return (False, 'taint passed')
    if matched_kinds == {'readback'} and effective_task:
        return (False, 'readback-only match on task call, exempt')
    return (True, 'taint match kinds=%s' % sorted(matched_kinds))
_WRITE_TOOLS = {'write_file', 'create_document', 'update_document', 'copy_file', 'create_draft', 'save_note'}

def _object_key(args):
    for f in ('path', 'doc', 'file', 'dst'):
        v = args.get(f)
        if isinstance(v, str):
            return v
    return None

class StagedStore:

    def __init__(self):
        self.objects = {}

    def observe_write(self, tool, args):
        if tool not in _WRITE_TOOLS:
            return
        if tool == 'copy_file':
            src, dst = (args.get('src'), args.get('dst'))
            if isinstance(src, str) and isinstance(dst, str) and (src in self.objects):
                self.objects[dst] = self.objects[src]
            return
        key = _object_key(args)
        content = args.get('content')
        if key and isinstance(content, str):
            self.objects[key] = content

    def observe_read(self, tool, args, tool_return):
        if not tool.startswith(('read_', 'get_', 'search_', 'list_')):
            return None
        key = _object_key(args)
        if key and key in self.objects:
            return self.objects[key]
        if isinstance(tool_return, str):
            for content in self.objects.values():
                if tool_return == content or (len(content) >= 10 and content in tool_return):
                    return content
        return None

class SemanticCumulative:

    def __init__(self, token_threshold=5, digit_threshold=2):
        self.token_threshold = token_threshold
        self.digit_threshold = digit_threshold
        self.tokens = {}
        self.digits = {}

    def _overlap(self, ret, args):
        rtoks = content_tokens(ret)
        toks, digs = (set(), set())
        for value in args.values():
            if not isinstance(value, str):
                continue
            ct = content_tokens(value)
            toks |= ct & rtoks
            digs |= {t for t in ct if t.isdigit()} & {t for t in rtoks if t.isdigit()}
        return (toks, digs)

    def projected_block(self, returns, args):
        for ret in returns:
            toks, digs = self._overlap(ret, args)
            if len(self.tokens.get(ret, set()) | toks) >= self.token_threshold:
                return True
            if len(self.digits.get(ret, set()) | digs) >= self.digit_threshold:
                return True
        return False

    def add(self, returns, args):
        for ret in returns:
            toks, digs = self._overlap(ret, args)
            self.tokens.setdefault(ret, set()).update(toks)
            self.digits.setdefault(ret, set()).update(digs)

def grant_flag(tool, effective_task):
    return tool in GRANT_TOOLS and (not effective_task)
