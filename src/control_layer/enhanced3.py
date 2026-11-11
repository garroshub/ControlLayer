"""Policy and taint enforcement primitives."""
import base64
import binascii
import re
import urllib.parse
STOPWORDS = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'to', 'of', 'in', 'on', 'for', 'with', 'and', 'or', 'it', 'its', 'this', 'that', 'at', 'by', 'from', 'comes', 'come', 'totals', 'total', 'figure', 'figures', 'spending', 'spend', 'costs', 'cost', 'reached', 'amount', 'about', 'around'}
_ONES = {'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12, 'thirteen': 13, 'fourteen': 14, 'fifteen': 15, 'sixteen': 16, 'seventeen': 17, 'eighteen': 18, 'nineteen': 19}
_TENS = {'twenty': 20, 'thirty': 30, 'forty': 40, 'fifty': 50, 'sixty': 60, 'seventy': 70, 'eighty': 80, 'ninety': 90}

def _parse_number_words(tokens):
    out = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in _ONES or t in _TENS or t in ('hundred', 'thousand', 'million', 'grand'):
            total, current = (0, 0)
            j = i
            while j < len(tokens):
                w = tokens[j]
                if w in _ONES:
                    current += _ONES[w]
                elif w in _TENS:
                    current += _TENS[w]
                elif w == 'hundred':
                    current = (current or 1) * 100
                elif w in ('thousand', 'grand'):
                    total += (current or 1) * 1000
                    current = 0
                elif w == 'million':
                    total += (current or 1) * 1000000
                    current = 0
                else:
                    break
                j += 1
            value = total + current
            if value or j > i:
                out.append(str(value))
            i = j
        else:
            out.append(t)
            i += 1
    return out

def content_tokens(text):
    raw = re.findall('[a-z0-9]+', text.lower())
    normed = _parse_number_words(raw)
    return {t for t in normed if t not in STOPWORDS and (not (len(t) == 1 and t.isalpha()))}

def _try_b64_decode(token):
    if len(token) < 8 or len(token) % 4 != 0:
        return None
    if not re.fullmatch('[A-Za-z0-9+/]+={0,2}', token):
        return None
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if all((32 <= ord(c) < 127 or c in '\n\t' for c in text)):
        return text
    return None

def _try_hex_decode(token):
    if len(token) < 8 or len(token) % 2 != 0:
        return None
    if not re.fullmatch('[0-9a-fA-F]+', token):
        return None
    try:
        text = bytes.fromhex(token).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        return None
    if all((32 <= ord(c) < 127 or c in '\n\t' for c in text)):
        return text
    return None

def normalize_text(text):
    s = urllib.parse.unquote(text)
    for _ in range(3):
        changed = False
        compact = re.sub('\\s+', '', s)
        if compact != s and len(compact) >= 16:
            dec = _try_b64_decode(compact)
            if dec is not None:
                s = dec
                changed = True
                continue
        for token in re.findall('[A-Za-z0-9+/=]+', s):
            dec = _try_b64_decode(token)
            if dec is not None and dec != token:
                s = s.replace(token, dec)
                changed = True
        for token in re.findall('\\b[0-9a-fA-F]{8,}\\b', s):
            dec = _try_hex_decode(token)
            if dec is not None and dec != token:
                s = s.replace(token, dec)
                changed = True
        if not changed:
            break
    return ' '.join(s.lower().split())

def normalized_taint_check(returns, tool, args):
    from control_layer.enhanced import SENSITIVE_TOOLS
    if tool not in SENSITIVE_TOOLS:
        return (False, 'not a sensitive sink')
    norm_returns = [normalize_text(r) for r in returns]
    for arg, value in args.items():
        if not isinstance(value, str):
            continue
        nv = normalize_text(value)
        for ret in norm_returns:
            if nv == ret:
                return (True, "normalized verbatim copy in arg '%s'" % arg)
            if len(ret) >= 10 and ret in nv:
                return (True, "normalized contains sensitive text in arg '%s'" % arg)
            if len(nv) >= 10 and nv in ret:
                return (True, "normalized arg '%s' copied from sensitive read" % arg)
    return (False, 'normalized taint passed')

def semantic_flag(returns, args):
    for arg, value in args.items():
        if not isinstance(value, str):
            continue
        toks = content_tokens(value)
        digits = {t for t in toks if t.isdigit()}
        for ret in returns:
            rtoks = content_tokens(ret)
            if digits & {t for t in rtoks if t.isdigit()}:
                return (True, "shared number with sensitive read in arg '%s'" % arg)
            if len(toks & rtoks) >= 3:
                return (True, "shared content tokens with sensitive read in arg '%s'" % arg)
    return (False, 'no semantic overlap')

class TieredBook:

    def __init__(self, entries):
        self.tiers = {}
        for e in entries:
            if isinstance(e, str):
                self.tiers[e] = 'personal'
            else:
                self.tiers[e.get('email')] = e.get('tier', 'personal')

    def tier_of(self, recipient):
        return self.tiers.get(recipient, 'personal')
RECIPIENT_FIELDS = ('to', 'recipients', 'participants', 'email')

def recipients_of(args):
    out = []
    for f in RECIPIENT_FIELDS:
        v = args.get(f)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.extend([x for x in v if isinstance(x, str)])
    return out

class CumulativeTaint:

    def __init__(self, threshold=0.5):
        self.threshold = threshold
        self.matched = {}

    def fraction(self, returns):
        best = 0.0
        for ret in returns:
            nret = normalize_text(ret)
            if nret:
                best = max(best, self.matched.get(ret, 0) / len(nret))
        return best

    def gains(self, returns, args):
        out = {}
        for ret in returns:
            nret = normalize_text(ret)
            if not nret:
                continue
            g = 0
            for value in args.values():
                if not isinstance(value, str):
                    continue
                nv = normalize_text(value)
                if nv and nv in nret:
                    g += len(nv)
                elif len(nret) >= 10 and nret in nv:
                    g += len(nret)
            out[ret] = g
        return out

    def add(self, returns, args):
        for ret, g in self.gains(returns, args).items():
            self.matched[ret] = self.matched.get(ret, 0) + g

    def fraction_after(self, returns, args):
        g = self.gains(returns, args)
        best = 0.0
        for ret in returns:
            nret = normalize_text(ret)
            if nret:
                best = max(best, (self.matched.get(ret, 0) + g.get(ret, 0)) / len(nret))
        return best

    def update(self, returns, args):
        self.add(returns, args)
        if self.fraction(returns) >= self.threshold:
            return (True, 'cumulative exfiltration over threshold')
        return (False, 'cumulative below threshold')
