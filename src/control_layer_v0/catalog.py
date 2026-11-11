"""Compact presentation of the full simulator tool catalog."""
from __future__ import annotations
import json
import re
INLINE_EMPTY_TOOL = re.compile('<function\\s*=\\s*(?P<name>[A-Za-z_]\\w*)\\s*>\\s*</function>')

def shorten_schema(schema, depth=0):
    if not isinstance(schema, dict):
        return schema
    out = {}
    for key in ('type', 'enum', 'const', 'required', 'format', 'additionalProperties', 'default', 'minimum', 'maximum', 'minLength', 'maxLength'):
        if key in schema:
            out[key] = schema[key]
    if depth < 6:
        if 'properties' in schema:
            out['properties'] = {name: shorten_schema(value, depth + 1) for name, value in schema['properties'].items()}
        if 'items' in schema:
            out['items'] = shorten_schema(schema['items'], depth + 1)
        for key in ('anyOf', 'oneOf', 'allOf'):
            if key in schema:
                out[key] = [shorten_schema(v, depth + 1) for v in schema[key]]
    if 'description' in schema and isinstance(schema['description'], str):
        out['description'] = schema['description'][:95]
    return out

def compact_full_catalog(system_message, tools):
    from agentdojo.agent_pipeline.llms import local_llm
    listed = list(tools)
    specs = [json.dumps({'name': tool.name, 'description': tool.description[:135], 'parameters': shorten_schema(tool.parameters.model_json_schema())}, ensure_ascii=False, separators=(',', ':')) for tool in listed]
    prompt = local_llm._tool_calling_prompt.format(functions='\n'.join(specs))
    if system_message:
        prompt += '\n\n## Additional Instructions\n\n' + system_message
    return prompt

def normalize_zero_arg_calls(text, no_argument_tool_names):
    count = 0

    def fix(match):
        nonlocal count
        name = match.group('name')
        if name not in no_argument_tool_names:
            return match.group(0)
        count += 1
        return f'<function={name}>{{}}</function>'
    fixed = INLINE_EMPTY_TOOL.sub(fix, text or '')
    return (fixed, count)
