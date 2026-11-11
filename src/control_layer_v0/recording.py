"""Complete request and response capture with error preservation."""
import json
import time

def snapshot(value):

    def default(item):
        return item.model_dump(mode='json') if hasattr(item, 'model_dump') else repr(item)
    return json.loads(json.dumps(value, default=default, ensure_ascii=False))

def observed_create(create, records):

    def request(*args, **kwargs):
        event = {'index': len(records)}
        try:
            event['request'] = snapshot(kwargs)
            if args:
                event['positional_arguments'] = snapshot(args)
        except Exception as exc:
            event['request_capture_error'] = type(exc).__name__
        records.append(event)
        tick = time.perf_counter()
        try:
            result = create(*args, **kwargs)
            try:
                event['response'] = snapshot(result)
            except Exception as exc:
                event['response_capture_error'] = type(exc).__name__
            return result
        except Exception as exc:
            event['error_type'] = type(exc).__name__
            raise
        finally:
            event['seconds'] = time.perf_counter() - tick
    return request
