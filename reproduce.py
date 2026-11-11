"""Portable benchmark execution against a locally managed Ollama service."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'src'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf8'))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf8')


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('Expected a positive episode limit')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--probes', action='store_true')
    parser.add_argument('--limit', type=positive)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    rows = load(ROOT/'evidence/benchmark-plan.json')['cases']
    if args.probes:
        rows=load(ROOT/'evidence/channel-plan.json')['cases']
    if args.smoke:
        rows = [r for r in rows if r['mode']=='clean' and r['suite']=='slack'
                and r['task'] in ('user_task_0','user_task_2','user_task_3')]
    if args.limit:
        rows = rows[:args.limit]
    if args.plan:
        print(json.dumps({'episodes':len(rows),'normal':sum(r['mode']=='clean' for r in rows),
                          'attack':sum(r['mode']=='attack' for r in rows)}))
        return
    if not sys.flags.utf8_mode:
        parser.error('Run Python with -X utf8 or set PYTHONUTF8=1 for benchmark fixture consistency')
    if args.out is None:
        parser.error('--out is required for execution')
    manifest = load(ROOT/'SOURCE_MANIFEST.json')
    for relative, digest in manifest['files'].items():
        if sha(ROOT/relative)!=digest:
            raise RuntimeError('Release source differs from manifest')
    expected = load(ROOT/'runtime-environment.json')
    with urllib.request.urlopen('http://127.0.0.1:11465/api/tags',timeout=10) as response:
        tags=json.load(response)
    with urllib.request.urlopen('http://127.0.0.1:11465/api/version',timeout=10) as response:
        version=json.load(response)['version']
    if version!=expected['ollama_version'] or not any(
            model['name']==expected['model'] and model['digest']==expected['served_model_digest']
            for model in tags['models']):
        raise RuntimeError('Actual local model or runtime differs from the recorded experiment')
    warm_request=urllib.request.Request('http://127.0.0.1:11465/api/generate',
        data=json.dumps({'model':expected['model'],'prompt':'','stream':False,'keep_alive':'10m',
                         'options':{'num_ctx':expected['context_length']}}).encode(),
        headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(warm_request,timeout=180) as response:
        json.load(response)
    with urllib.request.urlopen('http://127.0.0.1:11465/api/ps',timeout=10) as response:
        residency=json.load(response)
    loaded=next((m for m in residency.get('models',[]) if m.get('digest')==expected['served_model_digest']),None)
    if loaded is None or loaded.get('context_length')!=expected['context_length']:
        raise RuntimeError('Loaded actor context does not match the experiment')
    observed_service={'model_digest':loaded['digest'],'context_length':loaded['context_length'],
                      'client_concurrency':1,'server_parallelism':'Operator-managed; not exposed by the API'}
    from control_layer_v0.benchmark import run_case
    if args.probes:
        from control_layer_v0.probe_tasks import install
        install(ROOT/'evidence/channel-probes.json')
    args.out.mkdir(parents=True, exist_ok=False)
    private=args.out/'_private'
    private.mkdir()
    (private/'.gitignore').write_text('*\n!.gitignore\n',encoding='utf8')
    write(args.out/'protocol.json',{'cases':rows,'runtime':expected,'observed_service':observed_service,
          'source_manifest_sha256':sha(ROOT/'SOURCE_MANIFEST.json'),
          'scope':'New local reproduction. Semantic review and official scoring remain separate.'})
    for index,meta in enumerate(rows,1):
        write(private/(meta['id']+'-started.json'),meta)
        result=run_case(meta['suite'],meta['task'],meta['arm'],meta['injection'],meta['style'] or 'DirectAttack')
        audit=result.pop('audit')
        write(private/(meta['id']+'-audit.json'),audit)
        result.update(meta)
        if meta['mode']=='attack':
            key=hashlib.sha256(json.dumps([meta['suite'],meta['injection'],meta['style']],sort_keys=True,ensure_ascii=False).encode()).hexdigest()
            expected_hash=load(ROOT/'evidence/benchmark-plan.json')['expected_attack_hashes'][key]
            if result['attack_payload_sha256']!=expected_hash:
                result['status']='attack_payload_drift'
        result['audit_sha256']=sha(private/(meta['id']+'-audit.json'))
        write(args.out/(meta['id']+'.json'),result)
        print(json.dumps({'episode':index,'arm':meta['arm'],'task':meta['task'],
                          'status':result['status'],'official_utility':result['official_utility'],
                          'official_attacker_success':result['official_attacker_success']}),flush=True)


if __name__=='__main__':
    main()
