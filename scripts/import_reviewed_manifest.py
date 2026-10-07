"""Operator-only import. Copies reviewed JSON/JSONL into private workspace, never edits source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from agent import dns_lab_tools as api
from agent import manifest_traffic as t

def import_batch(source,batch_sha,catalog_sha,sums_sha,config):
 api.CONFIG_PATH=Path(config);api._config();base=t.private_manifest_root(api)
 source=Path(source)
 if not source.is_absolute() or source.is_symlink():t.fail('IMPORT_SOURCE_PATH_INVALID')
 source=source.resolve()
 def source_file(relative):
  p=source/relative
  if any(x.is_symlink() for x in [p,*p.parents]) or not p.resolve().is_relative_to(source):t.fail('IMPORT_SOURCE_PATH_INVALID')
  raw=p.read_bytes()
  if len(raw)>t.MAX_FILE:t.fail('IMPORT_ARTIFACT_TOO_LARGE')
  return raw
 batch=source_file('batch-manifest.json');catalog=source_file('catalog.jsonl');sums=source_file('SHA256SUMS.txt')
 if (t.sha(batch),t.sha(catalog),t.sha(sums))!=(batch_sha,catalog_sha,sums_sha):t.fail('IMPORT_REVIEWED_HASH_MISMATCH')
 manifest=json.loads(batch)
 if manifest.get('partition')!='controlled_candidate' or manifest.get('training_ready') is not False:t.fail('IMPORT_POLICY_INVALID')
 if manifest['lineage']['catalog']!={'path':'catalog.jsonl','sha256':catalog_sha}:t.fail('IMPORT_CATALOG_LINEAGE')
 destination=base/('reviewed-'+batch_sha[:16])
 if destination.exists():t.fail('IMPORT_DESTINATION_EXISTS')
 stage=Path(tempfile.mkdtemp(prefix='.import-',dir=base));stage.chmod(0o700)
 files={'batch-manifest.json':batch,'catalog.jsonl':catalog,'SHA256SUMS.txt':sums}
 try:
  for session in manifest['lineage']['sessions']:
   sid=session['session_id']
   if not isinstance(sid,str) or not t.re.fullmatch('[A-Za-z0-9_-]{1,80}',sid):t.fail('IMPORT_SESSION_INVALID')
   relative='sessions/'+sid+'/planned-queries.jsonl'
   if session['planned_queries_path']!=relative:t.fail('IMPORT_QUERY_PATH_INVALID')
   sm='sessions/'+sid+'/session-manifest.json'
   for name,digest in [(relative,session['query_list_sha256']),(sm,session['session_manifest_sha256'])]:
    raw=source_file(name)
    if t.sha(raw)!=digest:t.fail('IMPORT_SESSION_HASH_MISMATCH')
    files[name]=raw
  for name,raw in files.items():
   p=stage/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
   for parent in p.parents:
    if parent==base:break
    parent.chmod(0o700)
   fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  # Validate every session using the exact runtime parser before making it visible.
  for session in manifest['lineage']['sessions']:
   t.load_manifest(api,{'batch_manifest_path':str(stage/'batch-manifest.json'),'batch_manifest_sha256':batch_sha,'session_id':session['session_id'],'planned_queries_sha256':session['query_list_sha256']})
  os.rename(stage,destination)
  print(json.dumps({'imported':True,'batch_manifest_path':str(destination/'batch-manifest.json'),'batch_manifest_sha256':batch_sha,'sessions':len(manifest['lineage']['sessions']),'source_modified':False}))
  return destination
 except BaseException:
  shutil.rmtree(stage);raise

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--batch-sha256',required=True);p.add_argument('--catalog-sha256',required=True);p.add_argument('--sums-sha256',required=True);p.add_argument('--config',type=Path,default=api.CONFIG_PATH)
 a=p.parse_args()
 try:import_batch(a.source,a.batch_sha256,a.catalog_sha256,a.sums_sha256,a.config)
 except Exception:raise SystemExit('IMPORT_REJECTED: check reviewed hashes, lineage, schema and private workspace; source was not changed.') from None
if __name__=='__main__':main()
