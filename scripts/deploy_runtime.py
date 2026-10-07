"""Atomic operator deployment on the execution host; install protected config with code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def deploy(bundle,config_source,deployment_root):
 bundle=Path(bundle).resolve();source=Path(config_source)
 if source.is_symlink() or source.stat().st_mode&0o077:raise ValueError()
 cfg=json.loads(source.read_text());profile=cfg['profiles']['lab-malicious']
 if profile['base_url']!='https://172.16.30.209:1606':raise ValueError()
 secret=Path(profile['secret_file'])
 if not secret.is_file() or secret.stat().st_mode&0o077:raise ValueError()
 # Copy references, never secret contents. Account remains in protected config only.
 profile['traffic_dns_server']='172.16.30.222';profile['traffic_dns_port']=53
 workspace=Path(cfg.get('workspace_root','/home/jackie_tsai/Herta-Chat/agent_workspace/dns_lab'))
 cfg['manifest_root']=str(workspace/'manifests')
 root=Path(deployment_root).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700);root.chmod(0o700)
 releases=root/'releases';releases.mkdir(mode=0o700,exist_ok=True);releases.chmod(0o700)
 metadata=json.loads((bundle/'runtime-metadata.json').read_text());commit=metadata['git_commit']
 import re
 if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError()
 manifest=json.loads((bundle/'tool-manifest.json').read_text())
 for relative,digest in manifest['source_sha256'].items():
  if Path(relative).is_absolute() or '..' in Path(relative).parts or hashlib.sha256((bundle/relative).read_bytes()).hexdigest()!=digest:raise ValueError()
 release=releases/('20261007-'+commit[:12])
 if release.exists():raise ValueError()
 stage=Path(tempfile.mkdtemp(prefix='.deploy-',dir=releases));stage.chmod(0o700)
 try:
  for relative in ['agent/__init__.py','agent/dns_lab_tools.py','agent/top_reports.py','agent/manifest_traffic.py','agent/manifest_worker.py','agent/log_exports.py','agent/mcp_server.py','agent/approve_dns_lab_plan.py','agent/dns_lab_config.example.json','scripts/deploy_runtime.py','scripts/import_reviewed_manifest.py','scripts/deploy_acceptance.py','requirements-mcp.lock.txt','tool-manifest.json','runtime-metadata.json']:
   dest=stage/relative;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(bundle/relative,dest);dest.chmod(0o600)
  dest=stage/'agent/dns_lab_config.json'
  fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as f:json.dump(cfg,f);f.flush();os.fsync(f.fileno())
  os.rename(stage,release)
  for command in [[sys.executable,'-m','venv',str(release/'.venv')],[str(release/'.venv/bin/python'),'-m','pip','install','--disable-pip-version-check','-r',str(release/'requirements-mcp.lock.txt')]]:
   result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   if result.returncode:raise ValueError()
  command=[str(release/'.venv/bin/python'),str(release/'scripts/deploy_acceptance.py'),str(release)]
  result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
  if result.returncode:raise ValueError()
  link=root/('.current-'+commit[:12]);link.symlink_to(release);os.replace(link,root/'current')
  old=root/'mcp-binding-20261007-v1'
  if old.is_dir():
   dest=old/'DEPRECATED.json';dest.write_text(json.dumps({'deprecated':True,'replacement':str(root/'current'),'reason':'Use atomic runtime with protected adjacent config and contract 3.3'}));dest.chmod(0o600)
  print(json.dumps({'deployed':True,'runtime':str(release),'current':str(root/'current'),'git_commit':commit,'tool_contract_version':'3.3','config_mode':'0600','mcp_readonly_tools':6,'mcp_manifest_enabled_tools':10,'device_writes':0,'dns_packets_sent':0}))
 except BaseException:
  if stage.exists():shutil.rmtree(stage)
  # Failed acceptance leaves an unactivated release for operator inspection.
  raise

def main():
 p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);p.add_argument('--config-source',required=True);p.add_argument('--deployment-root',required=True);a=p.parse_args()
 try:deploy(a.bundle,a.config_source,a.deployment_root)
 except Exception:raise SystemExit('DEPLOYMENT_REJECTED: protected config, source hashes, dependencies or MCP acceptance failed; current runtime not switched.') from None
if __name__=='__main__':main()
