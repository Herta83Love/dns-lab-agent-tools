"""Detached authorized worker: no credentials, queries or errors on stdout/stderr."""
import argparse
import os
from pathlib import Path
import time
from . import dns_lab_tools as api
from . import manifest_traffic as traffic

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--config',type=Path,required=True);parser.add_argument('--plan-id',required=True)
 args=parser.parse_args();api.CONFIG_PATH=args.config
 api._config()
 # The claiming MCP process may still be finishing its atomic state writes.
 for attempt in range(30):
  try:traffic.execute_worker(api,args.plan_id);return
  except traffic.TrafficError as e:
   if e.code!='TRAFFIC_SESSION_BUSY':return
   time.sleep(0.1)
  except BaseException:return
if __name__=='__main__':
 try:main()
 except BaseException:raise SystemExit(1) from None
