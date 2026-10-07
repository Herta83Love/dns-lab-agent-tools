#!/usr/bin/env python3
"""Human approval writes a private token file; never prints the token."""
import argparse
import os
from pathlib import Path
from agent import dns_lab_tools as api

p=argparse.ArgumentParser(description='Human approval for one DNS lab plan')
p.add_argument('plan_id');p.add_argument('--plan-sha256',help='Required exact immutable SHA256 for manifest traffic')
p.add_argument('--config',type=Path,default=api.CONFIG_PATH)
p.add_argument('--token-file',type=Path,required=True,help='New owner-only token file; keep it outside chat/logs/Git')
args=p.parse_args();api.CONFIG_PATH=args.config
try:
 if not args.token_file.is_absolute() or args.token_file.exists():raise ValueError()
 fd=os.open(args.token_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:
  with os.fdopen(fd,'w') as f:
   token=api.approve_plan_cli(args.plan_id,args.plan_sha256)
   f.write(token+'\n');f.flush();os.fsync(f.fileno())
 except BaseException:
  args.token_file.unlink(missing_ok=True);raise
 print('APPROVED: one-time token saved to protected file; token omitted.')
except Exception:
 raise SystemExit('APPROVAL_REJECTED: check exact plan SHA, expiry, config and new private output path.') from None
