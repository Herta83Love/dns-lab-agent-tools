#!/usr/bin/env python3
import argparse
from agent.dns_lab_tools import approve_plan_cli

p=argparse.ArgumentParser(description="Human approval for one DNS lab plan")
p.add_argument("plan_id")
args=p.parse_args()
print(approve_plan_cli(args.plan_id))
