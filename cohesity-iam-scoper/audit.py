import json

with open('cft.json') as f:
    orig = json.load(f)
with open('scoped-cft.json') as f:
    scoped = json.load(f)


def collect_role_policies(cft):
    """Returns {rname: {policy_name: {action: {resource, condition}}}}"""
    result = {}
    for rname, r in cft.get('Resources', {}).items():
        if r.get('Type') != 'AWS::IAM::Role':
            continue
        result[rname] = {
            '_managed_arns': r.get('Properties', {}).get('ManagedPolicyArns', [])
        }
        for p in r.get('Properties', {}).get('Policies', []):
            pname = p.get('PolicyName', '?')
            if not isinstance(pname, str):
                pname = str(pname)
            actions = {}
            for stmt in p.get('PolicyDocument', {}).get('Statement', []):
                if stmt.get('Effect', 'Allow') != 'Allow':
                    continue
                res = stmt.get('Resource', '*')
                cond = stmt.get('Condition')
                acts = stmt.get('Action', [])
                if isinstance(acts, str):
                    acts = [acts]
                for a in acts:
                    actions[a] = {'resource': res, 'condition': cond}
            result[rname][pname] = actions
    return result


def all_actions(role_data):
    s = set()
    for k, v in role_data.items():
        if k == '_managed_arns':
            continue
        s.update(v.keys())
    return s


# Collect all managed policy resources in scoped CFT
scoped_managed = {}
for rname, r in scoped.get('Resources', {}).items():
    if r.get('Type') != 'AWS::IAM::ManagedPolicy':
        continue
    acts_detail = {}
    for stmt in r.get('Properties', {}).get('PolicyDocument', {}).get('Statement', []):
        if stmt.get('Effect', 'Allow') != 'Allow':
            continue
        res = stmt.get('Resource', '*')
        cond = stmt.get('Condition')
        a_list = stmt.get('Action', [])
        if isinstance(a_list, str):
            a_list = [a_list]
        for a in a_list:
            acts_detail[a] = {'resource': res, 'condition': cond}
    scoped_managed[rname] = {
        'actions': acts_detail,
        'name': r['Properties']['ManagedPolicyName'],
    }

# Map managed policy logical IDs -> roles
role_to_managed_logids = {}
for rname, r in scoped.get('Resources', {}).items():
    if r.get('Type') != 'AWS::IAM::Role':
        continue
    refs = [
        x.get('Ref')
        for x in r.get('Properties', {}).get('ManagedPolicyArns', [])
        if isinstance(x, dict) and 'Ref' in x
    ]
    role_to_managed_logids[rname] = refs


orig_roles = collect_role_policies(orig)
scoped_roles = collect_role_policies(scoped)

print("=" * 72)
print("ROLE-BY-ROLE AUDIT: cft.json  vs  scoped-cft.json")
print("=" * 72)

all_role_names = sorted(set(list(orig_roles.keys()) + list(scoped_roles.keys())))

grand_removed = set()
grand_added = set()

for rname in all_role_names:
    orig_acts = all_actions(orig_roles.get(rname, {}))

    scoped_inline_acts = all_actions(scoped_roles.get(rname, {}))
    scoped_managed_acts_detail = {}
    for logid in role_to_managed_logids.get(rname, []):
        if logid in scoped_managed:
            scoped_managed_acts_detail.update(scoped_managed[logid]['actions'])
    scoped_acts = scoped_inline_acts | set(scoped_managed_acts_detail.keys())

    removed = sorted(orig_acts - scoped_acts)
    added = sorted(scoped_acts - orig_acts)
    retained = sorted(orig_acts & scoped_acts)
    grand_removed.update(removed)
    grand_added.update(added)

    print(f"\n{'─' * 72}")
    print(f"ROLE: {rname}")

    orig_managed_arns = orig_roles.get(rname, {}).get('_managed_arns', [])
    scoped_managed_arns = scoped_roles.get(rname, {}).get('_managed_arns', [])

    print(f"  Actions — original: {len(orig_acts)}   scoped: {len(scoped_acts)}"
          f"  ({len(scoped_inline_acts)} inline + {len(scoped_managed_acts_detail)} in named managed policies)")

    if orig_managed_arns:
        print(f"  Original AWS-managed policies attached:")
        for arn in orig_managed_arns:
            print(f"    {arn}")
    if scoped_managed_arns:
        print(f"  Scoped AWS-managed policies attached (unchanged):")
        for arn in scoped_managed_arns:
            print(f"    {arn}")

    # Policy structure
    print(f"  Policy structure:")
    for k in scoped_roles.get(rname, {}):
        if k == '_managed_arns':
            continue
        cnt = len(scoped_roles[rname][k])
        size = len(json.dumps({"Version": "2012-10-17", "Statement": []}).encode())  # placeholder
        print(f"    [inline]  {k}  ({cnt} actions)")
    for logid in role_to_managed_logids.get(rname, []):
        if logid in scoped_managed:
            mp = scoped_managed[logid]
            print(f"    [managed] {mp['name']}  ({len(mp['actions'])} actions)")

    # Removed actions
    if removed:
        print(f"\n  ⛔  REMOVED ({len(removed)}) — in cft.json but ABSENT from scoped-cft.json:")
        for a in removed:
            orig_entry = None
            for k, v in orig_roles.get(rname, {}).items():
                if k == '_managed_arns':
                    continue
                if a in v:
                    orig_entry = v[a]
                    break
            res = str(orig_entry['resource'])[:70] if orig_entry else '?'
            print(f"    ✗  {a}  (was resource: {res})")
    else:
        print(f"\n  ✅  No actions removed — all original permissions retained")

    # Added actions
    if added:
        print(f"\n  ➕  ADDED ({len(added)}) — new in scoped-cft.json (from CFT source-of-truth):")
        for a in added:
            print(f"    +  {a}")

    # Scoping improvements
    # Build a flat action->entry map for scoped (inline + managed)
    scoped_all_detail = {}
    for k, v in scoped_roles.get(rname, {}).items():
        if k != '_managed_arns':
            scoped_all_detail.update(v)
    scoped_all_detail.update(scoped_managed_acts_detail)

    scoped_improvements = []
    cond_added = []
    for a in retained:
        orig_entry = None
        for k, v in orig_roles.get(rname, {}).items():
            if k == '_managed_arns':
                continue
            if a in v:
                orig_entry = v[a]
                break
        scoped_entry = scoped_all_detail.get(a)
        if not orig_entry or not scoped_entry:
            continue
        orig_res = orig_entry['resource']
        scoped_res = scoped_entry['resource']
        orig_wild = orig_res in ('*', ['*'])
        scoped_wild = scoped_res in ('*', ['*'])
        scoped_cond = scoped_entry.get('condition')
        orig_cond = orig_entry.get('condition')
        if orig_wild and not scoped_wild:
            scoped_improvements.append((a, scoped_res, scoped_cond))
        elif orig_wild and scoped_wild and scoped_cond and not orig_cond:
            cond_added.append((a, scoped_cond))

    if scoped_improvements:
        print(f"\n  🔒  Resource scoped ({len(scoped_improvements)}) — moved from Resource: * to specific ARN:")
        for a, res, cond in scoped_improvements:
            res_disp = json.dumps(res)[:80]
            cond_disp = f"\n         condition: {json.dumps(cond)[:80]}" if cond else ""
            print(f"    {a}")
            print(f"         → {res_disp}{cond_disp}")
    if cond_added:
        print(f"\n  🏷️   Condition added ({len(cond_added)}) — still Resource: * but now conditioned:")
        for a, cond in cond_added:
            print(f"    {a}  condition: {json.dumps(cond)[:80]}")

    unchanged_wild = [
        a for a in retained
        if scoped_all_detail.get(a, {}).get('resource') in ('*', ['*'])
        and not scoped_all_detail.get(a, {}).get('condition')
        and not any(
            a in v for k, v in orig_roles.get(rname, {}).items()
            if k != '_managed_arns' and v.get(a, {}).get('resource') not in ('*', ['*'])
        )
    ]
    # filter to only those that were also wildcard in original
    unchanged_wild = [
        a for a in unchanged_wild
        if any(
            a in v and v[a]['resource'] in ('*', ['*'])
            for k, v in orig_roles.get(rname, {}).items()
            if k != '_managed_arns'
        )
    ]
    if unchanged_wild:
        print(f"\n  ⚠️   Still Resource: * with no condition ({len(unchanged_wild)}):")
        for a in unchanged_wild:
            print(f"    ~  {a}")

print("\n" + "=" * 72)
print("OVERALL SUMMARY")
print("=" * 72)
all_orig_global = set()
all_scoped_global = set()
for rd in orig_roles.values():
    all_orig_global.update(all_actions(rd))
for rd in scoped_roles.values():
    all_scoped_global.update(all_actions(rd))
for mp in scoped_managed.values():
    all_scoped_global.update(mp['actions'].keys())

net_removed = all_orig_global - all_scoped_global
net_added = all_scoped_global - all_orig_global

print(f"  Original unique actions : {len(all_orig_global)}")
print(f"  Scoped unique actions   : {len(all_scoped_global)}")
print(f"  Net removed             : {len(net_removed)}")
print(f"  Net added               : {len(net_added)}")
print(f"  Retained                : {len(all_orig_global & all_scoped_global)}")

if net_removed:
    print(f"\n  ⛔  Actions in cft.json but ABSENT from scoped-cft.json:")
    for a in sorted(net_removed):
        print(f"    - {a}")
if net_added:
    print(f"\n  ➕  Actions in scoped-cft.json not in cft.json:")
    for a in sorted(net_added):
        print(f"    + {a}")
