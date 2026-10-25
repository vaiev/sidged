#!/usr/bin/env python3
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Static checks for docker-compose.yml (V1 spec L1 / §2 Edge Transport, 0010).

Every rule applies to every service; there is no exemption for llama.
Role rules: control and worker (the Edges) each mount one read-only key
volume at /keys; llama mounts none.

- services: `control` (Edge 1), `worker` (Edges 2..n), optional `llama`;
  control and worker use the same vaikor-core image;
- one same-host network, marked internal; worker and llama only on internal
  networks, so egress can only go through the control node's gateway;
- no published ports except one UI port on `control`, bound to 127.0.0.1;
  no port 2222 (no SSH); images digest-pinned unless built locally;
- every service: numeric non-root `uid[:gid]` (0 in any spelling refused,
  compared numerically), its own uid, read-only rootfs, cap_drop [ALL], no
  cap_add, no-new-privileges, not privileged, no host networking;
- no secret-like environment variables, no env_file, no inline key material;
- key/state volume owner and mode come from `x-vaikor-volume-init`
  (applied by scripts/compose-init.sh): every named volume has an entry whose
  uid:gid is the uid:gid of the service that mounts it, mode 0700 or 0500;
- local mode (VAIKOR_LOCAL=1) is the default and the base file declares no
  secrets at all; the cloud override (--override) is the opt-in: it sets
  VAIKOR_LOCAL 0 on control and adds only file-based secrets to control;
- approval (0004 R9/R9c): `x-vaikor-approval` names a separate, non-zero
  approver uid that no service uses, and the operator-provisioned approval
  dir, which no service may mount (the Core binds its socket in it);
- networks: `edges` and `model` are internal; llama joins only `model`,
  which only control shares (the worker can't reach llama), and publishes
  nothing; control gets the `egress` network only in the cloud override;
- `--secret-file PATH` (one layout): the host secret file, placed by
  `scripts/compose-init.sh --secret`, is a regular file (not a symlink) owned
  by control's uid (the euid of the process that reads it, not the
  operator's) with mode 0400 or 0600. Under rootless podman (ENGINE=podman,
  not root) the owner is read inside `podman unshare`, i.e. in the
  container's uid namespace.
Usage: compose-check.py [--override cloud.yml] [--secret-file PATH] [docker-compose.yml]
"""
import os
import re
import stat
import sys

import yaml

SECRET = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|SEED)", re.I)
USER = re.compile(r"^([0-9]+)(?::([0-9]+))?$")
EDGES = ("control", "worker")
errors = []


def err(msg):
    errors.append(msg)


def env_items(svc):
    env = (svc or {}).get("environment") or {}
    if isinstance(env, list):
        return [tuple((e.split("=", 1) + [""])[:2]) for e in env]
    return list(env.items())


def user_ids(name, svc):
    """(uid, gid|None) as integers, or None after reporting an error."""
    user = str(svc.get("user", ""))
    m = USER.match(user)
    if not m or int(m.group(1)) == 0 or (m.group(2) is not None and int(m.group(2)) == 0):
        err(f"{name}: must run as a numeric non-root uid:gid (user={user!r})")
        return None
    return int(m.group(1)), (int(m.group(2)) if m.group(2) is not None else None)


def check_service(name, svc, internal, doc):
    ids = user_ids(name, svc)
    if svc.get("read_only") is not True:
        err(f"{name}: read_only must be true")
    if [str(c).upper() for c in svc.get("cap_drop") or []] != ["ALL"]:
        err(f"{name}: cap_drop must be [ALL]")
    if svc.get("cap_add"):
        err(f"{name}: cap_add is not allowed ({svc.get('cap_add')})")
    if "no-new-privileges:true" not in (svc.get("security_opt") or []):
        err(f"{name}: security_opt must include no-new-privileges:true")
    if svc.get("privileged") or svc.get("network_mode") == "host":
        err(f"{name}: privileged or host networking is forbidden")
    if svc.get("container_name"):
        err(f"{name}: no fixed container_name")
    joined = set(svc.get("networks") or [])
    if not joined or not joined <= internal:
        if name == "control":
            err("control: the egress network belongs in the cloud override (local mode has no route out)")
        else:
            err(f"{name}: must join only internal networks (egress only via the control gateway)")
    if name == "llama":
        if joined != {"model"}:
            err("llama: must join only the model network (shared with control only)")
    elif "edges" not in joined:
        err(f"{name}: must join the edges network")
    if name == "worker" and "model" in joined:
        err("worker: must not join the model network (llama is reachable only from control)")
    ports = svc.get("ports") or []
    for p in ports:
        if "2222" in str(p):
            err(f"{name}: port 2222 (SSH) must not be published")
    if name != "control" and ports:
        err(f"{name}: must not publish ports")
    if name == "control":
        if len(ports) != 1:
            err(f"control: exactly one (UI) port allowed, got {len(ports)}")
        for p in ports:
            if not isinstance(p, dict) or p.get("host_ip") != "127.0.0.1":
                err(f"control: UI port must use long syntax with host_ip 127.0.0.1: {p!r}")
    for k, _ in env_items(svc):
        if SECRET.search(str(k)):
            err(f"{name}: secret-like environment variable {k}")
    if svc.get("env_file"):
        err(f"{name}: env_file is not allowed; secrets come from files")
    if svc.get("secrets"):
        err(f"{name}: no secrets in the base file (local mode); use the cloud override")
    return ids


def mounts(svc):
    out = []
    for v in svc.get("volumes") or []:
        if isinstance(v, dict):
            out.append((v.get("type", "volume"), v.get("source"), v.get("target"), v.get("read_only") is True))
        else:
            parts = str(v).split(":")
            out.append(("volume", parts[0], parts[1] if len(parts) > 1 else None, "ro" in parts[2:]))
    return out


def check_override(path, base):
    doc = yaml.safe_load(open(path)) or {}
    services = doc.get("services") or {}
    for name, svc in services.items():
        if name != "control":
            if (svc or {}).get("secrets"):
                err(f"override: only control may receive secrets ({name})")
            else:
                err(f"override: only control may be changed by the cloud override ({name})")
    control = services.get("control") or {}
    extra = set(control) - {"environment", "secrets", "networks"}
    if extra:
        err(f"override: control may only change environment, networks and secrets, got {sorted(extra)}")
    env = dict(env_items(control))
    if str(env.get("VAIKOR_LOCAL", "")) != "0":
        err("override: cloud override must set VAIKOR_LOCAL 0 on control")
    declared = doc.get("secrets") or {}
    for k, v in env.items():
        if k == "VAIKOR_API_KEY_FILE":
            m = re.fullmatch(r"/run/secrets/([A-Za-z0-9_.-]+)", str(v))
            if not m or m.group(1) not in declared:
                err("override: VAIKOR_API_KEY_FILE must name a declared secret under /run/secrets/")
        elif SECRET.search(str(k)):
            err(f"override: secret-like environment variable {k}")
    base_nets = set((base.get("services") or {}).get("control", {}).get("networks") or [])
    nets = set(control.get("networks") or [])
    if "egress" not in nets or not base_nets <= nets:
        err("override: control needs the egress network in cloud mode (and keeps its base networks)")
    if set(nets) - base_nets - {"egress"}:
        err(f"override: control may only add the egress network, got {sorted(nets - base_nets)}")
    onets = doc.get("networks") or {}
    if "egress" not in onets or (onets.get("egress") or {}).get("internal"):
        err("override: the egress network must be declared (not internal) in the override")
    for key, sec in declared.items():
        if set(sec or {}) != {"file"}:
            err(f"secret {key}: must be file-based only")
    for sec in control.get("secrets") or []:
        sname = sec if isinstance(sec, str) else sec.get("source")
        if sname not in declared:
            err(f"override: secret {sname} is not declared as a file-based secret")


def secret_stat(path):
    """(kind, uid, mode) without following symlinks, in the uid namespace the
    control container sees: rootless podman maps uids, so read it inside
    `podman unshare` there."""
    engine = os.environ.get("ENGINE", "podman")
    # podman or the trusted-store wrapper; unshare through it.
    if (engine == "podman" or engine.endswith("/podman")) and os.geteuid() != 0:
        import subprocess
        out = subprocess.run(
            [engine, "unshare", "stat", "-c", "%F %u %a", "--", path],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            return None
        kind, uid, mode = out.stdout.strip().rsplit(" ", 2)
        return kind == "regular file" or kind == "regular empty file", int(uid), int(mode, 8)
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return stat.S_ISREG(st.st_mode), st.st_uid, stat.S_IMODE(st.st_mode)


def check_secret_file(path, control_uid):
    got = secret_stat(path)
    if got is None or not got[0]:
        err(f"secret file must be a regular file, not a symlink: {path}")
        return
    _, uid, mode = got
    if control_uid is None:
        err("secret file: control has no valid uid to compare with")
    elif uid != control_uid:
        err(f"secret file must be owned by control uid {control_uid} (the reading process, not the operator), got {uid}: {path}; run scripts/compose-init.sh --secret <file>")
    if mode not in (0o400, 0o600):
        err(f"secret file mode must be 0400 or 0600, got {mode:04o}: {path}")


def main(argv):
    override = secret_file = None
    args = list(argv)
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--override" and args:
            override = args.pop(0)
        elif flag == "--secret-file" and args:
            secret_file = args.pop(0)
        else:
            print(__doc__, file=sys.stderr)
            return 2
    path = args[0] if args else "docker-compose.yml"
    doc = yaml.safe_load(open(path)) or {}
    services = doc.get("services") or {}
    if not set(EDGES) <= set(services) or not set(services) <= {"control", "worker", "llama"}:
        err(f"services must be control, worker (and optional llama), got {sorted(services)}")
    images = {services[n].get("image") for n in EDGES if n in services}
    if len(images) != 1 or not all(i and "vaikor-core" in i for i in images):
        err(f"control and worker must use the same vaikor-core image, got {images}")
    for name, svc in services.items():
        image = str(svc.get("image", ""))
        built = image.startswith("localhost/vaikor-core") and "build" in services.get("control", {})
        if "@sha256:" not in image and not built:
            err(f"{name}: image must be digest-pinned (@sha256:) or built locally: {image}")

    nets = doc.get("networks") or {}
    internal = {k for k, n in nets.items() if (n or {}).get("internal") is True}
    if "edges" not in internal:
        err("the edges network must exist and be internal")
    if "llama" in services and "model" not in internal:
        err("the model network must exist and be internal")
    if doc.get("secrets"):
        err("base file must not declare secrets (local mode is the default; secrets only in the cloud override)")

    ids = {}
    for name, svc in services.items():
        ids[name] = check_service(name, svc or {}, internal, doc)
    by_uid = {}
    for name, pair in ids.items():
        if pair:
            by_uid.setdefault(pair[0], []).append(name)
    for uid, names in by_uid.items():
        if len(names) > 1:
            err(f"services {names} share uid {uid}; each service needs its own uid")

    for name in EDGES:
        env = dict(env_items(services.get(name, {})))
        if str(env.get("VAIKOR_LOCAL", "")) not in ("1", "${VAIKOR_LOCAL:-1}"):
            err(f"{name}: VAIKOR_LOCAL must default to 1 (local mode is the demo default)")

    # Key volumes (role rule) and volume owner/mode from the init table.
    init = doc.get("x-vaikor-volume-init") or {}
    vols = doc.get("volumes") or {}
    key_volumes = {}
    for name, svc in services.items():
        ms = mounts(svc)
        keys = [m for m in ms if m[2] == "/keys"]
        if name in EDGES:
            if len(keys) != 1 or keys[0][0] != "volume" or not keys[0][3]:
                err(f"{name}: needs one read-only named volume at /keys")
            else:
                key_volumes[keys[0][1]] = name
        elif keys:
            err(f"{name}: must not mount a key volume")
        for kind, src, _tgt, _ro in ms:
            if kind != "volume" or not src:
                continue
            entry = init.get(src)
            if not isinstance(entry, dict):
                err(f"volume {src}: no x-vaikor-volume-init entry (owner and mode for {name})")
                continue
            pair = ids.get(name)
            if pair and entry.get("uid") != pair[0]:
                err(f"volume {src}: init uid {entry.get('uid')} is not the uid of {name} ({pair[0]})")
            if pair and pair[1] is not None and entry.get("gid") != pair[1]:
                err(f"volume {src}: init gid {entry.get('gid')} is not the gid of {name} ({pair[1]})")
            if str(entry.get("mode")) not in ("0700", "0500"):
                err(f"volume {src}: init mode must be 0700 or 0500, got {entry.get('mode')!r}")
    for name, svc in services.items():
        for _kind, src, tgt, _ro in mounts(svc):
            if src in key_volumes and (key_volumes[src] != name or tgt != "/keys"):
                err(f"{name}: key volume {src} mounted outside its edge's /keys")
    phys = [(vols.get(k) or {}).get("name", k) for k in key_volumes]
    if len(set(phys)) != len(phys):
        err("key volumes resolve to the same physical volume name")
    if len(key_volumes) != len([n for n in EDGES if n in services]):
        err("each edge needs its own key volume (own did:key device key)")
    if not set(key_volumes) <= set(vols):
        err("key volumes must be declared as named volumes")

    # Approver model (0004 R9/R9c).
    approval = doc.get("x-vaikor-approval")
    if not isinstance(approval, dict):
        err("x-vaikor-approval is required (separate approver uid, operator-provisioned approval dir)")
    else:
        approver = approval.get("approver_uid")
        if not isinstance(approver, int) or isinstance(approver, bool) or approver <= 0:
            err(f"approver uid must be a non-zero numeric uid, got {approver!r}")
        elif approver in by_uid:
            err(f"approver uid must differ from every service uid ({approver} is {by_uid[approver]})")
        adir = str(approval.get("dir", ""))
        if not adir.startswith("/"):
            err("x-vaikor-approval dir must be an absolute path")
        for name, svc in services.items():
            for _kind, _src, tgt, _ro in mounts(svc):
                t = str(tgt or "").rstrip("/")
                if adir and (t == adir.rstrip("/") or t.startswith(adir.rstrip("/") + "/")):
                    err(f"{name}: the approval dir is operator-provisioned; no service may mount {tgt}")
            if (svc or {}).get("tmpfs") and any(str(x).split(":")[0].rstrip("/") == adir.rstrip("/") for x in svc["tmpfs"]):
                err(f"{name}: the approval dir is operator-provisioned; no service may mount {adir}")

    if override:
        check_override(override, doc)
    if secret_file:
        check_secret_file(secret_file, (ids.get("control") or (None,))[0])

    text = open(path).read()
    if re.search(r"-----BEGIN|(?<!sha256:)\b[0-9a-f]{64}\b", text):
        err("compose file contains key-like material")

    for e in errors:
        print("FAIL:", e, file=sys.stderr)
    if not errors:
        print("PASS: compose config")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
