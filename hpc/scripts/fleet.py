#!/usr/bin/env python3
"""HPC controller for INERT-MAS experiments (Alliance: rorqual, narval, fir).

Uses ONLY the ControlMaster sockets in this repository's hpc/.ssh, opened by
hpc/scripts/ssh-session.sh; never handles credentials. Everything runs under the
project's own work directory on the cluster (hpc/config/clusters.json: "work").
Every submission is appended to hpc/fetched/jobs.jsonl.

  python3 hpc/scripts/fleet.py probe   [--sites rorqual,narval]
  python3 hpc/scripts/fleet.py setup   [--sites ...]   # copy Ollama runtime + models into <work>/ollama
  python3 hpc/scripts/fleet.py pull    --sites rorqual --model qwen2.5:72b   # login node has internet
  python3 hpc/scripts/fleet.py deploy  [--sites ...]   # rsync code + manifests into <work>/repo
  python3 hpc/scripts/fleet.py submit  --site rorqual --model qwen2.5:7b --manifest hpc/manifests/smoke.yaml \
          --shard 0/4 --tag smoke --time 1:00:00
  python3 hpc/scripts/fleet.py array   --site rorqual --model qwen2.5:7b --manifest hpc/manifests/full.yaml \
          --shards 40 --tag full --time 2:59:00 --throttle 10
  python3 hpc/scripts/fleet.py status
  python3 hpc/scripts/fleet.py fetch   [--sites ...]   # outputs -> hpc/fetched/<site>/outputs
"""
import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = json.loads((ROOT / "hpc/config/clusters.json").read_text())
FETCHED = ROOT / "hpc/fetched"
JOBS = FETCHED / "jobs.jsonl"
PAYLOAD = ["src", "baselines", "adapters", "models", "hpc/slurm", "hpc/manifests"]


def ssh_opts(site):
    return ["-o", f"ControlPath={ROOT}/hpc/.ssh/{site}", "-o", "ControlMaster=no",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]


def target(site):
    return f"{CFG['username']}@{CFG['clusters'][site]['host']}"


def rsh(site, cmd, timeout=180):
    r = subprocess.run(["ssh", *ssh_opts(site), target(site), cmd], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def rsync(site, src, dst, timeout=1800, extra=()):
    e = "ssh " + " ".join(shlex.quote(x) for x in ssh_opts(site))
    return subprocess.run(["rsync", "-az", *extra, "-e", e, src, dst], timeout=timeout).returncode


def sites(arg):
    return arg.split(",") if arg else ["rorqual", "narval"]


def probe(a):
    out = {}
    for s in sites(a.sites):
        w = CFG["clusters"][s]["work"]
        code, txt = rsh(s, "hostname; "
                        f"ls -d {w} {w}/ollama/runtime/bin/ollama {w}/ollama/models 2>&1; "
                        f"[ -d {w}/ollama/models/manifests ] && find {w}/ollama/models/manifests -mindepth 3 "
                        "-maxdepth 4 -type f | sed 's|.*/library/||' | tr '\\n' ' '; echo; "
                        "for st in " + " ".join(CFG["model_store_candidates"]) + "; do [ -d $st/manifests ] && "
                        "echo STORE:$st && find $st/manifests -mindepth 3 -maxdepth 4 -type f | sed 's|.*/library/||' "
                        "| tr '\\n' ' ' && echo; done; "
                        "sinfo -h -o '%P %G %a %D' 2>/dev/null | grep -i gpu | head -4; "
                        "squeue -u $USER -h 2>/dev/null | wc -l; diskusage_report 2>/dev/null | grep -iE 'scratch|project' | head -3",
                        timeout=120)
        out[s] = {"ok": code == 0, "report": txt}
        print(f"===== {s} (rc={code})\n{txt}\n")
    FETCHED.mkdir(parents=True, exist_ok=True)
    (FETCHED / "probe.json").write_text(json.dumps(out, indent=2))


def setup(a):
    """Copy (read-only source) an Ollama runtime and the configured models into <work>/ollama."""
    models = " ".join(m.replace(":", "/") for m in (a.models.split(";") if a.models else CFG["models"]))
    for s in sites(a.sites):
        w = CFG["clusters"][s]["work"]
        runtimes = " ".join(CFG["ollama_runtime_candidates"])
        stores = " ".join(CFG["model_store_candidates"])
        script = f"""set -e
mkdir -p {w}/ollama/runtime {w}/ollama/models/manifests/registry.ollama.ai/library {w}/ollama/models/blobs {w}/repo {w}/outputs {w}/logs
if [ ! -x {w}/ollama/runtime/bin/ollama ]; then
  for r in {runtimes}; do if [ -x $r/bin/ollama ]; then rsync -a --exclude=vulkan $r/ {w}/ollama/runtime/; echo runtime:$r; break; fi; done
fi
for m in {models}; do
  name=${{m%/*}}; tag=${{m#*/}}
  dst={w}/ollama/models/manifests/registry.ollama.ai/library/$name/$tag
  [ -f $dst ] && {{ echo have:$m; continue; }}
  for st in {stores}; do
    src=$st/manifests/registry.ollama.ai/library/$name/$tag
    if [ -f $src ]; then
      mkdir -p $(dirname $dst); cp $src $dst
      for d in $(grep -o 'sha256:[0-9a-f]*' $src | sort -u); do
        b={w}/ollama/models/blobs/${{d/:/-}}; [ -f $b ] || cp $st/blobs/${{d/:/-}} $b
      done
      echo copied:$m:$st; break
    fi
  done
  [ -f $dst ] || echo missing:$m
done
du -sh {w}/ollama"""
        code, txt = rsh(s, script, timeout=7200)
        print(f"===== {s} (rc={code})\n{txt}\n")


def pull(a):
    """Pull a missing model into <work>/ollama/models with a short-lived server on the login node."""
    for s in sites(a.sites):
        w = CFG["clusters"][s]["work"]
        script = f"""set -e
export OLLAMA_MODELS={w}/ollama/models OLLAMA_HOST=127.0.0.1:$((30000 + RANDOM % 20000))
{w}/ollama/runtime/bin/ollama serve > {w}/logs/pull_$$.log 2>&1 & P=$!
trap 'kill $P' EXIT; sleep 5
{w}/ollama/runtime/bin/ollama pull {a.model} 2>&1 | tail -2"""
        code, txt = rsh(s, script, timeout=7200)
        print(f"===== {s} (rc={code})\n{txt}\n")


def code_snapshot():
    """Content hash of the deployed payload; the exact tree is archived in hpc/fetched/code/."""
    import hashlib
    import tarfile
    files = sorted(p for d in PAYLOAD + ["pyproject.toml"] for p in ([ROOT / d] if (ROOT / d).is_file()
                   else (ROOT / d).rglob("*")) if p.is_file() and "__pycache__" not in p.parts)
    h = hashlib.sha256()
    for p in files:
        h.update(str(p.relative_to(ROOT)).encode() + b"\0" + p.read_bytes())
    digest = h.hexdigest()[:12]
    out = FETCHED / "code" / f"code-{digest}.tar.gz"
    if not out.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out, "w:gz") as tf:
            for p in files:
                tf.add(p, arcname=str(p.relative_to(ROOT)))
    return digest


def deploy(a):
    for s in sites(a.sites):
        w = CFG["clusters"][s]["work"]
        rsh(s, f"mkdir -p {w}/repo/hpc {w}/outputs {w}/logs")
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
        code_hash = code_snapshot()
        rsh(s, f"echo {commit}{'-dirty' if dirty else ''}+code.{code_hash} > {w}/repo/COMMIT")
        rcs = [rsync(s, f"{ROOT}/{p}/", f"{target(s)}:{w}/repo/{p}/",
                     extra=("--exclude=__pycache__", "--exclude=upstream/.git", "--delete")) for p in PAYLOAD]
        rcs.append(rsync(s, f"{ROOT}/pyproject.toml", f"{target(s)}:{w}/repo/pyproject.toml"))
        # project venv from the Alliance wheelhouse (no internet needed on compute nodes)
        code, txt = rsh(s, f"[ -x {w}/venv/bin/python ] || (module load StdEnv/2023 python/3.12.4 && "
                           f"virtualenv --no-download {w}/venv && {w}/venv/bin/pip install --no-index -q pydantic pyyaml); "
                           f"{w}/venv/bin/python -c 'import pydantic, yaml; print(\"venv ok\", pydantic.VERSION)'",
                        timeout=900)
        print(f"{s}: deploy rc={rcs} {txt[-200:]}")


def _env(a, w, safe):
    out = f"{w}/outputs/{a.tag}/{safe}"
    env = {"INERT_ROOT": w, "MODEL": a.model, "MANIFEST": a.manifest, "OUT": out,
           "PARALLEL": str(a.parallel), "SHARDS": str(getattr(a, "shards", 1) or 1), "EXTRA": a.extra}
    if "," in a.extra:
        sys.exit("use ';' to separate extra arguments (sbatch --export splits on commas)")
    return out, "ALL," + ",".join(f"{k}={v}" for k, v in env.items())


def _record(rec):
    FETCHED.mkdir(parents=True, exist_ok=True)
    with JOBS.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print(json.dumps(rec))


def submit(a):
    """One job running shard i/n of a manifest (n=1: whole manifest)."""
    s, c = a.site, CFG["clusters"][a.site]
    w = c["work"]
    safe = a.model.replace(":", "_").replace("/", "_")
    i, n = a.shard.split("/")
    a.shards = n
    out, exports = _env(a, w, safe)
    exports += f",SHARD_INDEX={i}"
    cmd = (f"cd {w}/logs && sbatch --parsable --account={c['gpu_account']} --gres={a.gres or c['gres']} --time={a.time} "
           f"--mem={a.mem} --job-name=inert-{a.tag}-{safe[:16]} --export={shlex.quote(exports)} {w}/repo/hpc/slurm/inert_shard.sbatch")
    code, txt = rsh(s, cmd)
    _record({"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "site": s, "tag": a.tag, "model": a.model,
             "manifest": a.manifest, "shard": a.shard, "time": a.time, "rc": code, "reply": txt[-300:], "out": out})


def array(a):
    """SLURM array: one task per shard; SHARD_INDEX = SLURM_ARRAY_TASK_ID. Throttled with %."""
    s, c = a.site, CFG["clusters"][a.site]
    w = c["work"]
    safe = a.model.replace(":", "_").replace("/", "_")
    out, exports = _env(a, w, safe)
    cmd = (f"cd {w}/logs && sbatch --parsable --account={c['gpu_account']} --gres={a.gres or c['gres']} --time={a.time} "
           f"--array={a.indices or f'0-{a.shards - 1}'}%{a.throttle} --mem={a.mem} --job-name=inert-{a.tag}-{safe[:16]} "
           f"--export={shlex.quote(exports)} {w}/repo/hpc/slurm/inert_shard.sbatch")
    code, txt = rsh(s, cmd)
    _record({"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "site": s, "tag": a.tag, "model": a.model,
             "manifest": a.manifest, "shards": a.shards, "time": a.time, "rc": code, "reply": txt[-300:], "out": out})


def status(a):
    for s in sites(a.sites):
        code, txt = rsh(s, "squeue -u $USER -h -o '%i %j %T %M %l %R' | grep inert || true; "
                        "sacct -u $USER -S now-2days -n -X -o JobID,JobName%36,State,Elapsed | grep inert | tail -40")
        print(f"===== {s}\n{txt}\n")


def fetch(a):
    for s in sites(a.sites):
        w = CFG["clusters"][s]["work"]
        dst = FETCHED / s
        (dst / "outputs").mkdir(parents=True, exist_ok=True)
        rc1 = rsync(s, f"{target(s)}:{w}/outputs/", f"{dst}/outputs/")
        rc2 = rsync(s, f"{target(s)}:{w}/logs/", f"{dst}/logs/", extra=("--exclude=ollama_*",))
        print(f"{s}: fetch rc={rc1},{rc2}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("probe", "setup", "deploy", "status", "fetch", "pull"):
        p = sub.add_parser(name)
        p.add_argument("--sites")
        p.add_argument("--models", default="")
        p.add_argument("--model", default="")
    for name in ("submit", "array"):
        p = sub.add_parser(name)
        p.add_argument("--site", required=True)
        p.add_argument("--model", required=True)
        p.add_argument("--manifest", required=True)
        p.add_argument("--tag", required=True)
        p.add_argument("--parallel", type=int, default=8)
        p.add_argument("--time", default="2:59:00")
        p.add_argument("--extra", default="", help="extra run-manifest args, ';'-separated")
        p.add_argument("--mem", default="64G", help="host memory (use 128G for 70B-class models)")
        p.add_argument("--gres", default="", help="override GPU request, e.g. gpu:a100:2 for a 70B model on narval")
        if name == "submit":
            p.add_argument("--shard", default="0/1")
        else:
            p.add_argument("--shards", type=int, required=True)
            p.add_argument("--throttle", type=int, default=10)
            p.add_argument("--indices", default="", help="subset of shard indices, e.g. 2-11 or 0,3,5")
    a = ap.parse_args()
    {"probe": probe, "setup": setup, "pull": pull, "deploy": deploy, "submit": submit, "array": array,
     "status": status, "fetch": fetch}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
