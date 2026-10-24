# analyst-lab — intentionally vulnerable training target

Owner-authorised demo target for Tirith's bounded analyst loop. **Deliberately insecure. Never deploy
this outside the local lab.**

Stdlib-only Python (no pip install): `python -m http.server`-scale code in one file. All data is dummy.

## Run

```sh
docker build -t tirith-analyst-lab:vuln -f vulnerable/Dockerfile vulnerable
docker run --rm -d --name tirith-analyst-lab-vuln -p 127.0.0.1:8081:8080 tirith-analyst-lab:vuln
docker build -t tirith-analyst-lab:patched -f patched/Dockerfile patched
docker run --rm -d --name tirith-analyst-lab-patched -p 127.0.0.1:8082:8080 tirith-analyst-lab:patched
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Demo-User: demo-low' http://127.0.0.1:8081/flag   # 200
```

Or the whole demo (build, boot, baseline, analyst run, patch check, teardown):
`backend/scripts/analyst_demo.py` — see the backend README.

## Without Docker

No container runtime needed: the target is stdlib-only Python 3, so it runs straight from this
directory. `run.sh` takes the variant and the port, and always binds loopback (`BIND=127.0.0.1`),
so nothing is exposed on the LAN by default.

```sh
./run.sh vulnerable 8091 &
curl -s 127.0.0.1:8091/health                                                              # vulnerable
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Demo-User: demo-low' '127.0.0.1:8091/flag'  # 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Demo-User: demo-low' '127.0.0.1:8091/flag?as=demo-admin'  # 200
./run.sh patched 8092 &                                                                     # no bypass: 403 both ways
kill %1 %2
```

Any other environment (`PORT`, `DEMO_FLAG`, …) still applies; only `BIND`/`PORT` are set for you.
Inside the container the Dockerfiles keep `BIND=0.0.0.0`, since there the bind address lives in the
container's own network namespace.

## Accounts (synthetic, fixed in code)

| user | role | may read `/flag`? |
|---|---|---|
| `demo-low` | low | no |
| `demo-admin` | admin | yes |

Identity arrives in the `X-Demo-User` header (the demo stands in for a session cookie). No password.

## The flaw (CWE-639 / broken access control)

`vulnerable/app.py` `flag_page()` chooses the identity from `?as=` **before** any authorization check and
never compares it with the caller's identity. `GET /flag` as `demo-low` → 403; `GET /flag?as=demo-admin` →
200 with the dummy flag. Nothing else is reachable: no file read, no command, no other user's data, and the
flag is a fixed dummy string.

`patched/app.py` compares the requested identity with the authenticated one (`authz.deny` on mismatch /
missing identity) → 403 with `WWW-Authenticate: Demo`. The response deliberately does **not** say why.

## What this demonstrates and what it does not

It demonstrates an **application-layer authorization bypass**: the app hands a page to an identity that is
not the caller. It does not demonstrate host or shell compromise — the container runs as an unprivileged
user, with no shell endpoint, and the "flag" is a constant. Keep that distinction when reading analyst
evidence: a 200 with the dummy flag is app-level evidence only.

## Layout

```
vulnerable/  Dockerfile + app.py (flawed)
patched/     Dockerfile + app.py (identical except the authorization check) + authz.py
```