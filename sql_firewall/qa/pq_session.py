#!/usr/bin/env python3
"""One libpq session driven by stdin, for tests that need exact protocol messages.

usage: pq_session.py USER [DBNAME]
env:   QA_LIBPQ (path to libpq.so.5), QA_CONNINFO (host, port, and dbname)

One stdin line per protocol exchange:
  exec<TAB>SQL             one simple-query message (PQexec), however many statements
  prepare<TAB>NAME<TAB>SQL a Parse message (PQprepare)
  run<TAB>NAME<TAB>V1,V2   Bind and Execute (PQexecPrepared) with text parameters
{NL} and {TAB} in SQL stand for a newline and a tab.

One stdout line per exchange: "OK", "OK rows=N: v1|v2|..." (first column of every
row of the last result), or "ERR SQLSTATE primary message".
"""
import ctypes, os, sys

lib = ctypes.CDLL(os.environ["QA_LIBPQ"])
lib.PQconnectdb.restype = ctypes.c_void_p
lib.PQconnectdb.argtypes = [ctypes.c_char_p]
lib.PQstatus.argtypes = [ctypes.c_void_p]
lib.PQerrorMessage.restype = ctypes.c_char_p
lib.PQerrorMessage.argtypes = [ctypes.c_void_p]
lib.PQexec.restype = ctypes.c_void_p
lib.PQexec.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.PQprepare.restype = ctypes.c_void_p
lib.PQprepare.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
lib.PQexecPrepared.restype = ctypes.c_void_p
lib.PQexecPrepared.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
lib.PQresultStatus.argtypes = [ctypes.c_void_p]
lib.PQresultErrorField.restype = ctypes.c_char_p
lib.PQresultErrorField.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.PQgetvalue.restype = ctypes.c_char_p
lib.PQgetvalue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
lib.PQntuples.argtypes = [ctypes.c_void_p]
lib.PQclear.argtypes = [ctypes.c_void_p]
lib.PQfinish.argtypes = [ctypes.c_void_p]


def result(res):
    status = lib.PQresultStatus(res)
    if status == 1:
        out = "OK"
    elif status == 2:
        n = lib.PQntuples(res)
        values = [lib.PQgetvalue(res, i, 0).decode(errors="replace") for i in range(n)]
        out = f"OK rows={n}: " + "|".join(values)
    else:
        state = lib.PQresultErrorField(res, ord("C"))
        msg = lib.PQresultErrorField(res, ord("M"))
        out = f"ERR {state.decode() if state else '?'} {msg.decode(errors='replace') if msg else ''}"
    lib.PQclear(res)
    return out.replace("\n", "{NL}")


def main():
    user = sys.argv[1]
    conninfo = os.environ["QA_CONNINFO"] + f" user={user}"
    if len(sys.argv) > 2:
        conninfo += f" dbname={sys.argv[2]}"
    conn = lib.PQconnectdb(conninfo.encode())
    if lib.PQstatus(conn) != 0:
        sys.stderr.write((lib.PQerrorMessage(conn) or b"connect failed").decode(errors="replace"))
        return 2
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        kind, _, rest = line.partition("\t")
        if kind == "exec":
            sql = rest.replace("{NL}", "\n").replace("{TAB}", "\t")
            print(result(lib.PQexec(conn, sql.encode())), flush=True)
        elif kind == "prepare":
            name, _, sql = rest.partition("\t")
            print(result(lib.PQprepare(conn, name.encode(), sql.encode(), 0, None)), flush=True)
        elif kind == "run":
            name, _, values = rest.partition("\t")
            vals = [v.encode() for v in values.split(",")] if values else []
            arr = (ctypes.c_char_p * len(vals))(*vals) if vals else None
            print(result(lib.PQexecPrepared(conn, name.encode(), len(vals), arr, None, None, 0)), flush=True)
        else:
            sys.stderr.write(f"unknown op {kind}\n")
            return 2
    lib.PQfinish(conn)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
