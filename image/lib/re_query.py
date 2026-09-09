#!/usr/bin/env python3
"""Быстрые запросы к дампу, который сделал ghidra-analyze.

Ghidra здесь уже не запускается -- читаем готовые файлы, ответ мгновенный.
Вызывается через обёртки ghidra-funcs / ghidra-decompile / ghidra-xrefs.
"""
import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path


def find_dump(explicit=None):
    """Находит каталог дампа: явный путь, переменная RE_GHIDRA_OUT или поиск в /work."""
    if explicit:
        p = Path(explicit)
        return p if (p / "functions.csv").is_file() else None
    env = os.environ.get("RE_GHIDRA_OUT")
    if env and (Path(env) / "functions.csv").is_file():
        return Path(env)
    candidates = sorted(Path("/work").glob("**/*.ghidra"))
    candidates = [c for c in candidates if (c / "functions.csv").is_file()]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        print("Дамп не найден. Сначала: ghidra-analyze <бинарь>", file=sys.stderr)
    else:
        print("Дампов несколько, укажите нужный через --dump или RE_GHIDRA_OUT:",
              file=sys.stderr)
        for c in candidates:
            print("  " + str(c), file=sys.stderr)
    return None


def load_funcs(dump):
    with (dump / "functions.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def norm_addr(a):
    """0x1234 / 00001234 / 1234 -> сравнимая форма."""
    a = a.strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    return a.lstrip("0") or "0"


def match_func(rows, needle):
    """Ищет функцию по адресу (в любой записи) или по имени (точно, потом подстрокой)."""
    n = norm_addr(needle)
    for r in rows:
        if norm_addr(r["address"]) == n:
            return [r]
    exact = [r for r in rows if r["name"] == needle]
    if exact:
        return exact
    low = needle.lower()
    return [r for r in rows if low in r["name"].lower()]


def cmd_funcs(args, dump):
    rows = load_funcs(dump)
    if args.pattern:
        rx = re.compile(args.pattern, re.I)
        rows = [r for r in rows if rx.search(r["name"])]
    if args.min_size:
        rows = [r for r in rows if int(r["size"]) >= args.min_size]
    if not args.include_thunks:
        rows = [r for r in rows if r["thunk"] == "0" and r["external"] == "0"]
    key = {"size": lambda r: -int(r["size"]),
           "callers": lambda r: -int(r["n_callers"]),
           "addr": lambda r: r["address"],
           "name": lambda r: r["name"].lower()}[args.sort]
    rows.sort(key=key)
    total = len(rows)
    rows = rows[:args.limit]
    print("%-12s %-46s %7s %7s %7s  %s" % ("ADDR", "NAME", "SIZE", "CALLERS", "CALLEES", "DECOMP"))
    for r in rows:
        print("%-12s %-46s %7s %7s %7s  %s" % (
            r["address"], r["name"][:46], r["size"], r["n_callers"], r["n_callees"],
            "yes" if r["decomp_file"] else "-"))
    if total > len(rows):
        print("... показано %d из %d (--limit N чтобы больше)" % (len(rows), total))
    return 0


def cmd_decompile(args, dump):
    rows = load_funcs(dump)
    hits = match_func(rows, args.target)
    if not hits:
        print("Функция не найдена: %s" % args.target, file=sys.stderr)
        print("Подсказка: ghidra-funcs -p <часть_имени>", file=sys.stderr)
        return 1
    if len(hits) > 1:
        print("Совпадений несколько, уточните:", file=sys.stderr)
        for r in hits[:20]:
            print("  %s  %s" % (r["address"], r["name"]), file=sys.stderr)
        return 1
    r = hits[0]
    if not r["decomp_file"]:
        print("Для %s (%s) псевдокода нет: thunk/внешняя или декомпиляция не удалась."
              % (r["name"], r["address"]), file=sys.stderr)
        print("Попробуйте дизассемблер: r2 -q -c 'pdf @ %s' <бинарь>" % r["address"],
              file=sys.stderr)
        return 1
    sys.stdout.write((dump / r["decomp_file"]).read_text(encoding="utf-8"))
    return 0


def cmd_xrefs(args, dump):
    data = json.loads((dump / "xrefs.json").read_text(encoding="utf-8"))
    rows = load_funcs(dump)
    hits = match_func(rows, args.target)
    if not hits:
        print("Функция не найдена: %s" % args.target, file=sys.stderr)
        return 1
    for r in hits[:10]:
        rec = data.get(r["address"], {})
        print("== %s @ %s" % (rec.get("name", r["name"]), r["address"]))
        print("  вызывают (callers): %s" % (", ".join(rec.get("callers", [])) or "-"))
        print("  вызывает (callees): %s" % (", ".join(rec.get("callees", [])) or "-"))
    return 0


def main():
    ap = argparse.ArgumentParser(description="Запросы к дампу Ghidra")
    ap.add_argument("--dump", help="каталог дампа (иначе RE_GHIDRA_OUT или автопоиск в /work)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("funcs", help="список функций")
    p.add_argument("-p", "--pattern", help="регулярка по имени")
    p.add_argument("-m", "--min-size", type=int, default=0)
    p.add_argument("-n", "--limit", type=int, default=60)
    p.add_argument("-s", "--sort", choices=["size", "callers", "addr", "name"], default="size")
    p.add_argument("--include-thunks", action="store_true")

    p = sub.add_parser("decompile", help="C-псевдокод одной функции")
    p.add_argument("target", help="адрес (0x...) или имя функции")

    p = sub.add_parser("xrefs", help="кто вызывает функцию и кого зовёт она")
    p.add_argument("target")

    args = ap.parse_args()
    dump = find_dump(args.dump)
    if dump is None:
        return 2
    return {"funcs": cmd_funcs, "decompile": cmd_decompile, "xrefs": cmd_xrefs}[args.cmd](args, dump)


if __name__ == "__main__":
    sys.exit(main())
