#!/usr/bin/env python3
"""Однократный статический дамп бинаря средствами Ghidra (PyGhidra).

Идея: Ghidra стартует и анализирует небыстро, а модели нужен мгновенный
случайный доступ. Поэтому анализируем один раз и выкладываем результат на диск
обычными файлами -- дальше агент работает через grep/cat за миллисекунды.

Раскладка результата:
    <out>/summary.txt      формат, архитектура, точка входа, секции
    <out>/functions.csv    все функции: адрес, имя, размер, вызовы
    <out>/decomp/*.c       по файлу на функцию (C-псевдокод)
    <out>/xrefs.json       граф вызовов: кто кого зовёт
    <out>/strings.txt      строки, найденные анализатором
    <out>/imports.txt      импортируемые символы по библиотекам
"""
import argparse
import csv
import json
import re
import sys
import time
import warnings
from pathlib import Path

SAFE_RE = re.compile(r"[^A-Za-z0-9_.@-]")


def safe_name(name):
    return SAFE_RE.sub("_", name)[:100]


def iter_strings(program):
    """Строки, найденные анализатором.

    API переезжал между версиями Ghidra: в 12.x это DefinedStringIterator,
    в 11.x -- метод DefinedDataIterator.definedStrings. Пробуем по очереди,
    в крайнем случае обходим листинг руками.
    """
    try:
        from ghidra.program.util import DefinedStringIterator
        return DefinedStringIterator.forProgram(program)
    except Exception:
        pass
    try:
        from ghidra.program.util import DefinedDataIterator
        return DefinedDataIterator.definedStrings(program)
    except Exception:
        pass
    return (d for d in program.getListing().getDefinedData(True) if d.hasStringValue())


def main():
    ap = argparse.ArgumentParser(description="Статический дамп бинаря через Ghidra")
    ap.add_argument("binary")
    ap.add_argument("-o", "--out", help="каталог результата (по умолчанию <binary>.ghidra)")
    ap.add_argument("--max-funcs", type=int, default=5000,
                    help="предел на число декомпилируемых функций (крупнейшие в приоритете)")
    ap.add_argument("--decomp-timeout", type=int, default=90, help="секунд на одну функцию")
    ap.add_argument("--max-strings", type=int, default=50000)
    ap.add_argument("--no-analysis", action="store_true",
                    help="не запускать автоанализ (только если проект уже проанализирован)")
    args = ap.parse_args()

    binpath = Path(args.binary).resolve()
    if not binpath.is_file():
        print("нет такого файла: %s" % binpath, file=sys.stderr)
        return 2

    out = Path(args.out).resolve() if args.out else Path(str(binpath) + ".ghidra")
    decomp_dir = out / "decomp"
    proj_dir = out / "_project"
    for d in (out, decomp_dir, proj_dir):
        d.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    print("[*] Ghidra: анализирую %s (десятки секунд для небольших бинарей, "
          "минуты для многомегабайтных)" % binpath.name, flush=True)

    # open_program() помечен устаревшим, но рабочий; предупреждение только
    # засоряет вывод, который читает модель.
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import pyghidra
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    monitor = TaskMonitor.DUMMY

    with pyghidra.open_program(
        str(binpath),
        project_location=str(proj_dir),
        project_name="re",
        analyze=not args.no_analysis,
    ) as flat:
        program = flat.getCurrentProgram()
        print("[*] анализ завершён за %.0f c" % (time.time() - t0), flush=True)

        # --- summary ------------------------------------------------------
        lang = program.getLanguage()
        entries = ", ".join(str(a) for a in program.getSymbolTable().getExternalEntryPointIterator())
        lines = [
            "file           : %s" % binpath.name,
            "size           : %d bytes" % binpath.stat().st_size,
            "format         : %s" % program.getExecutableFormat(),
            "language       : %s" % lang.getLanguageID(),
            "processor      : %s" % lang.getProcessor(),
            "endian         : %s" % ("big" if lang.isBigEndian() else "little"),
            "pointer size   : %s" % program.getDefaultPointerSize(),
            "compiler spec  : %s" % program.getCompilerSpec().getCompilerSpecID(),
            "image base     : %s" % program.getImageBase(),
            "entry points   : %s" % entries,
            "",
            "sections:",
        ]
        for b in program.getMemory().getBlocks():
            perms = "%s%s%s" % (
                "r" if b.isRead() else "-",
                "w" if b.isWrite() else "-",
                "x" if b.isExecute() else "-",
            )
            lines.append("  %-24s %s-%s %10d %s" % (
                b.getName(), b.getStart(), b.getEnd(), b.getSize(), perms))
        (out / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

        # --- функции ------------------------------------------------------
        fm = program.getFunctionManager()
        funcs = []
        for f in fm.getFunctions(True):
            funcs.append({
                "obj": f,
                "addr": str(f.getEntryPoint()),
                "name": str(f.getName()),
                "size": int(f.getBody().getNumAddresses()),
                "thunk": bool(f.isThunk()),
                "external": bool(f.isExternal()),
                "params": int(f.getParameterCount()),
            })
        print("[*] функций найдено: %d" % len(funcs), flush=True)

        # --- граф вызовов --------------------------------------------------
        xrefs = {}
        for rec in funcs:
            f = rec["obj"]
            callers = sorted(set(str(c.getName()) for c in f.getCallingFunctions(monitor)))
            callees = sorted(set(str(c.getName()) for c in f.getCalledFunctions(monitor)))
            rec["callers"] = callers
            rec["callees"] = callees
            xrefs[rec["addr"]] = {"name": rec["name"], "callers": callers, "callees": callees}
        (out / "xrefs.json").write_text(
            json.dumps(xrefs, ensure_ascii=False, indent=1), encoding="utf-8")

        # --- декомпиляция ---------------------------------------------------
        target = [r for r in funcs if not r["external"] and not r["thunk"]]
        target.sort(key=lambda r: r["size"], reverse=True)
        skipped = 0
        if len(target) > args.max_funcs:
            skipped = len(target) - args.max_funcs
            target = target[:args.max_funcs]

        ifc = DecompInterface()
        ifc.openProgram(program)
        done = 0
        for rec in target:
            fname = "%s_%s.c" % (rec["addr"], safe_name(rec["name"]))
            code = None
            try:
                res = ifc.decompileFunction(rec["obj"], args.decomp_timeout, monitor)
                if res.decompileCompleted():
                    code = str(res.getDecompiledFunction().getC())
            except Exception as exc:  # декомпилятор изредка падает на отдельных функциях
                print("[!] %s %s: %s" % (rec["addr"], rec["name"], exc), file=sys.stderr)
            if code:
                header = ("// %s @ %s  size=%d\n// callers: %s\n// callees: %s\n\n" % (
                    rec["name"], rec["addr"], rec["size"],
                    ", ".join(rec["callers"]) or "-",
                    ", ".join(rec["callees"]) or "-"))
                (decomp_dir / fname).write_text(header + code, encoding="utf-8")
                rec["decomp"] = "decomp/" + fname
                done += 1
            else:
                rec["decomp"] = ""
            if done and done % 250 == 0:
                print("    декомпилировано %d/%d" % (done, len(target)), flush=True)
        ifc.dispose()
        msg = "[*] декомпилировано %d функций" % done
        if skipped:
            msg += ", пропущено по лимиту %d" % skipped
        print(msg, flush=True)

        with (out / "functions.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["address", "name", "size", "params", "thunk", "external",
                        "n_callers", "n_callees", "decomp_file"])
            for rec in sorted(funcs, key=lambda r: r["addr"]):
                w.writerow([rec["addr"], rec["name"], rec["size"], rec["params"],
                            int(rec["thunk"]), int(rec["external"]),
                            len(rec["callers"]), len(rec["callees"]),
                            rec.get("decomp", "")])

        # Дальше каждый экспорт отгорожен своим try: сбой одного не должен
        # уносить остальные. Ровно на этом прокололась первая версия --
        # падение на строках лишило нас ещё и файла импортов.

        # --- строки ---------------------------------------------------------
        try:
            n = 0
            with (out / "strings.txt").open("w", encoding="utf-8") as fh:
                for data in iter_strings(program):
                    try:
                        val = str(data.getValue())
                    except Exception:
                        continue
                    fh.write("%s\t%s\n" % (data.getAddress(), val))
                    n += 1
                    if n >= args.max_strings:
                        break
            print("[*] строк выгружено: %d" % n, flush=True)
            if n == 0:
                print("[!] строк не найдено -- проверьте: strings <бинарь>", file=sys.stderr)
        except Exception as exc:
            print("[!] выгрузка строк не удалась: %s" % exc, file=sys.stderr)
            print("    используйте обычный strings <бинарь>", file=sys.stderr)

        # --- импорты --------------------------------------------------------
        try:
            st = program.getSymbolTable()
            imports = {}
            for sym in st.getExternalSymbols():
                lib = str(sym.getParentNamespace().getName())
                imports.setdefault(lib, []).append(str(sym.getName()))
            with (out / "imports.txt").open("w", encoding="utf-8") as fh:
                for lib in sorted(imports):
                    fh.write("[%s]\n" % lib)
                    for name in sorted(set(imports[lib])):
                        fh.write("  %s\n" % name)
            print("[*] импортов выгружено: %d" % sum(len(v) for v in imports.values()),
                  flush=True)
        except Exception as exc:
            print("[!] выгрузка импортов не удалась: %s" % exc, file=sys.stderr)

    print("\n[+] готово за %.0f c. Результат: %s" % (time.time() - t0, out))
    print("    summary.txt functions.csv decomp/ xrefs.json strings.txt imports.txt")
    print("    Дальше: ghidra-funcs, ghidra-decompile, ghidra-xrefs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
