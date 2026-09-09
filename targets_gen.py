#!/usr/bin/env python3
"""Генератор targets.yaml из маркеров в исходном коде. Без LLM, детерминированно.

Проблема: targets.yaml легко забыть синхронизировать с кодом -- номера строк и
значения плывут при правках. Решение: пометить защищаемое одним коротким маркером
прямо в коде. Имя, значение и границы скрипт извлекает сам из объявления.

МАРКЕРЫ (ищутся как подстрока; язык комментариев не важен):

  Константа -- маркер над объявлением. id = имя константы, value = её литерал:
      // @re-target-const
      static const uint32_t LICENSE_KEY = 0x4F2A9C31;
  ->  id=LICENSE_KEY, kind=constant, value=0x4F2A9C31, weight=high

  Константа-геттер с обфусцирующим макросом (encf!/enci!) -- id = имя функции,
  value = аргумент макроса (в бинаре он зашифрован, в исходнике это эталон):
      // @re-target-const
      pub fn frame_max_foreground_ratio() -> f64 { encf!(0.35) }
  ->  id=frame_max_foreground_ratio, value=0.35
  Другие макросы задаются через --getter-macros.

  Алгоритм -- маркер над функцией. id = имя функции, диапазон = её тело:
      // @re-target-algo
      void cipher_block(uint32_t *v) { ... }
  ->  id=cipher_block, kind=algorithm, truth_ref=file:начало-конец

  Защита (антианализ) -- как algo, но kind=defense:
      // @re-target-defense
      int detect_debugger(void) { ... }

  Метаданные бинаря (один раз, где угодно; или тянутся из Cargo.toml, см. --cargo):
      // @re-binary: name=protected version=1.4.0

НЕОБЯЗАТЕЛЬНО:
  - вес после маркера:            // @re-target-const low
    (по умолчанию high -- раз помечено, значит важно)
  - переопределение id:           // @re-target-algo id=stable_name
    (id по умолчанию = имя из кода; задайте явно, если код переименуют, а
     сравнение регрессий должно продолжаться под старым id)
  - явное значение:               // @re-target-const value=42
    (нужно для голых десятичных чисел -- их автопарсер не берёт)
  - описания строками-продолжениями сразу под маркером:
        //   role: ключ проверки лицензии
        //   reveal: опознан XTEA
        //   reveal: восстановлена дельта
  - явный конец тела для языков без фигурных скобок (Python и т.п.):
        # @re-target-end

    python targets_gen.py --source truth --out truth/protected.yaml
    python targets_gen.py --source truth --out truth/protected.yaml --check
    python targets_gen.py --source truth --out truth/protected.yaml --cargo src/Cargo.toml
"""
import argparse
import re
import sys
from pathlib import Path

KIND_BY_MARK = {
    "@re-target-const": "constant",
    "@re-target-algo": "algorithm",
    "@re-target-defense": "defense",
}
MARK_END = "@re-target-end"
MARK_BIN = "@re-binary:"

TEXT_EXT = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".py", ".rs", ".go",
            ".java", ".js", ".ts", ".s", ".asm", ".S"}

# Литерал-значение справа от '='. Голые десятичные без иного контекста берём тоже,
# но только сразу после '=', где спутать с типом (u32) уже нельзя.
ASSIGN_VALUE = re.compile(r'=\s*(0[xX][0-9a-fA-F_]+|"(?:[^"\\]|\\.)*"|-?\d[\d_]*(?:\.\d+)?)')
# Имя константы: идентификатор перед ':' (Rust: NAME: T = ..) или перед '=' (C).
NAME_BEFORE_COLON = re.compile(r'([A-Za-z_]\w*)\s*:')
NAME_BEFORE_EQ = re.compile(r'([A-Za-z_]\w*)\s*=')
# Имя функции: идентификатор перед '('.
FUNC_NAME = re.compile(r'([A-Za-z_]\w*)\s*\(')

# Константа-геттер с обфусцирующим макросом:
#   pub fn frame_max_foreground_ratio() -> f64 { encf!(0.35) }
# Значение в бинаре зашифровано макросом -- в исходнике оно и есть эталон (truth).
# Набор макросов настраивается через --getter-macros.
GETTER_MACROS = ["encf", "enci"]


def getter_re(macros):
    # Тело геттера может иметь суффикс после макроса: { enci!(20) as usize }.
    # Поэтому НЕ требуем закрывающую '}' сразу за макросом -- достаточно enc!(VALUE).
    names = "|".join(re.escape(m) for m in macros)
    return re.compile(
        r'fn\s+([A-Za-z_]\w*)\s*\(\s*\)\s*->\s*[^{;]+\{\s*'
        r'(?:' + names + r')\s*!\s*\(\s*(.+?)\s*\)')


def is_text_file(path):
    if path.suffix.lower() in TEXT_EXT:
        return True
    try:
        return b"\x00" not in path.read_bytes()[:2048]
    except OSError:
        return False


def marker_options(rest):
    """'low id=foo value=42' -> ('low'-как-weight + {id:foo, value:42})."""
    weight = None
    opts = {}
    for tok in rest.split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            opts[k] = v
        elif tok in ("high", "medium", "low"):
            weight = tok
    return weight, opts


def const_name_and_value(code_lines, start, getter):
    """Из объявления под маркером достаёт (имя, значение, № строки).

    Понимает две формы:
      обычную:      static const T NAME = VALUE;   /   const NAME: T = VALUE;
      геттер:       fn NAME() -> T { encf!(VALUE) } -- обфусцированная константа.
    Многострочный геттер тоже ловим (склеиваем несколько строк).
    """
    # Окно поиска обрываем на следующем маркере: объявление принадлежит ЭТОМУ
    # маркеру, и парсер не должен перескочить на чужой геттер ниже.
    limit = start
    while limit < min(start + 4, len(code_lines)):
        if limit > start and any(m in code_lines[limit] for m in KIND_BY_MARK) \
                or MARK_END in code_lines[limit]:
            break
        limit += 1

    # Геттер сначала: у него нет '=', обычная ветка его бы пропустила.
    window = "\n".join(code_lines[start:limit])
    gm = getter.search(window)
    if gm:
        off = window[:gm.start()].count("\n")
        return gm.group(1), gm.group(2).strip(), start + off + 1

    for k in range(start, limit):
        line = code_lines[k]
        if any(m in line for m in KIND_BY_MARK) or "//" == line.strip()[:2] and "=" not in line:
            continue
        if "=" not in line:
            continue
        left = line.split("=", 1)[0]
        # Rust/typed 'NAME: Type =' -> имя ПЕРЕД первым двоеточием (первое совпадение).
        # C 'Type NAME =' -> имя это последний идентификатор перед '='.
        if ":" in left:
            m = NAME_BEFORE_COLON.search(left)
            name = m.group(1) if m else None
        else:
            names = NAME_BEFORE_EQ.findall(line)
            name = names[-1] if names else None
        vm = ASSIGN_VALUE.search(line)
        value = vm.group(1) if vm else None
        return name, value, k + 1
    return None, None, None


def func_name(code_lines, start):
    """Имя функции из сигнатуры под маркером."""
    for k in range(start, min(start + 4, len(code_lines))):
        if any(m in code_lines[k] for m in KIND_BY_MARK):
            continue
        m = FUNC_NAME.search(code_lines[k])
        if m and m.group(1) not in ("if", "for", "while", "switch", "return", "match"):
            return m.group(1), k + 1
    return None, start + 1


def brace_end(code_lines, sig_line):
    """Конец тела функции по балансу фигурных скобок. None, если {} нет (Python)."""
    depth = 0
    seen = False
    for k in range(sig_line - 1, len(code_lines)):
        for ch in code_lines[k]:
            if ch == "{":
                depth += 1; seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    return k + 1
    return None


def read_continuations(lines, i):
    """role:/reveal: строки-комментарии сразу под маркером."""
    role, reveal = None, []
    j = i + 1
    while j < len(lines):
        m = re.search(r'(role|reveal)\s*:\s*(.+?)\s*(?:\*/)?$', lines[j])
        if not m or any(mk in lines[j] for mk in KIND_BY_MARK):
            break
        if m.group(1) == "reveal":
            reveal.append(m.group(2).strip())
        else:
            role = m.group(2).strip()
        j += 1
    return role, reveal


def collect(source_root, getter_macros=GETTER_MACROS):
    getter = getter_re(getter_macros)
    source_root = Path(source_root)
    files = [source_root] if source_root.is_file() else sorted(
        p for p in source_root.rglob("*") if p.is_file())
    base = source_root if source_root.is_dir() else source_root.parent

    targets, problems, binary = [], [], {}

    for f in files:
        if f.name == ".gitignore" or not is_text_file(f):
            continue
        rel = str(f.relative_to(base)).replace("\\", "/")
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        end_marks = [n + 1 for n, ln in enumerate(lines) if MARK_END in ln]

        for i, line in enumerate(lines):
            if MARK_BIN in line:
                for tok in line.split(MARK_BIN, 1)[1].split():
                    if "=" in tok:
                        k, _, v = tok.partition("="); binary[k] = v
                continue
            mark = next((m for m in KIND_BY_MARK if m in line), None)
            if not mark:
                continue

            kind = KIND_BY_MARK[mark]
            weight, opts = marker_options(line.split(mark, 1)[1])
            role, reveal = read_continuations(lines, i)
            t = {"kind": kind, "weight": weight or "high"}
            if role:
                t["role"] = role
            if reveal:
                t["reveal_criteria"] = reveal

            if kind == "constant":
                name, value, vline = const_name_and_value(lines, i + 1, getter)
                t["id"] = opts.get("id") or name
                t["truth"] = opts.get("value") or value
                t["truth_ref"] = f"{rel}:{vline or i + 1}"
                if not t["id"]:
                    problems.append(f"{rel}:{i+1} const: не извлеклось имя -- задайте id=")
                if t["truth"] is None:
                    problems.append(f"{t.get('id','?')}: не извлеклось значение -- задайте value= "
                                    f"(голые десятичные автопарсер не берёт)")
            else:
                name, sig = func_name(lines, i + 1)
                t["id"] = opts.get("id") or name
                end = next((e for e in end_marks if e > i + 1), None) or brace_end(lines, sig)
                if end:
                    t["truth_ref"] = f"{rel}:{i + 1}-{end}"
                else:
                    t["truth_ref"] = f"{rel}:{i + 1}"
                    problems.append(f"{t.get('id','?')}: не нашёл конец тела "
                                    f"(нет {{}} и нет @re-target-end)")
                if not t["id"]:
                    problems.append(f"{rel}:{i+1} algo: не извлеклось имя функции -- задайте id=")

            targets.append(t)

    seen = {}
    for t in targets:
        seen[t.get("id")] = seen.get(t.get("id"), 0) + 1
    for tid, n in seen.items():
        if tid and n > 1:
            problems.append(f"{tid}: id встречается {n} раза -- имена целей должны быть уникальны")

    doc = {"binary": {"name": binary.get("name", "unknown"),
                      "version": binary.get("version", "0")},
           "targets": targets}
    return doc, problems


def merge_cargo(doc, cargo_path):
    """Тянет name/version из Cargo.toml, чтобы не дублировать в @re-binary."""
    text = Path(cargo_path).read_text(encoding="utf-8", errors="replace")
    in_pkg = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_pkg = s == "[package]"
            continue
        if in_pkg:
            m = re.match(r'(name|version)\s*=\s*"([^"]+)"', s)
            if m and doc["binary"].get(m.group(1)) in (None, "unknown", "0"):
                doc["binary"][m.group(1)] = m.group(2)


def diff_summary(old_path, new_doc):
    import yaml
    if not Path(old_path).is_file():
        return ["  (нового файла ещё нет -- все цели новые)"]
    old = yaml.safe_load(Path(old_path).read_text(encoding="utf-8")) or {}
    old_t = {t["id"]: t for t in old.get("targets", []) if t.get("id")}
    new_t = {t["id"]: t for t in new_doc["targets"] if t.get("id")}
    out = []
    for tid in new_t:
        if tid not in old_t:
            out.append(f"  + новая цель: {tid}")
        else:
            for k in ("truth", "truth_ref", "weight", "kind"):
                if old_t[tid].get(k) != new_t[tid].get(k):
                    out.append(f"  ~ {tid}.{k}: {old_t[tid].get(k)} -> {new_t[tid].get(k)}")
    for tid in old_t:
        if tid not in new_t:
            out.append(f"  - убрана цель: {tid} (маркер удалён или константа переименована)")
    return out or ["  (изменений нет)"]


def main():
    ap = argparse.ArgumentParser(description="Сборка targets.yaml из маркеров в коде")
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--check", action="store_true", help="показать diff и проблемы, не записывать")
    ap.add_argument("--cargo", default=None, help="Cargo.toml, откуда взять name/version бинаря")
    ap.add_argument("--getter-macros", default=",".join(GETTER_MACROS),
                    help="макросы констант-геттеров через запятую (по умолчанию encf,enci)")
    args = ap.parse_args()

    src = Path(args.source).resolve()
    if not src.exists():
        sys.exit(f"нет каталога исходников: {src}")

    macros = [m.strip() for m in args.getter_macros.split(",") if m.strip()]
    doc, problems = collect(src, macros)
    if not doc["targets"]:
        sys.exit(f"в {src} не найдено ни одного маркера @re-target-*. "
                 f"Разметьте защищаемое (см. шапку targets_gen.py).")
    if args.cargo:
        merge_cargo(doc, args.cargo)

    print(f"[i] целей: {len(doc['targets'])} "
          f"(бинарь {doc['binary']['name']} v{doc['binary']['version']})")
    for t in doc["targets"]:
        extra = t.get("truth") if t["kind"] == "constant" else t.get("truth_ref")
        print(f"    [{t['weight']:<6}] {t['kind']:<10} {str(t.get('id')):<24} {extra}")

    if problems:
        print("\n[!] проблемы разметки:")
        for p in problems:
            print(f"    - {p}")

    print("\n[i] изменения к текущему файлу:")
    for line in diff_summary(args.out, doc):
        print(line)

    if args.check:
        print("\n[i] --check: файл не записан")
        return 1 if problems else 0

    import yaml
    Path(args.out).write_text(
        yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"\n[+] записано: {args.out}")
    if problems:
        print("[!] но остались проблемы разметки (выше) -- judge.py может ошибиться на этих целях")
    return 0


if __name__ == "__main__":
    sys.exit(main())
