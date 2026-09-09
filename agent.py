#!/usr/bin/env python3
"""Агентный цикл: одна LLM разбирает бинарь в изолированном контейнере.

Модель не умеет ничего выполнять -- она только выдаёт текст. Руки здесь у этого
скрипта: он получает от модели "хочу выполнить такую-то команду", выполняет её
внутри контейнера через docker exec и возвращает вывод обратно в диалог.

Разделение намеренное:
    agent.py  -- на хосте, есть интернет и ключи от API
    контейнер -- сети нет, на запись только /work, там же анализируемый образец

Пример:
    python agent.py --sample samples/foo --model anthropic/claude-opus-4-5
    python agent.py --sample samples/foo --model openrouter/google/gemini-2.5-pro \\
                    --task "Найди, как формируется сетевой протокол" --max-turns 60
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

MAX_OUTPUT_CHARS = 20000   # сколько вывода команды отдаём модели
HEAD_TAIL = 8000           # при обрезке: столько с начала и столько с конца

# Модель и разбираемый бинарь выдают произвольный Unicode, а консоль Windows
# кодирует в cp1251/cp866. Один символ вроде "✓" ронял весь прогон на print().
# Кодировку не меняем (иначе в терминале будет каша) -- только режим ошибок.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Песочница
# ---------------------------------------------------------------------------
class Sandbox:
    """Контейнер, в котором выполняются команды модели."""

    def __init__(self, image, workdir, name, agent_label, network="none"):
        self.image = image
        self.workdir = Path(workdir).resolve()
        self.name = name
        self.agent_label = agent_label
        self.network = network
        self.started = False

    def start(self):
        self.workdir.mkdir(parents=True, exist_ok=True)
        # Мёртвый контейнер с тем же именем помешает; убираем молча.
        subprocess.run(["docker", "rm", "-f", self.name],
                       capture_output=True, check=False)
        cmd = [
            "docker", "run", "-d", "--name", self.name,
            "--network", self.network,
            "-v", f"{self.workdir}:/work",
            "-e", f"RE_AGENT={self.agent_label}",
            "-w", "/work",
            self.image, "sleep", "infinity",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"не удалось запустить контейнер:\n{res.stderr}")
        self.started = True

    def run(self, command, timeout=300):
        """Выполняет команду в контейнере. Возвращает (код возврата, вывод)."""
        # timeout внутри контейнера, а не снаружи: иначе docker exec отвалится,
        # а сам процесс продолжит жить и жрать ресурсы.
        # Именно -c, а не -lc: login-shell читает /etc/profile, который в Debian
        # перезаписывает PATH и выкидывает из него /opt/re/bin с нашими обёртками.
        wrapped = f"timeout --signal=KILL {timeout} bash -c {shlex.quote(command)}"
        res = subprocess.run(
            ["docker", "exec", "-w", "/work", self.name, "bash", "-c", wrapped],
            capture_output=True, timeout=timeout + 30,
        )
        out = (res.stdout + res.stderr).decode("utf-8", errors="replace")
        if res.returncode == 137:
            out += f"\n[оборвано по таймауту {timeout} c]"
        return res.returncode, out

    def write_file(self, path, content):
        """Кладёт файл в контейнер через stdin -- без возни с экранированием."""
        res = subprocess.run(
            ["docker", "exec", "-i", self.name, "tee", path],
            input=content.encode("utf-8"), capture_output=True,
        )
        if res.returncode != 0:
            return "ошибка записи: " + res.stderr.decode("utf-8", errors="replace")
        return f"записано {len(content)} байт в {path}"

    def read_text(self, path):
        res = subprocess.run(["docker", "exec", self.name, "cat", path],
                             capture_output=True)
        return res.stdout.decode("utf-8", errors="replace") if res.returncode == 0 else ""

    def stop(self, keep=False):
        if not self.started:
            return
        if keep:
            print(f"[i] контейнер {self.name} оставлен: docker exec -it {self.name} bash")
            return
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, check=False)


# ---------------------------------------------------------------------------
# Настоящая Raspberry Pi (необязательна)
# ---------------------------------------------------------------------------
class PiDevice:
    """Доступ к живой Raspberry Pi по SSH.

    Работает с хоста, а не из контейнера: контейнер намеренно оставлен без сети,
    и учётные данные Pi туда не попадают. Модель дёргает Pi через отдельные
    инструменты, а agent.py выполняет запрошенное и возвращает вывод.
    """

    def __init__(self, host, user, password=None, key_path=None, port=22,
                 workdir=None):
        self.host = host
        self.user = user
        self.password = password
        self.key_path = key_path
        self.port = int(port or 22)
        self.workdir = workdir or "/tmp/re-agent"
        self.client = None

    @classmethod
    def from_env(cls, run_id):
        host = os.environ.get("RE_PI_HOST", "").strip()
        if not host:
            return None
        return cls(
            host=host,
            user=os.environ.get("RE_PI_USER", "pi").strip(),
            password=os.environ.get("RE_PI_PASSWORD") or None,
            key_path=os.environ.get("RE_PI_KEY") or None,
            port=os.environ.get("RE_PI_PORT") or 22,
            workdir=os.environ.get("RE_PI_WORKDIR") or f"/tmp/re-{run_id}",
        )

    def connect(self):
        import paramiko

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # Pi в лаборатории обычно нет в known_hosts. Ключ принимаем, но печатаем
        # отпечаток -- чтобы подмену хоста можно было заметить глазами.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host, port=self.port, username=self.user,
            password=self.password,
            key_filename=self.key_path or None,
            timeout=15, allow_agent=bool(not self.password),
            look_for_keys=bool(not self.password),
        )
        self.client = client
        key = client.get_transport().get_remote_server_key()
        import hashlib
        import base64
        fp = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print(f"[i] Pi {self.user}@{self.host}:{self.port}, ключ SHA256:{fp}")
        # Каталог создаём БЕЗ перехода в него: exec() по умолчанию делает cd,
        # а переходить ещё некуда.
        code, out = self.exec(f"mkdir -p {shlex.quote(self.workdir)}",
                              timeout=15, in_workdir=False)
        if code != 0:
            raise RuntimeError(f"не создать рабочий каталог {self.workdir} на Pi: {out.strip()}")
        return self

    def exec(self, command, timeout=120, in_workdir=True):
        if self.client is None:
            self.connect()
        prefix = f"cd {shlex.quote(self.workdir)} && " if in_workdir else ""
        wrapped = (prefix +
                   f"timeout --signal=KILL {timeout} bash -c {shlex.quote(command)}")
        _, out, err = self.client.exec_command(wrapped, timeout=timeout + 20)
        text = out.read().decode("utf-8", errors="replace")
        text += err.read().decode("utf-8", errors="replace")
        code = out.channel.recv_exit_status()
        if code == 137:
            text += f"\n[оборвано по таймауту {timeout} c]"
        return code, text

    def push(self, local_path, remote_name=None):
        if self.client is None:
            self.connect()
        local = Path(local_path)
        remote = f"{self.workdir}/{remote_name or local.name}"
        sftp = self.client.open_sftp()
        try:
            sftp.put(str(local), remote)
            sftp.chmod(remote, 0o755)
        finally:
            sftp.close()
        return remote

    def pull(self, remote_path, local_path):
        if self.client is None:
            self.connect()
        sftp = self.client.open_sftp()
        try:
            sftp.get(remote_path, str(local_path))
        finally:
            sftp.close()
        return local_path

    def close(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass


def truncate(text):
    """Обрезает середину длинного вывода: голова и хвост информативнее всего."""
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    cut = len(text) - 2 * HEAD_TAIL
    return (text[:HEAD_TAIL]
            + f"\n\n... [вырезано {cut} символов из середины] ...\n"
            + "Вывод слишком велик. Сузьте его: grep, head, awk, "
            + "или пишите промежуточный результат в файл.\n\n"
            + text[-HEAD_TAIL:])


# ---------------------------------------------------------------------------
# Инструменты, которые видит модель
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": (
                "Выполнить команду в песочнице (Debian, рабочий каталог /work). "
                "Сети нет. Длинный вывод обрезается по середине -- фильтруйте сами."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "команда для bash -lc"},
                    "timeout": {"type": "integer",
                                "description": "секунд, по умолчанию 300; ghidra-analyze требует больше"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Записать файл в песочницу целиком. Надёжнее, чем heredoc в bash, "
                "когда нужен скрипт или заметка."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "абсолютный путь, обычно /work/..."},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
]

# Инструменты Pi показываем модели, только если Pi действительно настроена.
# Рассказывать про недоступное -- значит гарантированно потратить её шаги впустую.
PI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "pi_exec",
            "description": (
                "Выполнить команду на НАСТОЯЩЕЙ Raspberry Pi по SSH. Там есть железо, "
                "сеть и реальная Raspberry Pi OS -- то, чего нет в эмуляции. "
                "Рабочий каталог на Pi общий для всего прогона."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer", "description": "секунд, по умолчанию 120"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pi_push",
            "description": "Скопировать файл из рабочего каталога (/work/...) на Pi и сделать исполняемым.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "например /work/sample"},
                    "remote_name": {"type": "string", "description": "имя на Pi, необязательно"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pi_pull",
            "description": "Забрать файл с Pi в рабочий каталог, чтобы разбирать его инструментами песочницы.",
            "parameters": {
                "type": "object",
                "properties": {
                    "remote_path": {"type": "string"},
                    "name": {"type": "string", "description": "имя файла в /work, необязательно"},
                },
                "required": ["remote_path"],
            },
        },
    },
]

SYSTEM_PROMPT = """Ты опытный реверс-инженер. Разбираешь бинарь в изолированной песочнице.

Правила работы:
- Рабочий каталог /work, только он доступен на запись. Сети нет: ни pip, ни apt, ни curl.
- Действуй сам: выбирай инструменты, пиши свои скрипты, проверяй гипотезы. Не спрашивай разрешения.
- Дорогие шаги делай один раз. ghidra-analyze идёт минуты -- повторный запуск бессмыслен.
- Каждый содержательный вывод фиксируй командой re-note с честной оценкой уверенности.
- Не выдумывай. Если чего-то не установил -- так и напиши, это ценнее правдоподобной догадки.
- Закончив, запиши итог в /work/report.md: назначение бинаря, ключевые функции с адресами,
  потоки данных, что осталось неясным. Явно раздели установленное и предполагаемое.

Ниже -- описание среды, в которой ты работаешь.

"""


# ---------------------------------------------------------------------------
# Цикл
# ---------------------------------------------------------------------------
def explain_api_error(exc):
    """Переводит частые ошибки провайдеров в одну внятную строку."""
    text = str(exc)
    if "402" in text or "requires more credits" in text:
        return ("на балансе провайдера не хватает средств. Пополните счёт "
                "или возьмите модель дешевле. Для проверки самого цикла "
                "годятся бесплатные модели OpenRouter (с суффиксом :free).")
    if "401" in text or "invalid_api_key" in text or "AuthenticationError" in text:
        return "ключ не принят: проверьте значение в .env и права ключа у провайдера."
    if "429" in text or "rate_limit" in text:
        return "провайдер ограничил частоту запросов, попробуйте позже."
    if "not a valid model" in text or "NotFoundError" in text or "404" in text:
        return "провайдер не знает такой модели: сверьте имя с каталогом моделей."
    return None


def is_rate_limit(exc):
    text = str(exc).lower()
    return ("429" in text or "rate limit" in text or "rate_limit" in text
            or "ratelimit" in type(exc).__name__.lower())


def workspace_path(sandbox, path):
    """Путь /work/... внутри контейнера -> путь на хосте. Наружу не выпускает."""
    p = str(path).replace("\\", "/")
    p = p[len("/work/"):] if p.startswith("/work/") else p.lstrip("/")
    target = (sandbox.workdir / p).resolve()
    if sandbox.workdir not in target.parents and target != sandbox.workdir:
        raise ValueError(f"путь вне рабочего каталога: {path}")
    return target


WRAP_UP_MESSAGE = (
    "ВНИМАНИЕ: {reason} почти исчерпан, у тебя осталось всего несколько шагов.\n"
    "Прямо сейчас, не начиная новых исследований:\n"
    "1) запиши через re-note все существенные выводы, которые ещё не записаны;\n"
    "2) напиши итоговый /work/report.md по тому, что уже выяснил.\n"
    "Незаписанное будет потеряно: переписка после остановки не сохраняется."
)


def run_agent(model, task, sandbox, log_dir, max_turns, max_usd, cmd_timeout,
              max_tokens, max_retries, retry_delay, pi=None, wrap_at=0.75,
              use_cache=True, deps=()):
    import litellm

    def roll_cache_breakpoint(msgs):
        """Двигает точку кэширования к концу истории.

        Один брейкпоинт на системном промпте кэширует только его. Чтобы под кэш
        попадала и накопленная переписка, ставим второй на последнем результате
        инструмента и снимаем со всех предыдущих: у Anthropic лимит на число
        точек, а нужна нам всегда самая свежая.
        """
        marked = 0
        for m in reversed(msgs):
            if not isinstance(m, dict) or m.get("role") != "tool":
                continue
            content = m.get("content")
            if marked == 0:
                if isinstance(content, str):
                    m["content"] = [{"type": "text", "text": content,
                                     "cache_control": {"type": "ephemeral"}}]
                marked = 1
            elif isinstance(content, list):
                m["content"] = "".join(b.get("text", "") for b in content
                                       if isinstance(b, dict))

    tools_md = sandbox.read_text("/opt/re/TOOLS.md")
    if not tools_md:
        print("[!] не прочитал /opt/re/TOOLS.md -- модель не узнает про инструменты",
              file=sys.stderr)

    tools = TOOLS + (PI_TOOLS if pi else [])
    if pi:
        status = (f"\n\n## Статус настоящей Raspberry Pi\n\n"
                  f"ПОДКЛЮЧЕНА: {pi.user}@{pi.host}, рабочий каталог {pi.workdir}.\n"
                  f"Доступны инструменты pi_exec, pi_push, pi_pull. Это реальное железо "
                  f"с настоящей Raspberry Pi OS: работает всё, чего не может эмуляция.\n")
    else:
        status = ("\n\n## Статус настоящей Raspberry Pi\n\n"
                  "НЕ ПОДКЛЮЧЕНА. Раздел про неё в описании среды игнорируй, "
                  "инструментов pi_* у тебя нет. Динамика только через rpi-run.\n")

    # Кэширование промпта. Без него каждый шаг пересылает всю переписку заново
    # по полной цене: на 16 шагов это ~90% входных токенов -- повторы одного и
    # того же префикса. Помеченный cache_control префикс читается по 0.1 цены.
    if deps:
        status += ("\n\n## Зависимости бинаря\n\n"
                   "В /work вместе с образцом лежат файлы, нужные ему для запуска: "
                   + ", ".join(deps) + ".\n"
                   "Это НЕ часть образца, а его окружение (библиотеки, данные модели) "
                   "-- то, что доступно и настоящему атакующему. Их можно анализировать "
                   "и использовать при запуске. Для динамического запуска библиотеке "
                   ".so обычно нужен LD_LIBRARY_PATH=/work.\n")

    system_text = SYSTEM_PROMPT + tools_md + status
    if use_cache:
        system_block = [{"type": "text", "text": system_text,
                         "cache_control": {"type": "ephemeral"}}]
    else:
        system_block = system_text

    messages = [
        {"role": "system", "content": system_block},
        {"role": "user", "content": task},
    ]

    transcript = (log_dir / "transcript.jsonl").open("w", encoding="utf-8")
    readable = (log_dir / "session.md").open("w", encoding="utf-8")

    def log(kind, payload):
        transcript.write(json.dumps({"ts": time.time(), "kind": kind, **payload},
                                    ensure_ascii=False) + "\n")
        transcript.flush()

    log("start", {"model": model, "task": task})
    readable.write(f"# {model}\n\n**Задача:** {task}\n\n")

    total_usd = 0.0
    cost_known = True   # снимется, если LiteLLM не знает цен на эту модель
    wrap_sent = False   # просили ли уже подвести итог
    tok = {"in": 0, "out": 0, "cache_read": 0, "cache_write": 0}
    stop_reason = "лимит шагов"
    t0 = time.time()

    for turn in range(1, max_turns + 1):
        # Ограничение частоты -- штатная ситуация, особенно на дешёвых и
        # бесплатных моделях. Ждём и пробуем снова, а не бросаем работу.
        if use_cache:
            roll_cache_breakpoint(messages)

        resp = None
        delay = retry_delay
        for attempt in range(max_retries + 1):
            try:
                # max_tokens обязателен: без него провайдер берёт потолок модели
                # (у Opus это 64k) и отказывает, если баланса на столько не хватает.
                resp = litellm.completion(model=model, messages=messages, tools=tools,
                                          max_tokens=max_tokens)
                break
            except Exception as exc:
                if is_rate_limit(exc) and attempt < max_retries:
                    print(f"[i] лимит частоты запросов, жду {delay} c "
                          f"(попытка {attempt + 1} из {max_retries})", file=sys.stderr)
                    log("rate_limit", {"turn": turn, "attempt": attempt + 1, "delay": delay})
                    time.sleep(delay)
                    delay *= 2
                    continue
                hint = explain_api_error(exc)
                print(f"\n[!] ошибка вызова модели на шаге {turn}", file=sys.stderr)
                if hint:
                    print(f"    {hint}", file=sys.stderr)
                print(f"    подробности: {str(exc)[:400]}", file=sys.stderr)
                log("error", {"turn": turn, "error": str(exc)})
                stop_reason = hint or f"ошибка API: {str(exc)[:200]}"
                break
        if resp is None:
            break

        # Стоимость: LiteLLM обычно кладёт её прямо в ответ, и это дешевле,
        # чем пересчитывать. Для моделей, которых нет в его справочнике цен
        # (свежие и бесплатные), не выйдет ни то, ни другое.
        cost = None
        try:
            cost = (getattr(resp, "_hidden_params", None) or {}).get("response_cost")
            if cost is None:
                cost = litellm.completion_cost(completion_response=resp)
        except Exception:
            cost = None
        # Учёт токенов: без него нельзя проверить, работает ли кэш вообще.
        u = getattr(resp, "usage", None)
        if u is not None:
            def field(name):
                return getattr(u, name, None) or (u.get(name) if isinstance(u, dict) else 0) or 0
            tok["in"] += field("prompt_tokens") or field("input_tokens")
            tok["out"] += field("completion_tokens") or field("output_tokens")
            details = getattr(u, "prompt_tokens_details", None)
            cached = getattr(details, "cached_tokens", 0) if details else 0
            tok["cache_read"] += cached or field("cache_read_input_tokens")
            tok["cache_write"] += field("cache_creation_input_tokens")

        if cost is None:
            if cost_known:  # предупреждаем один раз, а не на каждом шаге
                print("[!] LiteLLM не знает цен на эту модель: --max-usd работать "
                      "не будет, следите за балансом у провайдера сами", file=sys.stderr)
            cost_known = False
        else:
            total_usd += cost or 0.0

        msg = resp.choices[0].message
        messages.append(msg.model_dump() if hasattr(msg, "model_dump") else msg)

        if msg.content:
            print(f"\n--- шаг {turn} ({total_usd:.3f}$) ---\n{msg.content[:1500]}")
            readable.write(f"\n## Шаг {turn}\n\n{msg.content}\n")
            log("assistant", {"turn": turn, "content": msg.content})

        calls = getattr(msg, "tool_calls", None)
        if not calls:
            stop_reason = "модель закончила"
            break

        for call in calls:
            name = call.function.name
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError as exc:
                result = f"не разобрал аргументы: {exc}"
                args = {}
            else:
                if name == "bash":
                    command = args.get("command", "")
                    timeout = int(args.get("timeout") or cmd_timeout)
                    print(f"  $ {command[:200]}")
                    readable.write(f"\n```bash\n$ {command}\n```\n")
                    try:
                        code, out = sandbox.run(command, timeout=timeout)
                    except subprocess.TimeoutExpired:
                        code, out = -1, "[docker exec не ответил вовремя]"
                    result = truncate(out) or f"(пусто, код возврата {code})"
                    readable.write(f"\n<details><summary>вывод ({len(out)} симв.)"
                                   f"</summary>\n\n```\n{out[:4000]}\n```\n</details>\n")
                elif name == "write_file":
                    result = sandbox.write_file(args.get("path", ""), args.get("content", ""))
                    print(f"  > {result}")
                    readable.write(f"\n`{result}`\n")
                elif name in ("pi_exec", "pi_push", "pi_pull") and pi:
                    try:
                        if name == "pi_exec":
                            command = args.get("command", "")
                            print(f"  pi$ {command[:200]}")
                            readable.write(f"\n```bash\n[Raspberry Pi] $ {command}\n```\n")
                            code, out = pi.exec(command, int(args.get("timeout") or 120))
                            result = truncate(out) or f"(пусто, код возврата {code})"
                            readable.write(f"\n<details><summary>вывод с Pi ({len(out)} симв.)"
                                           f"</summary>\n\n```\n{out[:4000]}\n```\n</details>\n")
                        elif name == "pi_push":
                            local = workspace_path(sandbox, args.get("path", ""))
                            remote = pi.push(local, args.get("remote_name"))
                            result = f"скопировано на Pi: {remote}"
                            print(f"  > {result}")
                            readable.write(f"\n`{result}`\n")
                        else:
                            remote = args.get("remote_path", "")
                            local = workspace_path(sandbox, args.get("name") or Path(remote).name)
                            pi.pull(remote, local)
                            result = f"забрано с Pi в /work/{local.name}"
                            print(f"  > {result}")
                            readable.write(f"\n`{result}`\n")
                    except Exception as exc:
                        result = f"ошибка работы с Pi: {exc}"
                        print(f"  [!] {result}", file=sys.stderr)
                else:
                    result = f"неизвестный инструмент: {name}"

            log("tool", {"turn": turn, "tool": name, "args": args, "result": result[:4000]})
            messages.append({"role": "tool", "tool_call_id": call.id,
                             "name": name, "content": result})

        readable.flush()

        # Мягкая посадка. Жёсткий обрыв по лимиту уничтожает всю работу: она
        # живёт в переписке, а переписка после остановки выбрасывается. Поэтому
        # заранее оставляем модели запас на то, чтобы записать выводы на диск.
        near_budget = bool(max_usd) and cost_known and total_usd >= max_usd * wrap_at
        near_turns = turn >= max_turns * wrap_at
        if (near_budget or near_turns) and not wrap_sent:
            wrap_sent = True
            reason = "бюджет" if near_budget else "лимит шагов"
            messages.append({"role": "user", "content": WRAP_UP_MESSAGE.format(reason=reason)})
            print(f"[i] {reason} на исходе -- прошу модель подвести итог", flush=True)
            log("wrap_up", {"turn": turn, "reason": reason, "usd": round(total_usd, 4)})
            continue

        if max_usd and cost_known and total_usd >= max_usd:
            stop_reason = f"исчерпан бюджет {max_usd}$"
            break

    transcript.close()
    readable.close()

    # Страховка: если отчёта нет, выкладываем рассуждения модели на диск.
    # Пусть это черновик, но лучше черновик, чем ничего.
    if not (log_dir / "report.md").is_file():
        notes = [m for m in messages
                 if (m.get("role") if isinstance(m, dict) else getattr(m, "role", None)) == "assistant"]
        texts = []
        for m in notes:
            c = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
            if c:
                texts.append(str(c))
        if texts:
            (log_dir / "unfinished_notes.md").write_text(
                f"# Незавершённый разбор: {model}\n\n"
                f"Отчёт не написан ({stop_reason}). Ниже -- рассуждения модели по ходу работы,\n"
                f"сохранённые автоматически, чтобы работа не пропала.\n\n---\n\n"
                + "\n\n---\n\n".join(texts), encoding="utf-8")
            print(f"[i] отчёта нет, черновик рассуждений сохранён в unfinished_notes.md")

    return {
        "model": model,
        "turns": turn,
        "usd": round(total_usd, 4) if cost_known else "неизвестно",
        "usd_per_turn": round(total_usd / turn, 4) if cost_known and turn else None,
        "seconds": round(time.time() - t0),
        "stop_reason": stop_reason,
        "wrap_up_sent": wrap_sent,
        "tokens": tok,
        "cache_hit_rate": (round(tok["cache_read"] / tok["in"], 3)
                           if tok["in"] else None),
    }


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Реверс-инжиниринг одной моделью")
    ap.add_argument("--sample", help="путь к бинарю на хосте")
    ap.add_argument("--deps", nargs="*", default=[],
                    help="доп. файлы, нужные бинарю (библиотеки .so, данные): "
                         "копируются в /work с исходными именами")
    ap.add_argument("--model", default="",
                    help="имя модели для LiteLLM, например anthropic/claude-opus-4-5 "
                         "или openrouter/google/gemini-2.5-pro")
    ap.add_argument("--task", default="Определи, что делает этот бинарь и как он работает.")
    ap.add_argument("--run-dir", default=None, help="каталог запуска (по умолчанию runs/<дата>)")
    ap.add_argument("--image", default="re-workbench:latest")
    ap.add_argument("--max-turns", type=int, default=80)
    ap.add_argument("--max-usd", type=float, default=5.0, help="0 -- без ограничения")
    ap.add_argument("--max-tokens", type=int, default=8192,
                    help="потолок вывода модели за один шаг; агенту столько и не нужно, "
                         "а провайдер иначе резервирует максимум модели")
    ap.add_argument("--cmd-timeout", type=int, default=300, help="секунд на команду по умолчанию")
    ap.add_argument("--max-retries", type=int, default=4,
                    help="повторов при ограничении частоты запросов")
    ap.add_argument("--retry-delay", type=int, default=20,
                    help="секунд до первого повтора, дальше удваивается")
    ap.add_argument("--keep-container", action="store_true",
                    help="не удалять контейнер после работы -- удобно для разбора полётов")
    ap.add_argument("--wrap-at", type=float, default=0.75,
                    help="доля бюджета/шагов, после которой модель просят подвести итог")
    ap.add_argument("--no-cache", action="store_true",
                    help="отключить кэширование промпта (оно экономит до 5x на входных токенах)")
    ap.add_argument("--no-pi", action="store_true",
                    help="не давать модели доступ к настоящей Pi, даже если она настроена")
    ap.add_argument("--check-pi", action="store_true",
                    help="проверить связь с Pi и выйти (--sample и --model не нужны)")
    args = ap.parse_args()

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    if args.check_pi:
        pi = PiDevice.from_env(run_id)
        if pi is None:
            sys.exit("RE_PI_HOST не задан -- Pi не настроена (см. .env.example)")
        failed = 0
        try:
            pi.connect()
            checks = [
                ("uname -a", "ядро и архитектура"),
                ("cat /etc/os-release | grep PRETTY_NAME", "версия ОС"),
                ("nproc", "ядер CPU"),
                ("df -h / | tail -1", "место на диске"),
                ("pwd", "рабочий каталог создан"),
                ("command -v strace ltrace gdb || echo '(нет ни strace, ни ltrace, ни gdb)'",
                 "средства динамического анализа"),
            ]
            for cmd, label in checks:
                code, out = pi.exec(cmd, timeout=20)
                mark = "  " if code == 0 else "!!"
                print(f"{mark} {label}:\n     {out.strip() or '(пусто)'}")
                if code != 0:
                    failed += 1
        except Exception as exc:
            sys.exit(f"[!] подключиться не удалось: {exc}")
        finally:
            pi.close()
        if failed:
            sys.exit(f"\n[!] команд с ошибкой: {failed} -- связь есть, но среда не в порядке")
        print(f"\n[+] Pi доступна и готова, рабочий каталог {pi.workdir}")
        return

    if not args.sample or not args.model:
        sys.exit("нужны --sample и --model (или --check-pi для проверки связи с Pi)")

    sample = Path(args.sample).resolve()
    if not sample.is_file():
        sys.exit(f"нет такого файла: {sample}")

    # Ключи спрашиваем до запуска контейнера: узнать о забытом ключе на первом
    # обращении к API, потратив минуту на старт Ghidra, обидно.
    # Имена переменных знает LiteLLM -- он выводит их из приставки в имени модели.
    import litellm
    # LiteLLM печатает подсказки и баннеры прямо в stderr, мимо исключений;
    # перехватить их из кода нельзя, отключается только этим флагом.
    litellm.suppress_debug_info = True

    # Модель без поддержки вызова инструментов в этом цикле бесполезна: она
    # не сможет ничего выполнить и просто поговорит с вами.
    try:
        if not litellm.supports_function_calling(model=args.model):
            print(f"[!] LiteLLM не подтверждает поддержку инструментов у {args.model}.\n"
                  f"    Если модель их не умеет, она не выполнит ни одной команды.",
                  file=sys.stderr)
    except Exception:
        pass

    env = litellm.validate_environment(model=args.model)
    if not env.get("keys_in_environment"):
        missing = " или ".join(env.get("missing_keys") or ["?"])
        sys.exit(f"не задан ключ для {args.model}: нужна переменная {missing}\n"
                 f"впишите её в .env (образец -- .env.example)")

    label = args.model.replace("/", "_").replace(":", "_")
    run_dir = Path(args.run_dir).resolve() if args.run_dir else Path("runs") / run_id
    work = run_dir / label
    work.mkdir(parents=True, exist_ok=True)

    # Копия образца: пусть модель ковыряет свой экземпляр, а не оригинал.
    target = work / "sample"
    target.write_bytes(sample.read_bytes())
    (work / "findings.jsonl").touch()

    # Зависимости бинаря (библиотеки, данные) -- копируем с ИСХОДНЫМИ именами:
    # .so ищется по SONAME, данные по имени файла, переименовывать нельзя.
    dep_names = []
    for dep in args.deps:
        dp = Path(dep).resolve()
        if not dp.is_file():
            sys.exit(f"нет файла зависимости: {dp}")
        (work / dp.name).write_bytes(dp.read_bytes())
        dep_names.append(dp.name)
    if dep_names:
        print(f"[i] зависимости: {', '.join(dep_names)} (в /work)")

    sandbox = Sandbox(
        image=args.image,
        workdir=work,
        name=f"re-{label[:30]}-{uuid.uuid4().hex[:6]}",
        agent_label=args.model,
    )

    print(f"[i] модель     : {args.model}")
    print(f"[i] образец    : {sample.name} -> {target}")
    print(f"[i] каталог    : {work}")

    # Pi необязательна. Если не настроена или отключена флагом -- модель о ней
    # даже не узнает, чтобы не тратила шаги на недоступное.
    pi = None if args.no_pi else PiDevice.from_env(run_id)
    if pi is not None:
        try:
            pi.connect()
        except Exception as exc:
            print(f"[!] Pi настроена, но недоступна: {exc}", file=sys.stderr)
            print("    продолжаю без неё; проверить связь: python agent.py --check-pi",
                  file=sys.stderr)
            pi = None
    print(f"[i] Pi         : {pi.host if pi else 'нет, только эмуляция'}")

    sandbox.start()
    print(f"[i] контейнер  : {sandbox.name}")
    try:
        summary = run_agent(args.model, args.task, sandbox, work,
                            args.max_turns, args.max_usd, args.cmd_timeout,
                            args.max_tokens, args.max_retries, args.retry_delay,
                            pi=pi, wrap_at=args.wrap_at,
                            use_cache=not args.no_cache, deps=dep_names)
    except KeyboardInterrupt:
        summary = {"model": args.model, "stop_reason": "прервано пользователем"}
    except Exception as exc:
        # Сводку пишем в любом случае: без неё непонятно даже, сколько потрачено.
        import traceback
        traceback.print_exc()
        summary = {"model": args.model,
                   "stop_reason": f"аварийное завершение: {type(exc).__name__}: {exc}"}
    finally:
        sandbox.stop(keep=args.keep_container)
        if pi is not None:
            pi.close()
    summary["pi"] = f"{pi.user}@{pi.host}" if pi else None

    findings = sum(1 for _ in (work / "findings.jsonl").open(encoding="utf-8"))
    summary["findings"] = findings
    summary["report"] = (work / "report.md").is_file()
    (work / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    for k, v in summary.items():
        print(f"  {k:<12} {v}")
    print(f"  каталог      {work}")
    if not summary["report"]:
        print("  [!] report.md не написан -- модель не довела работу до конца")


if __name__ == "__main__":
    main()
