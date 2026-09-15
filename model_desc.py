#!/usr/bin/env python3
"""Разбор файла описания модели -- общий для orchestrate.py (атакующие) и
judge.py (судья). Единый источник формата, чтобы описания моделей не разъезжались.

Формат файла (models/*.txt), ключ = значение, # -- комментарий:
    name, litellm_model, litellm_budget,
    subscription_model, subscription_budget,
    preferred_run_type ('litellm' по умолчанию)
"""
from pathlib import Path


def parse_model_desc(spec):
    """Спецификация модели -> dict со всеми её настройками.

    spec -- путь к файлу описания (models/attack_claude.txt) ИЛИ прямое имя
    litellm-модели (обратная совместимость: openrouter/... трактуется как
    только-litellm).

    Настройки маршрутов симметричны: пара *_model + *_budget на каждый маршрут.
      name, litellm_model, litellm_budget,
      subscription_model, subscription_budget,
      preferred_run_type ('litellm' по умолчанию, если не задан).
    """
    base = {"name": "", "litellm_model": "", "litellm_budget": "",
            "subscription_model": "", "subscription_budget": "",
            "preferred_run_type": "litellm"}
    p = Path(spec)
    if p.is_file():
        d = dict(base)
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip().strip('"').strip("'")
        d["id"] = d.get("litellm_model") or d.get("subscription_model") or d.get("name") or spec
        return d
    d = dict(base)
    d["litellm_model"] = spec
    d["id"] = spec
    return d
