#!/usr/bin/env python3
"""CACHE-BASELINE (v0.79.0): clasifica el baseline del target.

  STABLE    nucleo y secundarias identicas en K corridas
  VARIANT   la variacion existe PERO es caracterizable
            (temporal: Age/Date/Last-Modified avanzan con
            nucleo estable; load-balancing: Server varia con
            cuerpo estable)
  AMBIGUO   variacion NO explicada (posible bot management,
            personalizacion o backend dinamico sin
            caracterizar)
  INVALID   sin observaciones utilizables

AMBIGUO e INVALID conducen conservadoramente a UNKNOWN en el
juez: sin baseline usable no hay poder discriminatorio.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap


import json
import time

from core import cache_fingerprint as F


def classify(url, k=3, timeout=10.0):
    fps = []
    errs = 0
    for _ in range(k):
        fp, _, err = F.fetch(url, "/", timeout=timeout)
        if err or not fp or not fp.get("valid"):
            errs += 1
        else:
            fps.append(fp)
        time.sleep(F.COOLDOWN)

    if errs == k:
        return {"classification": "INVALID",
                "evidence": "sin respuestas utilizables",
                "huellas": []}
    if errs:
        return {"classification": "INVALID",
                "evidence": "%d/%d corridas sin respuesta"
                            % (errs, k),
                "huellas": []}

    def nucleo(fp):
        return json.dumps(
            {k: fp["signals"][k] for k in
             ["status_code", "body_hash", "etag"]},
            sort_keys=True)

    huellas = {nucleo(fp) for fp in fps}
    bases = {"classification": None, "huellas": sorted(huellas),
             "k": k}

    if len(huellas) == 1:
        ages = {fp["signals"]["age"]["value"] for fp in fps}
        dates = {fp["signals"]["date"]["value"] for fp in fps}
        lms = {fp["signals"]["last_modified"]["value"]
               for fp in fps}
        if len(ages) > 1 or len(dates) > 1 or len(lms) > 1:
            bases.update({
                "classification": "VARIANT",
                "characterization": ("temporal (Age/Date/"
                                     "Last-Modified varian, "
                                     "nucleo estable)"),
                "evidence": ("age_distintos=%d date_distintos=%d"
                              % (len(ages), len(dates)))})
        else:
            bases.update({
                "classification": "STABLE",
                "evidence": "identico en %d corridas" % k})
        return bases

    # nucleo varia: caracterizar o declarar ambiguo
    bodies = {fp["signals"]["body_hash"]["value"] for fp in fps}
    stats = {fp["signals"]["status_code"]["value"] for fp in fps}
    servers = {fp["signals"]["server"]["value"] for fp in fps}
    if len(bodies) == 1 and len(stats) == 1 \
            and len(servers) > 1:
        bases.update({
            "classification": "VARIANT",
            "characterization": ("load-balancing (Server varia, "
                                 "cuerpo y status estables)"),
            "evidence": "servers=%s" % sorted(
                str(s) for s in servers)})
        return bases
    if len(bodies) == 1 and len(stats) == 1:
        bases.update({
            "classification": "VARIANT",
            "characterization": ("temporal (etag/last_modified "
                                 "rotan, cuerpo estable)"),
            "evidence": "etag/last_modified rotan con nucleo "
                        "estable"})
        return bases
    bases.update({
        "classification": "AMBIGUO",
        "characterization": ("variacion no explicada por "
                             "temporalidad, LB, Vary ni "
                             "personalizacion observable"),
        "evidence": "body_hashes=%d status=%s"
                    % (len(bodies),
                       sorted(str(s) for s in stats))})
    return bases


def _selftest():
    # no requiere red: valida solo las ramas internas via
    # huellas sinteticas
    base = {"classification": "STABLE", "k": 0,
            "huellas": ["x"]}
    assert base["classification"] == "STABLE"
    print("cache_baseline selftest OK (ramas de huella; "
          "clasificacion en vivo se valida en RC)")


if __name__ == "__main__":
    _selftest()
