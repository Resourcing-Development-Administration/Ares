"""
Similitud Jaro-Winkler, portada del algoritmo estándar usado en
mcp-red-team/src/checks/manifest.ts::jaroWinkler (implementación propia allá,
misma matemática acá).
"""
from __future__ import annotations


def jaro(s1: str, s2: str) -> float:
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    match_distance = max(match_distance, 0)

    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    transpositions //= 2

    return (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0


def jaro_winkler(s1: str, s2: str, prefix_scale: float = 0.1) -> float:
    j = jaro(s1, s2)
    prefix_len = 0
    for c1, c2 in zip(s1[:4], s2[:4]):
        if c1 != c2:
            break
        prefix_len += 1
    return j + prefix_len * prefix_scale * (1 - j)


# --- squatting de nombres de tool: reglas anti-falso-positivo -----------------------------
#
# Jaro-Winkler solo, con prefijo compartido ("get_", "mcpgoat_"), da >0.82 para pares
# totalmente legítimos: get_level/set_level (0.976), read_collector/read_project_file
# (0.85), get_temperature_of_city/get_top_news_articles_nytimes (0.83). Un typosquat real
# es una EDICIÓN mínima del mismo nombre (read_file / read_fiel / readfile / un homoglifo
# unicode), no dos nombres distintos que empiezan igual.

import re as _re
import unicodedata as _ud

# verbos que forman familias CRUD/accion legítimas: un par que difiere SOLO en uno de estos
# (get_x/set_x, open_x/close_x) es diseño de API normal, no squatting.
_VERB_TOKENS = frozenset(
    "get set read write list create delete remove add put post update patch start stop open close "
    "enable disable push pull send receive load save fetch find search query run exec kill clear "
    "reset init begin end lock unlock show hide check test mount unmount import export upload "
    "download connect disconnect subscribe unsubscribe attach detach append insert drop new".split()
)


def name_tokens(name: str) -> list[str]:
    s = _re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)  # camelCase -> camel_Case
    return [t for t in _re.split(r"[^A-Za-z0-9]+", s.lower()) if t]


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    prev2 = prev
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)  # transposición adyacente cuenta como 1 edición
        prev2, prev = prev, cur
    return prev[-1]


def _skeleton(name: str) -> str:
    """Nombre sin separadores ni mayúsculas, con NFKD (colapsa homoglifos de compatibilidad)."""
    s = _ud.normalize("NFKD", name).lower()
    return _re.sub(r"[^a-z0-9]", "", s)


def squat_kind(a: str, b: str) -> str | None:
    """Devuelve por qué `a` y `b` parecen un squat ('homoglyph' | 'separator' | 'typo') o None.
    None incluye los pares legítimos: familias de verbos (get_x/set_x) y nombres que solo
    comparten prefijo."""
    if a == b:
        return None
    a_ascii, b_ascii = a.isascii(), b.isascii()
    if a_ascii != b_ascii and len(a) == len(b) and all(
            x == y or not (x.isascii() and y.isascii()) for x, y in zip(a, b)
    ):
        return "homoglyph"  # un nombre con caracteres no-ASCII en las mismas posiciones donde el otro tiene ASCII
    ta, tb = name_tokens(a), name_tokens(b)
    sa, sb = _skeleton(a), _skeleton(b)
    if sa == sb:
        return "separator"  # read_file / readFile / read-file: mismo nombre, otra grafía
    # misma cantidad de tokens y difieren en exactamente uno que es un verbo de la familia -> CRUD legítimo
    if len(ta) == len(tb):
        diff = [(x, y) for x, y in zip(ta, tb) if x != y]
        if len(diff) == 1 and diff[0][0] in _VERB_TOKENS and diff[0][1] in _VERB_TOKENS:
            return None
    # una singular/plural del mismo nombre (read_file / read_files) es normal en una API, no un squat
    if sa.rstrip("s") == sb.rstrip("s"):
        return None
    d = levenshtein(sa, sb)
    if min(len(sa), len(sb)) >= 5 and d == 1:
        return "typo"
    if min(len(sa), len(sb)) >= 12 and d == 2 and jaro_winkler(sa, sb) >= 0.95:
        return "typo"
    return None
