"""
Aislamiento de proceso para el subprocess stdio del server bajo auditoría --
DOS capas independientes, compuestas en el mismo comando:

  1. `prlimit` (util-linux) -- RLIMIT real de memoria/CPU/procesos/FDs.
  2. `bwrap`/bubblewrap -- namespaces de PID/IPC/UTS, y opcionalmente de red.

Cada una se activa por separado si el binario correspondiente está
disponible -- con las dos, el comando real queda envuelto como
`bwrap <namespaces> -- prlimit <rlimits> -- <command> <args>`; con una
sola, se envuelve solo con esa; sin ninguna, pasa sin modificar (fail-open
EXPLÍCITO -- quien llama esto decide si avisar, ver sandbox_status()).

Qué resuelve cada namespace de bwrap, confirmado empíricamente contra este
mismo host (bwrap 0.12.0; `unshare` crudo sin privilegios FALLA acá con
"Operation not permitted" -- bwrap arma su propio user namespace por
dentro y sí funciona):

  --unshare-pid: el proceso del target queda en SU PROPIO namespace de PID
    (se ve a sí mismo como PID 2) -- no puede ver, señalizar (kill/ptrace)
    ni leer /proc de Ares ni de ningún otro proceso del host. Esto es lo
    que impide que un MCP hostil "alcance a la herramienta" por la vía de
    manipulación de procesos, distinto del vector de red.
  --unshare-ipc: sin memoria compartida/semáforos/colas SysV compartidos
    con el host -- otro canal de IPC local cerrado.
  --unshare-uts: namespace de hostname propio, trivial, sin downside.
  --unshare-net (CONDICIONAL a `allow_network`): confirmado que corta TODA
    la red del subprocess, incluido loopback hacia el host -- ni siquiera
    puede llegar al dashboard de Ares si estuviera corriendo en 127.0.0.1.
    Default ON (red cortada) por el mismo criterio que ya usa
    ScanConfig.allow_network_side_effects para gatear cualquier otro
    side-effect de red saliente real (SSRF a metadata endpoints, OSV.dev,
    etc.): la mayoría de las auditorías no necesitan que el target haga
    llamadas de red reales, y cuando SÍ hace falta (adv.ssrf_exfil, un
    server que legítimamente llama una API externa) el usuario ya tiene
    que pasar --allow-network para habilitar esos tests -- se reusa esa
    MISMA decisión para levantar el corte de red del sandbox, en vez de
    inventar un flag nuevo para lo mismo.

Qué NO hace esto (alcance deliberado, no descuido): el filesystem queda
READ-WRITE, igual que antes de esta ronda. Un jail de filesystem bien hecho
(exponer solo lo que el command/runtime específico necesita) depende de
cada caso -- un command="python3"/"node"/cualquier intérprete con args
arbitrarios no permite adivinar con seguridad qué rutas hacen falta, y
romper eso en falso (un server legítimo que necesita escribir su propia
DB/cache/logs) sería peor que no tenerlo. Namespace de proceso + red es la
mitigación de mayor impacto con menor riesgo de falso negativo -- un jail
de filesystem queda deliberadamente afuera de esta ronda.
"""
from __future__ import annotations
import os
import shutil

PRLIMIT_BIN = "prlimit"
BWRAP_BIN = "bwrap"

# Defaults generosos para cualquier server MCP legítimo (ninguno necesita más
# de 512MB/120s de CPU/256 FDs para responder un tool call) pero que sí
# cortan un ataque real contra el HOST -- distinto de test_timeout_s (que
# corta el TEST de Ares si tarda, no el proceso del target).
DEFAULT_MEM_MB = 512
DEFAULT_CPU_S = 120
DEFAULT_NOFILE = 256
# RLIMIT_NPROC NO es un límite "por proceso hijo" -- es un tope sobre el TOTAL
# de procesos/threads que YA tiene el usuario (EUID) en TODO el host, kernel
# aparte. Confirmado el error de diseño de la primera versión de esto: un
# default fijo de 64 rompía CUALQUIER corrida real, porque un dev box/CI
# normal ya tiene bastante más de 64 procesos/threads del usuario corriendo
# ANTES de que Ares lance nada (59 en esta misma máquina, en un shell
# vacío). El límite tiene que ser relativo a lo que YA hay, no un número
# absoluto adivinado -- NPROC_HEADROOM es cuánto margen se le da al target
# por ENCIMA de esa base (suficiente para que spawnee threads/procesos
# normales, chico para seguir bloqueando un fork bomb real).
NPROC_HEADROOM = 200


def prlimit_available() -> bool:
    return shutil.which(PRLIMIT_BIN) is not None


def bwrap_available() -> bool:
    return shutil.which(BWRAP_BIN) is not None


def sandbox_available() -> bool:
    """True si CUALQUIERA de las dos capas puede aplicarse -- usado para decidir
    si avisar que no hay NINGUNA protección. Ver sandbox_status() para el detalle
    capa por capa (un informe de 'parcial' es más útil que un booleano solo)."""
    return prlimit_available() or bwrap_available()


def sandbox_status() -> dict:
    """Detalle de qué capas están realmente disponibles en este host, para que el
    orquestador arme un aviso preciso ('sin bwrap, el target SÍ puede ver/señalizar
    otros procesos del host' es mucho más accionable que 'sandbox no disponible')."""
    return {"prlimit": prlimit_available(), "bwrap": bwrap_available()}


def _current_user_proc_count() -> int | None:
    """Cuenta procesos/threads del EUID actual vía /proc -- None si /proc no está
    disponible (no-Linux) o no se pudo leer, para que el caller se degrade a no
    pasar --nproc en vez de adivinar un número que puede romper todo (ver arriba)."""
    try:
        uid = os.getuid()
        n = 0
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("Uid:"):
                            if int(line.split()[1]) == uid:
                                n += 1
                            break
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue  # el proceso murió entre el listdir y el open, o no es nuestro -- normal
        return n
    except Exception:
        return None


def _wrap_prlimit(
    command: str, args: list[str], *, mem_mb: int, cpu_s: int, nproc: int | None, nofile: int,
) -> tuple[str, list[str]]:
    if nproc is None:
        base = _current_user_proc_count()
        nproc = base + NPROC_HEADROOM if base is not None else None
    limit_args = [f"--as={mem_mb * 1024 * 1024}", f"--cpu={cpu_s}", f"--nofile={nofile}"]
    if nproc is not None:
        limit_args.append(f"--nproc={nproc}")
    return PRLIMIT_BIN, [*limit_args, "--", command, *args]


def _paths_under_tmp_to_restore(command: str, args: list[str]) -> list[str]:
    """`--tmpfs /tmp` (de abajo) tapa CUALQUIER cosa que ya hubiera en /tmp con un tmpfs
    vacío -- confirmado rompiendo esto mismo en la práctica: un script de prueba servido
    desde el scratchpad de la sesión (bajo /tmp/claude-.../) quedaba invisible para el
    subprocess, que ni siquiera podía encontrar su propio archivo ('No such file or
    directory'). Si command o algún arg apunta a una ruta bajo /tmp, hay que re-exponer
    ESE archivo puntual (ro-bind individual, no la carpeta entera -- no regala visibilidad
    de lo demás que haya en esa carpeta de /tmp) DESPUÉS del --tmpfs /tmp en la lista de
    bwrap args, para que la capa posterior gane."""
    binds = []
    seen = set()
    base = os.getcwd()
    for c in [command, *args]:
        if not isinstance(c, str) or not c:
            continue
        p = c if os.path.isabs(c) else os.path.normpath(os.path.join(base, c))
        if (p == "/tmp" or p.startswith("/tmp/")) and p not in seen and os.path.exists(p):
            seen.add(p)
            binds += ["--ro-bind", p, p]
    return binds


def _wrap_bwrap(command: str, args: list[str], *, allow_network: bool) -> tuple[str, list[str]]:
    bwrap_args = [
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        *_paths_under_tmp_to_restore(command, args),
        "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--die-with-parent",   # si Ares muere/es matado, el target no queda huérfano vivo
        "--new-session",       # sin control de terminal -- ni ioctls raros ni señales de sesión
    ]
    if not allow_network:
        bwrap_args.append("--unshare-net")
    return BWRAP_BIN, [*bwrap_args, "--", command, *args]


def wrap_command(
    command: str, args: list[str], *,
    mem_mb: int = DEFAULT_MEM_MB, cpu_s: int = DEFAULT_CPU_S,
    nproc: int | None = None, nofile: int = DEFAULT_NOFILE,
    allow_network: bool = False,
) -> tuple[str, list[str]]:
    """Devuelve (command, args) envueltos con las capas disponibles. El caller debe
    chequear sandbox_status() aparte para decidir si avisar cuando falta alguna --
    acá adentro, sin ninguna, se devuelve (command, args) SIN modificar (fail-open
    explícito, nunca oculto).

    `allow_network`: si True (mismo flag que ScanConfig.allow_network_side_effects),
    el subprocess SÍ tiene red real -- necesario para servers que legítimamente la
    usan, y para que adv.ssrf_exfil pueda confirmar una llamada saliente real. Si
    False (default), bwrap corta la red del todo, incluido loopback hacia el host."""
    if prlimit_available():
        command, args = _wrap_prlimit(command, args, mem_mb=mem_mb, cpu_s=cpu_s, nproc=nproc, nofile=nofile)
    if bwrap_available():
        command, args = _wrap_bwrap(command, args, allow_network=allow_network)
    return command, args
