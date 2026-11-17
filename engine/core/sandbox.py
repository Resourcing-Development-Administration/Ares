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

Filesystem (actualizado -- el párrafo viejo de esta sección quedó
desactualizado y decía lo contrario): `--ro-bind / /` deja TODO el
filesystem real de solo lectura para el target, así que la ESCRITURA ya
está cerrada (confirmado: un intento de escribir en $HOME del host da
"Read-only file system"). `--tmpfs /tmp` descarta cualquier escritura ahí
al terminar el proceso. Lo que se consideró "depende de cada caso" (y por
eso no se adivinó un allowlist de lectura general -- un command="python3"/
"node" con args arbitrarios no permite saber con seguridad qué rutas de
lectura hacen falta, y romper eso en falso sería peor que no tenerlo) sigue
sin resolverse PARA LECTURA EN GENERAL. Lo que SÍ se cerró, sin ese riesgo,
es la lectura de un puñado de rutas de ALTO VALOR y bien conocidas
(credenciales SSH/cloud, configs de otros clientes MCP) -- ver
`credential_mask_bind_args()` más abajo: en vez de intentar adivinar qué
necesita el runtime (el problema real de un jail de lectura general), se
REEMPLAZA el contenido de esas rutas puntuales por un canario sintético
antes de que el target pueda leerlas. Esto cierra el filo más afilado
(que dynamic.credential_harvest_paths exfiltre una credencial REAL del
host de Ares) sin el riesgo de falso negativo de enmascarar de más: el
propio test ahora confirma la vulnerabilidad por el canario, no por la
presencia casual de un secreto real en el host donde corre Ares.
"""
from __future__ import annotations
import os
import shutil

PRLIMIT_BIN = "prlimit"
BWRAP_BIN = "bwrap"

# Defaults generosos para cualquier server MCP legítimo (ninguno necesita más
# de 120s de CPU/256 FDs para responder un tool call) pero que sí cortan un
# ataque real contra el HOST -- distinto de test_timeout_s (que corta el TEST
# de Ares si tarda, no el proceso del target).
#
# DEFAULT_MEM_MB confirmado contra targets reales del campo de tiro (no
# teórico): 512 -- el valor de la primera versión de esto -- bloqueaba la
# conexión a TODO server MCP en Node.js (@modelcontextprotocol/sdk sobre
# V8/libnode), con 'Connection closed' sin relación alguna con la seguridad
# del target. Causa: RLIMIT_AS limita memoria VIRTUAL reservada, no memoria
# física en uso -- V8 reserva varios cientos de MB de CodeRange/heap arena al
# arrancar (antes de ejecutar una sola línea del server), aunque solo use una
# fracción real. Confirmado en este host: V8 no levanta con --as=1024MB, sí
# con --as=2048MB -- el mismo patrón aplica a cualquier runtime JIT/managed
# (JVM, .NET) por el mismo motivo. 2048 sigue cortando una bomba de memoria
# real (el objetivo de este límite) sin romper el ecosistema Node del MCP,
# que es la mayoría de los servers publicados hoy.
DEFAULT_MEM_MB = 2048
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
    ese subárbol DESPUÉS del --tmpfs /tmp en la lista de bwrap args, para que la capa
    posterior gane.

    Se restaura el PRIMER directorio bajo /tmp que contiene la ruta (ej. "/tmp/foo" para
    "/tmp/foo/bin/python"), no solo el archivo puntual -- confirmado rompiendo esto mismo
    en la práctica: un intérprete de un virtualenv creado bajo /tmp (común en CI/sandboxes,
    ej. "/tmp/ares-venv/bin/python") se resuelve bien como ejecutable, pero al importar
    falla con "ModuleNotFoundError" porque site-packages/lib del mismo venv, un par de
    directorios al lado, seguía tapado por el tmpfs -- solo se había expuesto el binario,
    no el resto del árbol del que depende en tiempo de ejecución. Restaurar el directorio
    completo (no todo /tmp) es el balance: cubre runtimes/paquetes relativos al comando sin
    regalar visibilidad de otras rutas no relacionadas que hubiera en /tmp."""
    binds = []
    seen = set()
    base = os.getcwd()
    for c in [command, *args]:
        if not isinstance(c, str) or not c:
            continue
        p = c if os.path.isabs(c) else os.path.normpath(os.path.join(base, c))
        if p == "/tmp" or p.startswith("/tmp/"):
            rest = p[len("/tmp/"):] if p != "/tmp" else ""
            top = "/tmp/" + rest.split("/", 1)[0] if rest else "/tmp"
            if top not in seen and os.path.exists(top):
                seen.add(top)
                binds += ["--ro-bind", top, top]
    return binds


def _wrap_bwrap(command: str, args: list[str], *, allow_network: bool, home: str | None,
                mask_credentials: bool) -> tuple[str, list[str]]:
    bwrap_args = [
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        *_paths_under_tmp_to_restore(command, args),
        # DESPUÉS de --tmpfs /tmp + sus restores: así gana sin importar si $HOME cae bajo /tmp
        # (poco común en producción, pero así no hace falta pensarlo -- mismo principio de
        # "capa posterior pisa a la anterior en la misma ruta" que ya usa el bloque de arriba).
        *(credential_mask_bind_args(home) if mask_credentials and home else []),
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
    allow_network: bool = False, home: str | None = None, mask_credentials: bool = True,
) -> tuple[str, list[str]]:
    """Devuelve (command, args) envueltos con las capas disponibles. El caller debe
    chequear sandbox_status() aparte para decidir si avisar cuando falta alguna --
    acá adentro, sin ninguna, se devuelve (command, args) SIN modificar (fail-open
    explícito, nunca oculto).

    `allow_network`: si True (mismo flag que ScanConfig.allow_network_side_effects),
    el subprocess SÍ tiene red real -- necesario para servers que legítimamente la
    usan, y para que adv.ssrf_exfil pueda confirmar una llamada saliente real. Si
    False (default), bwrap corta la red del todo, incluido loopback hacia el host.

    `home`: el HOME efectivo del subprocess (el que realmente va a usar -- ver
    get_default_environment()/connection['env'] en engine/core/client.py), para saber
    dónde buscar ~/.ssh, ~/.aws, etc. `mask_credentials` (default True) gatea si se
    aplica credential_mask_bind_args() sobre esas rutas -- ver docstring del módulo."""
    if prlimit_available():
        command, args = _wrap_prlimit(command, args, mem_mb=mem_mb, cpu_s=cpu_s, nproc=nproc, nofile=nofile)
    if bwrap_available():
        command, args = _wrap_bwrap(command, args, allow_network=allow_network, home=home,
                                     mask_credentials=mask_credentials)
    return command, args


# ---------------------------------------------------------------------------------------------
# Enmascarado de credenciales reales del host (ver docstring del módulo): rutas de alto valor
# que viven en su propia subcarpeta bajo $HOME (SSH, cloud, otros clientes MCP) se enmascaran
# montando un tmpfs sobre la subcarpeta y poniendo contenido FALSO con un canario fijo.
#
# Los archivos sueltos directo en $HOME (.netrc/.npmrc/.gitconfig/.bash_history/.zsh_history) de
# CREDENTIAL_HARVEST_PATHS se enmascaran aparte, con un --ro-bind por archivo (confirmado
# empíricamente: bwrap SÍ puede bind-montar un archivo falso directo sobre un archivo existente
# bajo `--ro-bind / /`, sin tocar $HOME entero -- la restricción real es solo que el archivo
# DESTINO ya exista en el host antes del bind, igual que con las subcarpetas de arriba; si no
# existe, bwrap falla con "Read-only file system" al intentar crear el nodo nuevo).

import secrets
import tempfile
import atexit

CREDENTIAL_CANARY = "ARES_SYNTHETIC_CREDENTIAL_" + "DO_NOT_USE_c7f1a4"  # fijo: no necesita ser
                                                                          # único por scan, ver sandbox.py

# subdir relativo a $HOME -> {nombre de archivo: contenido falso (con el canario embebido)}
# cada contenido imita la firma real que dynamic.credential_harvest_paths ya reconoce
# (payloads.canary.CREDENTIAL_CONTENT_SIGNATURES), para que un target que SÍ tiene el bug de
# traversal sigua devolviendo algo con pinta de credencial real -- solo que es la nuestra.
_MASKED_SUBDIRS: dict[str, dict[str, str]] = {
    ".ssh": {
        "id_rsa": f"-----BEGIN RSA PRIVATE KEY-----\n{CREDENTIAL_CANARY}\n-----END RSA PRIVATE KEY-----\n",
        "id_ed25519": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CREDENTIAL_CANARY}\n-----END OPENSSH PRIVATE KEY-----\n",
        "id_ecdsa": f"-----BEGIN EC PRIVATE KEY-----\n{CREDENTIAL_CANARY}\n-----END EC PRIVATE KEY-----\n",
    },
    ".aws": {
        "credentials": f"[default]\naws_access_key_id = {CREDENTIAL_CANARY}\naws_secret_access_key = {CREDENTIAL_CANARY}\n",
        "config": f"[default]\nregion = us-east-1\n# {CREDENTIAL_CANARY}\n",
    },
    os.path.join(".config", "gcloud"): {
        "credentials.db": CREDENTIAL_CANARY,
    },
    ".azure": {
        "credentials": f"# {CREDENTIAL_CANARY}\n",
    },
    ".docker": {
        "config.json": f'{{"auths": {{"canary.invalid": {{"auth": "{CREDENTIAL_CANARY}"}}}}}}\n',
    },
    ".cursor": {
        "mcp.json": f'{{"mcpServers": {{"ares-canary": {{"command": "{CREDENTIAL_CANARY}"}}}}}}\n',
    },
    os.path.join(".config", "claude"): {
        "claude_desktop_config.json": f'{{"mcpServers": {{"ares-canary": {{"command": "{CREDENTIAL_CANARY}"}}}}}}\n',
    },
}

# Archivos sueltos directo en $HOME (no en una subcarpeta propia) -> contenido falso. Mismo
# canario, con pinta de lo que cada archivo real tendría -- ver CREDENTIAL_HARVEST_PATHS en
# payloads/canary.py (".netrc"/".npmrc"/".gitconfig"/".bash_history"/".zsh_history").
_MASKED_HOME_FILES: dict[str, str] = {
    ".netrc": f"machine canary.invalid\nlogin ares-canary\npassword {CREDENTIAL_CANARY}\n",
    ".npmrc": f"//registry.npmjs.org/:_authToken={CREDENTIAL_CANARY}\n",
    ".gitconfig": f"[user]\n\temail = ares-canary@invalid\n[credential]\n\t# {CREDENTIAL_CANARY}\n",
    ".bash_history": f"export ARES_CANARY_TOKEN={CREDENTIAL_CANARY}\n",
    ".zsh_history": f"export ARES_CANARY_TOKEN={CREDENTIAL_CANARY}\n",
}

_staging_dirs: list[str] = []  # cleanup best-effort al salir del proceso de Ares


def _cleanup_staging():
    for d in _staging_dirs:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup_staging)


def credential_mask_bind_args(home: str) -> list[str]:
    """Args de bwrap para reemplazar el contenido de las rutas de alto valor por el canario
    (ver arriba). Solo actúa sobre una subcarpeta si YA EXISTE en el host real -- si no existe,
    bwrap no puede crear el punto de montaje bajo la raíz ya read-only (confirmado: falla con
    "Read-only file system"), y de todos modos no hay nada real que proteger ahí. Debe ir DESPUÉS
    de `--ro-bind / /` y ANTES de `--tmpfs /tmp` en la lista de bwrap args (mismo orden que
    _paths_under_tmp_to_restore: una capa posterior pisa a la anterior en la MISMA ruta)."""
    staging = tempfile.mkdtemp(prefix="ares-credmask-")
    _staging_dirs.append(staging)
    args: list[str] = []
    for subdir, files in _MASKED_SUBDIRS.items():
        real_dir = os.path.join(home, subdir)
        if not os.path.isdir(real_dir):
            continue
        args += ["--tmpfs", real_dir]
        for name, content in files.items():
            fake = os.path.join(staging, subdir.replace(os.sep, "_") + "_" + name)
            os.makedirs(os.path.dirname(fake), exist_ok=True)
            with open(fake, "w") as f:
                f.write(content)
            args += ["--ro-bind", fake, os.path.join(real_dir, name)]
    for name, content in _MASKED_HOME_FILES.items():
        real_file = os.path.join(home, name)
        if not os.path.isfile(real_file):
            continue  # bwrap no puede crear el nodo de bind si el archivo no existe ya
        fake = os.path.join(staging, "home_" + name.lstrip("."))
        with open(fake, "w") as f:
            f.write(content)
        args += ["--ro-bind", fake, real_file]
    return args
