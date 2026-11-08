# Escritura apoyada con IA
# Tooling de pruebas manuales/e2e: no es código del agente.
#
# Uso rápido:
#   just check-env        # ¿el kernel/toolchain pueden cargar los LSM BPF?
#   just capture-test     # e2e: arranca swivel, dispara eventos y verifica que llegan
#   just run              # swivel interactivo (Ctrl-C para salir)
#   just trigger-all      # (en otra terminal) genera un evento de cada tipo

set shell := ["bash", "-euo", "pipefail", "-c"]

# debug | release  →  `just profile=release capture-test`
profile := "debug"
log := env("RUST_LOG", "info")
cargo_flags := if profile == "release" { "--release" } else { "" }
bin := justfile_directory() / "target" / profile / "swivel"

# Segundos que se espera a que swivel adjunte los hooks
ready_timeout := "60"

default:
    @just --list

# Comprueba requisitos del kernel y del toolchain para cargar programas LSM BPF
check-env:
    #!/usr/bin/env bash
    set -uo pipefail
    ok=0
    lsms=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
    if [[ ",$lsms," == *",bpf,"* ]]; then
        echo "OK   LSM 'bpf' activo ($lsms)"
    else
        echo "FAIL LSM 'bpf' no está en /sys/kernel/security/lsm ('$lsms'). Añade lsm=...,bpf al cmdline."
        ok=1
    fi
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        echo "OK   BTF del kernel disponible"
    else
        echo "FAIL /sys/kernel/btf/vmlinux no existe (CONFIG_DEBUG_INFO_BTF)"
        ok=1
    fi
    if command -v bpf-linker >/dev/null; then
        rustc_llvm=$(rustc -vV | sed -n 's/^LLVM version: \([0-9]*\).*/\1/p')
        linker_llvm=$(ldd "$(command -v bpf-linker)" 2>/dev/null | sed -n 's/.*libLLVM[.-]so\.\([0-9]*\).*/\1/p; s/.*libLLVM-\([0-9]*\).*/\1/p' | head -n1 || true)
        if [[ -n "$linker_llvm" && "$rustc_llvm" != "$linker_llvm" ]]; then
            echo "FAIL LLVM de rustc ($rustc_llvm) != LLVM de bpf-linker ($linker_llvm). Ver rust-toolchain.toml"
            ok=1
        else
            echo "OK   bpf-linker presente (LLVM rustc=$rustc_llvm linker=${linker_llvm:-?})"
        fi
    else
        echo "FAIL bpf-linker no está en PATH"
        ok=1
    fi
    exit $ok

# Compila swivel (el build.rs compila y embebe spark-ebpf)
build:
    cargo build {{cargo_flags}} -p swivel

# Tests unitarios/integración de commons (sin privilegios)
unit:
    cargo test -p commons

# Ejecuta swivel en primer plano como root (Ctrl-C para salir)
run: build
    sudo env RUST_LOG={{quote(log)}} {{quote(bin)}}

# Lanza un ejecutable con nombre único → bprm_check_security
trigger-exec marker=`date +%s%N`:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d -t terrier-trigger.XXXXXX)
    trap 'rm -rf -- "$dir"' EXIT
    exe="$dir/terrier-exec-{{marker}}"
    # Script y no copia de `true`: en NixOS coreutils puede ser multicall (toybox)
    # y se niega a ejecutarse con otro nombre.
    printf '#!/bin/sh\nexit 0\n' > "$exe"
    chmod 0700 -- "$exe"
    "$exe"
    echo "exec  → $exe"

# Abre un fichero con nombre único → file_open
trigger-file marker=`date +%s%N`:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d -t terrier-trigger.XXXXXX)
    trap 'rm -rf -- "$dir"' EXIT
    f="$dir/terrier-file-{{marker}}"
    : > "$f"
    cat -- "$f" >/dev/null
    echo "open  → $f"

# connect() TCP a 127.0.0.1:<port> (nadie escucha; el hook salta igual) → socket_connect
trigger-net port="47311":
    @timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{{port}}' 2>/dev/null || true
    @echo "connect → 127.0.0.1:{{port}}"

# Un evento de cada tipo (útil con `just run` en otra terminal)
trigger-all: trigger-exec trigger-file trigger-net

# E2E: arranca swivel, dispara un evento por hook y comprueba que se capturan
capture-test: build
    #!/usr/bin/env bash
    set -euo pipefail

    work=$(mktemp -d -t terrier-capture.XXXXXX)
    logf="$work/swivel.log"
    marker="$(date +%s%N)"
    port=$(( 40000 + RANDOM % 20000 ))
    pid=""

    cleanup() {
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            sudo kill -INT "$pid" 2>/dev/null || true
            for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
            kill -0 "$pid" 2>/dev/null && sudo kill -KILL "$pid" 2>/dev/null || true
        fi
        echo "Log completo: $logf"
    }
    trap cleanup EXIT

    sudo -v   # pide la contraseña ahora, no con swivel en background

    echo "==> Arrancando swivel (log en $logf)"
    sudo env RUST_LOG={{quote(log)}} {{quote(bin)}} >"$logf" 2>&1 &
    pid=$!

    for _ in $(seq 1 $(( {{ready_timeout}} * 10 ))); do
        grep -q "Waiting for Ctrl-C" "$logf" && break
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "FAIL swivel terminó antes de estar listo:"
            tail -n 30 "$logf"
            exit 1
        fi
        sleep 0.1
    done
    if ! grep -q "Waiting for Ctrl-C" "$logf"; then
        echo "FAIL swivel no llegó a 'Waiting for Ctrl-C' en {{ready_timeout}}s"
        tail -n 30 "$logf"
        exit 1
    fi
    echo "==> Hooks adjuntos. Disparando eventos (marker=$marker, port=$port)"

    just --quiet trigger-exec "$marker"
    just --quiet trigger-file "$marker"
    just --quiet trigger-net "$port"

    sleep 1   # margen para que el reader vacíe el ring buffer

    fails=0
    check() {
        local name="$1" pattern="$2"
        if grep -qF -- "$pattern" "$logf"; then
            echo "PASS $name  (encontrado: $pattern)"
        else
            echo "FAIL $name  (no aparece: $pattern)"
            fails=$((fails + 1))
        fi
    }
    check "exec  / bprm_check_security" "terrier-exec-$marker"
    check "file  / file_open          " "terrier-file-$marker"
    check "net   / socket_connect     " "port: $port,"

    total=$(grep -c "Evento recibido" "$logf" || true)
    parse_err=$(grep -c "Evento fallado" "$logf" || true)
    echo "==> Eventos recibidos: $total | errores de parseo: $parse_err"
    if (( parse_err > 0 )); then
        echo "Primeros errores de parseo:"
        grep -m5 "Evento fallado" "$logf" || true
    fi

    exit $fails
