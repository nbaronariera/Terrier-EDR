# Terrier — Documento de diseño

> **Nota de transparencia (AGENTS.md §2):** este documento ha sido redactado
> con apoyo de IA a partir de las notas y decisiones del diseñador.
> Las tablas de formato y dominio (extraídas del código de `commons`)
> y la sección final *Pendiente* son
> generadas por IA. Estado a 2026-10-19.

---

## 1. Objetivo

Terrier es un **mini-EDR** (Endpoint Detection and Response) para Linux. Observa
eventos del sistema (ejecución de procesos, acceso a ficheros y conexiones de
red) y los bloquea cuando incumplen una regla.

Las reglas son de dos tipos:

| Tipo | Dónde se evalúa | Cómo actúa | Ejemplos |
|---|---|---|---|
| **Rápida** | Dentro del eBPF (Spark), en el propio hook LSM | Deniega la operación antes de que ocurra | Acceso a carpetas protegidas, `ssh`, levantar un servidor HTTP |
| **Lenta** | En userspace (Swivel), sobre eventos acumulados | Congela o mata el proceso | Abrir y cerrar 100 ficheros seguidos |

Una regla lenta actúa siempre *después* de que la acción haya ocurrido, así que
asume cierto daño. Por eso todo lo crítico debe ser una regla rápida.

La respuesta a una regla lenta es congelar el proceso. Como mejora futura, se
estudiará volcar la memoria del proceso congelado para analizarlo.

## 2. Modelo de amenaza

Terrier está pensado para sistemas médicos y críticos que ya tienen una
defensa general (por ejemplo Wazuh) y necesitan una capa adicional, rápida y
local, para cerrar huecos concretos:

- **Movimiento lateral de usuarios válidos.** Credenciales legítimas haciendo
  cosas ilegítimas, o accediendo a lugares que no les corresponden. Esos
  "lugares" son, en principio, carpetas del sistema a las que nadie debe acceder.
  o peticiones extrañas, como escaneo de puertos o de urls.
- **Ransomware.** Detenerlo en el orden de milisegundos.
- **Conexiones de red anómalas.** Bloquearlas directamente y pedir MFA
  mediante una petición HTTP al servidor de Terrier.

Un usuario root puede detener Swivel y Spark: esto está fuera de alcance
como prevención. La caída sí debe quedar registrada como alerta.

Todavía faltan hooks LSM para cubrir todo lo anterior; se irán añadiendo.

## 3. Arquitectura

Los nombres de los componentes son motores de Kerbal Space Program.

| Componente | Crate | Entorno | Responsabilidad |
|---|---|---|---|
| **Terrier** | workspace | — | El proyecto en conjunto |
| **Spark** | `spark-ebpf` | Kernel (eBPF, `no_std`) | Hooks LSM; construye eventos y los envía al ring buffer `EVENTS`; evaluará las reglas rápidas |
| **Swivel** | `swivel` | Userspace (tokio) | Carga y adjunta Spark, lee el ring buffer, convierte los eventos y evaluará las reglas lentas |
| **commons** | `commons` | Ambos | Formato de cable compartido y modelo de dominio |

Flujo de un evento:

```
hook LSM (Spark) ──EventBuilder──▶ RingBuf EVENTS ──▶ Swivel
                                                     parse_event()  → RawEvent  (sin copia)
                                                     Event::from_raw() → Event  (dominio)
```

`commons` se compila de dos formas:

- **Por defecto (`no_std`)**, para Spark. Solo incluye `event_wire`, sin
  memoria dinámica.
- **Con la feature `user`**, para Swivel. Añade el módulo `events` (que
  necesita `alloc` porque la conversión crea un `String`) y la dependencia `aya`.

Spark no puede usar la versión `user` porque en eBPF no hay asignador de memoria.

El servidor de logs con visor TUI queda como trabajo futuro; por ahora no hace falta.

## 4. Formato de cable

Spark escribe cada evento en el ring buffer como una secuencia de bytes con
esta estructura:

```
[ RawEventHeader (24 B) ][ payload (16 B, según tipo) ][ tail (variable) ]
|<──────────────────────── total_length ────────────────────────────────>|
```

Las estructuras son `#[repr(C)]`, así que incluyen el relleno (padding) que
impone C.

**Orden de bytes:** todo va en el orden nativo excepto IPs y puertos, que
viajan en big-endian (orden de red). Spark los escribe con `.to_be()` y
`Event::from_raw` los devuelve a nativo con `from_be`.

**Versionado:** el header no lleva campo de versión. Se asume que el formato
cambiará sin retrocompatibilidad hasta que se estabilice; el versionado queda
para el futuro.

### `RawEventHeader` (24 bytes)

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `event_type` | `u8` | `EventKind`: 0 = Process, 1 = File, 2 = Net |
| 1–3 | — | padding | |
| 4 | `total_length` | `u32` | Bytes totales del evento: header + payload + tail |
| 8 | `timestamp` | `u64` | `bpf_ktime_get_ns()` (nanosegundos desde el arranque) |
| 16 | `pid` | `u32` | TGID del proceso actual |
| 20 | `uid` | `u32` | UID del proceso actual |

### `RawProcessPayload` (16 bytes) — tail: nombre del binario

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `process_id` | `u32` | TGID del proceso |
| 4 | `ancestor_id` | `u32` | TGID del padre real |
| 8 | `inode` | `u64` | Inode del ejecutable |

### `RawFilePayload` (16 bytes) — tail: nombre del fichero

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `operation` | `u8` | `FileOperation` (ver §5) |
| 1–7 | — | padding | |
| 8 | `inode` | `u64` | Inode del fichero |

### `RawNetPayload` (16 bytes) — sin tail

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `origin_ip` | `u32` | IPv4 de origen, **big-endian** |
| 4 | `target_ip` | `u32` | IPv4 de destino, **big-endian** |
| 8 | `origin_port` | `u16` | Puerto de origen, **big-endian** |
| 10 | `target_port` | `u16` | Puerto de destino, **big-endian** |
| 12 | `protocol` | `u8` | Número de protocolo IP |
| 13 | `result` | `u8` | 0 = éxito, otro = código de error |
| 14 | `direction` | `u8` | 0 = entrante, 1 = saliente |
| 15 | — | padding | |

### Tail

Son los bytes que van desde el final del payload hasta `total_length`. En
Process y File contiene el nombre leído del `dentry`. Puede acabar en `\0`;
`from_raw` lo elimina si está.

### Validación (`parse_event`)

| Error | Condición |
|---|---|
| `HeaderTruncated` | El buffer es más pequeño que el header |
| `BufferTooSmallForLength` | `total_length` es mayor que el buffer recibido |
| `UnknownEventType` | `event_type` no es un `EventKind` válido |
| `InvalidTotalLength` | `total_length` es menor que header + payload |

## 5. Modelo de dominio

`Event::from_raw` convierte un `RawEvent` en el tipo de dominio que usa Swivel:

```
Event
├── common: EventCommon { pid, uid, timestamp, host }
└── event_type: EventType
    ├── Process(ProcessEvent { process, ancestor, inode, route })
    ├── File(FileEvent { route, inode, operation: FileOperation })
    └── Net(NetEvent { origin: NetAddress, target: NetAddress,
                       protocol: NetProtocol, result: NetResult,
                       direction: NetDirection })
```

| Tipo | Valores |
|---|---|
| `FileOperation` | Open = 0, Write = 1, Read = 2, Rename = 3, Move = 4, Link = 5, Unlink = 6 |
| `NetProtocol` | ICMP = 1, TCP = 6, UDP = 17, `Unregistered(u8)` para el resto |
| `NetDirection` | Inbound (0), Outbound (1); cualquier otro valor es un error |
| `NetResult` | `Success` (0), `Failed(código)` |
| `NetAddress` | `{ ip: u32, port: u16 }`, ya en orden nativo |

Errores de conversión (`EventError`):

| Error | Condición |
|---|---|
| `MissingRoute` | Evento Process o File sin tail |
| `InvalidRouteUtf8` | El tail no es UTF-8 válido |
| `InvalidFileOperation(u8)` | `operation` fuera de rango |
| `InvalidNetDirection(u8)` | `direction` distinto de 0 y de 1 |

**TODOs del dominio:**

- `EventCommon.host` vale siempre `0`: falta obtener el host.
- `ProcessEvent` no tiene todavía los argumentos del proceso (`args`).
- Falta comprobar cómo se comporta `NetProtocol::Unregistered(u8)` con `FromRepr`.

## 6. Swivel: procesamiento de eventos

Responsabilidades de Swivel:

1. **Árbol de procesos.** Mantener un árbol de procesos general y otro por
   usuario, construidos a partir de los eventos.
2. **Reglas lentas y riesgo.** Evaluar las reglas lentas sobre los eventos y
   acumular el riesgo que generan. Cuando el riesgo llega al umbral, cerrar el
   proceso y notificar.
3. **Reglas rápidas.** Se guardan en un mapa eBPF que Spark consulta desde el
   propio hook.
4. **Modo de prueba.** Cualquier regla puede ponerse en este modo: en lugar de
   actuar, solo registra lo que habría hecho. Sirve para validar reglas antes
   de activarlas.
5. **Informar.** Mantener un websocket con el servidor de logs y visor TUI
   (futuro). Si el websocket falla, Swivel sigue funcionando.
6. **Resiliencia.** Si Swivel muere, se relanza.
7. **Parseo inicial** Swivel parsea el documento de reglas y las carga en memoria 

## 7. Límites

- El ring buffer `EVENTS` mide 8 MB (`RING_BUFFER_SIZE`) y puede ampliarse si se ve que el tamaño es insuficiente.
- Cada evento reserva siempre `MAX_EVENT_SIZE` (2 KB), aunque ocupe menos.
  Ajustar la reserva al tamaño real es complicado, así que se acepta este desperdicio.
- No se espera llenar el buffer. Si se llena, la política deseada es
  **sobrescribir el evento más antiguo y notificar**. Esto todavía no está
  implementado.

## 8. Tests

- **Unitarios y de integración** en cada crate. Ahora mismo cubren `commons`.
- **Entorno de simulación**: un contenedor con scripts que reproduzcan
  situaciones reales (ransomware, movimiento lateral, conexiones anómalas).
  Está por decidir cómo ejecutar ese contenedor.

---

## Pendiente por definir

**Implementación**
- [ ] Implementar `assemble_net` (hoy es un stub `Ok(())`). Escribir IP y
      puerto en big-endian (`.to_be()`). Definir `direction`, `result` y `protocol`.
- [ ] Test de ida y vuelta con el productor real: `EventBuilder → parse_event →
      from_raw`, para detectar divergencias de ABI. Es el hueco de tests más valioso.
- [ ] Documentar el endianness en el código (`event_wire.rs`). En este
      documento ya está, en §4.
- [ ] Consumir eventos de verdad en Swivel (hoy solo los imprime). Ver §6.
- [ ] Adjuntar en Swivel los hooks `file_open` y `socket_connect` (están
      declarados en Spark pero no se adjuntan).
- [ ] CI: `cargo test -p commons --features user` y después `--workspace`.

**§1 Objetivo**
- [ ] Mecanismo concreto para congelar y para matar procesos ("fuerza bruta"
      no basta para el diseño). Compara señales con el freezer de cgroups.
- [ ] Cómo bloquea en la práctica una regla rápida: qué debe devolver un hook
      LSM para denegar (hoy todos devuelven `0`).
- [ ] Lista inicial de reglas rápidas y reglas lentas, con sus umbrales.

**§2 Modelo de amenaza**
- [ ] Concretar qué carpetas son las "protegidas" y cómo se configuran.
- [ ] Revisa qué contiene realmente `route`. Mira de qué campo del kernel sale
      en `event_assembly.rs` y decide si basta para una regla basada en carpetas.
- [ ] Si root detiene Swivel, ¿**quién** registra la alerta de caída? Swivel
      no puede avisar de su propia muerte.
- [ ] Lista de hooks LSM que faltan para cubrir ransomware (escrituras,
      renombrados) y red entrante.
- [ ] Flujo del MFA (petición HTTP al servidor de Terrier). Un hook LSM no
      puede esperar a que un humano responda, así que la conexión se deniega
      al momento. Falta definir qué pasa cuando el MFA se aprueba: ¿se
      reintenta la conexión? ¿Quién la reintenta? ¿La aprobación cambia algo
      en el mapa de reglas rápidas, y durante cuánto tiempo?
- [ ] El MFA depende del servidor, que en §3 figura como trabajo futuro:
      decidir si el servidor entra antes en el plan o si el MFA espera.
- [ ] Autenticación entre Swivel y el servidor para el MFA: ¿cómo evitas que
      un atacante en la misma máquina apruebe su propia conexión?
- [ ] Escaneo de puertos o de URLs: un escaneo es un patrón entre muchos
      eventos, no un evento suelto. ¿Regla rápida o lenta? Y las URLs no
      son visibles a nivel de socket.

**§4 Formato**
- [ ] Decidir cuándo se introduce el versionado del formato.

**§5 Dominio**
- [ ] Origen del valor `host`.
- [ ] Formato y límite de tamaño de `args` (comparten el tail con `route`).
- [ ] Semántica de `direction`, `result` y `protocol` en red (ligado a `assemble_net`).

**§6 Swivel**
- [ ] Cómo se construye el árbol: hoy solo llegan eventos de `exec`. ¿De dónde
      salen los `fork` y los `exit`, y cómo se limpian los nodos?
- [ ] Clave del árbol: los PIDs se reutilizan.
- [ ] Modelo de riesgo: si se acumula por proceso, por árbol o por usuario;
      si decae con el tiempo; qué se cierra exactamente al llegar al umbral.
- [ ] Mapa de reglas rápidas: clave (inode, ruta, uid, puerto…), formato y
      cómo lo actualiza Swivel.
- [ ] Modo de prueba: si vive en el kernel, en userspace o en ambos.
- [ ] Documento de reglas: formato (TOML, YAML…), ubicación, quién puede
      modificarlo y si se recarga en caliente o solo al arrancar.
- [ ] Websocket caído: qué pasa con los logs mientras tanto (¿búfer o
      fichero local?). Autenticación y TLS.
- [ ] Relanzar Swivel: ¿quién lo hace (systemd u otro)? ¿Qué pasa con los
      hooks y las reglas rápidas mientras Swivel está caído? (Busca "pinning"
      en aya.) Decidir si el sistema falla abierto o cerrado.

**§7 Límites**
- [ ] Rehaz la cuenta de capacidad con `RING_BUFFER_SIZE` y `MAX_EVENT_SIZE`:
      la estimación anterior de "unos 4 millones de eventos" no cuadra.
- [ ] Sobrescribir el evento más antiguo: investiga si el ring buffer de BPF
      lo permite. Si no, define la política real ante un buffer lleno y cómo se
      cuentan los eventos perdidos.

**§8 Tests**
- [ ] Decidir cómo ejecutar el entorno de simulación. BPF LSM necesita que el
      kernel tenga `bpf` en `lsm=`: ¿contenedor privilegiado o VM (`virtme-ng`)?
- [ ] Arreglar `runner.sh`, que rompe `cargo test` con cargo nightly 1.100
      porque los binarios de test ya no están bajo `/deps/`.
