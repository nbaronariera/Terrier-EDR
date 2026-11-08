# Terrier — Documento de diseño

> **Nota de transparencia (CLAUDE.md §2):** este documento ha sido redactado
> con apoyo de IA a partir de las notas y decisiones del diseñador.
> Las tablas de formato y dominio (extraídas del código de `commons`)
> y la sección final *Pendiente* son
> generadas por IA. Estado a 2026-10-25.

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

- **Por defecto (`no_std`)**, para Spark. Incluye `events::wire` (formato de
  cable y `parse_event`) y `events::domain` (enums y tipos compartidos), sin
  memoria dinámica.
- **Con la feature `user`**, para Swivel. Añade `events::user_space` (que
  necesita `alloc` porque la conversión crea un `String`) y la dependencia `aya`.

Spark no puede usar la versión `user` porque en eBPF no hay asignador de memoria.

El servidor de logs con visor TUI queda como trabajo futuro; por ahora no hace falta.

## 4. Formato de cable

Spark escribe cada evento en el ring buffer como una secuencia de bytes con
esta estructura:

```
[ RawEventHeader (24 B) ][ payload (16 o 40 B, según tipo) ][ tail (variable) ]
|<──────────────────────────── total_length ──────────────────────────────>|
```

Las estructuras son `#[repr(C)]`, así que incluyen el relleno (padding) que
impone C.

**Orden de bytes:** todo va en el orden nativo excepto las **IPs**, que
viajan en big-endian (orden de red) tal cual las da el kernel y se convierten
en los constructores de `NetAddress`. Los **puertos** viajan ya en orden
nativo: Spark aplica `from_be` a `sin_port`/`skc_dport` al leerlos, y
`skc_num` ya viene en orden del host. En userspace todo está en orden nativo.

**Tamaño real en el ring buffer:** cada registro lleva además una cabecera de
8 B del ring buffer y se redondea a múltiplo de 8. Un evento IPv4 ocuparía
48 B y uno IPv6 72 B si la reserva se ajustara al tamaño real (ver §7).

**Versionado:** el header no lleva campo de versión. Se asume que el formato
cambiará sin retrocompatibilidad hasta que se estabilice; el versionado queda
para el futuro.

### `RawEventHeader` (24 bytes)

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `event_type` | `u8` | `EventKind`: 0 = Process, 1 = File, 2 = NetIPv4, 3 = NetIPv6 |
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

### Red: un `EventKind` por familia

IPv4 e IPv6 son tipos de evento distintos, cada uno con un payload de tamaño
fijo. Así `parse_event` sigue deduciendo el tamaño del payload a partir del
tipo, el verificador ve tamaños constantes y un evento IPv4 no paga los 24 B
extra de las direcciones IPv6. Spark elige el tipo leyendo la familia del
`sockaddr` (o del `sock` si no hay `sockaddr`): `AF_INET` = 2, `AF_INET6` = 10.

Qué extremo representa el `sockaddr` depende de la operación: en `Bind` es el
origen; en el resto, el destino. El otro extremo se lee del `sock`.

### `RawNetIPv4Payload` (16 bytes) — sin tail

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `origin_ip` | `u32` | IPv4 de origen, **big-endian** |
| 4 | `target_ip` | `u32` | IPv4 de destino, **big-endian** |
| 8 | `origin_port` | `u16` | Puerto de origen, orden nativo |
| 10 | `target_port` | `u16` | Puerto de destino, orden nativo |
| 12 | `protocol` | `u8` | Número de protocolo IP (`sk_protocol`) |
| 13 | `operation` | `u8` | `NetOperation` (ver §5) |
| 14 | `result` | `u8` | 0 = éxito, otro = código de error |
| 15 | — | padding | |

### `RawNetIPv6Payload` (40 bytes) — sin tail

| Offset | Campo | Tipo | Descripción |
|---|---|---|---|
| 0 | `origin_ip` | `[u8; 16]` | Octetos de `in6_addr` de origen, orden de red |
| 16 | `target_ip` | `[u8; 16]` | Octetos de `in6_addr` de destino, orden de red |
| 32 | `origin_port` | `u16` | Puerto de origen, orden nativo |
| 34 | `target_port` | `u16` | Puerto de destino, orden nativo |
| 36 | `protocol` | `u8` | Número de protocolo IP |
| 37 | `operation` | `u8` | `NetOperation` |
| 38 | `result` | `u8` | 0 = éxito, otro = código de error |
| 39 | — | padding | |

> Estado: la ruta IPv6 está escrita en `assemble_net`, pero
> `EventBuilder::write_payload` tiene la rama `NetIPv6` vacía, y
> `parse_event` y `Event::from_raw` todavía tienen `todo!()`.

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
    └── Net(NetEvent { origin: Option<NetAddress>, target: Option<NetAddress>,
                       protocol: NetProtocol, result: NetResult,
                       operation: NetOperation })
```

Los tipos de dominio viven en `events::domain` y los comparten Spark y
Swivel. Los de red se convierten a y desde `u8` con `to_u8`/`from_u8`
escritos a mano, que nunca fallan: los valores desconocidos se conservan.

| Tipo | Valores |
|---|---|
| `FileOperation` | Open = 0, Write = 1, Read = 2, Rename = 3, Move = 4, Link = 5, Unlink = 6 |
| `NetProtocol` | ICMP = 1, TCP = 6, UDP = 17, `UndefinedProtocol(u8)` para el resto |
| `NetOperation` | Connect = 1, Bind = 2, `UndefinedOperation(u8)` para el resto |
| `NetResult` | `Success` (0), `Failed(código)`; `Failed(0)` se codifica como 255 |
| `NetAddress` | `{ ip: NetAddressProtocol, port: u16 }`; puerto en orden nativo |
| `NetAddressProtocol` | `IPv4(Ipv4Addr)` o `IPv6(Ipv6Addr)`, de `core::net` |

Un enum es adecuado aquí y no en el cable: en el dominio los datos ya están
validados y el tamaño del enum no importa. En el cable se usan bytes planos
y el `EventKind` hace de discriminante.

Errores de conversión (`EventError`):

| Error | Condición |
|---|---|
| `MissingRoute` | Evento Process o File sin tail |
| `InvalidRouteUtf8` | El tail no es UTF-8 válido |
| `InvalidFileOperation(u8)` | `operation` fuera de rango |
| `InvalidNetDirection(u8)` | Sin uso desde que `direction` pasó a `operation` |

**TODOs del dominio:**

- `EventCommon.host` vale siempre `0`: falta obtener el host.
- `ProcessEvent` no tiene todavía los argumentos del proceso (`args`).
- `from_raw` construye siempre `Some` en `origin` y `target`: falta decidir
  cuándo un extremo es desconocido (ver *Pendiente*, §5).

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

**🔴 Prioritario**
- [x] **Desajuste de LLVM entre `rustc` y `bpf-linker`.** `swivel` no compila
      porque el build script no puede enlazar Spark (`ERROR llvm: Invalid
      record`). `rustc` 1.100.0-nightly usa LLVM 23.1.1 y el `bpf-linker`
      0.10.4 del sistema está enlazado contra LLVM 22.1.8. Opciones: un
      `bpf-linker` contra LLVM 23, o fijar en `rust-toolchain.toml` un nightly
      con LLVM 22 (más estable: evita que vuelva a pasar al actualizar).
      Comprobar con `rustc -vV` y `ldd $(which bpf-linker) | grep LLVM`.

**Implementación**
- [x] ~~Implementar `assemble_net`~~: lee familia, IPs, puertos y protocolo
      del `sockaddr`/`sock` y escribe `NetIPv4` o `NetIPv6` según la familia.
- [x] ~~Unificar las direcciones del dominio~~: `NetAddress` con
      `NetAddressProtocol` (IPv4/IPv6) en lugar de un tipo por familia.
- [x] ~~Documentar el endianness en el código~~: está en `wire/net.rs` y en
      los constructores de `NetAddress`.
- [x] ~~Regenerar `vmlinux.rs`~~ con `sockaddr_in` y `sockaddr_in6`.
- [x] ~~Que compile el binario `spark`~~: imports añadidos en `main.rs`.
- [ ] Completar IPv6:
  - `EventBuilder::write_payload`: la rama `NetIPv6` está vacía. Ya no hace
    `panic`, pero marca el payload como escrito sin escribirlo ni sumarlo a
    `total_length`.
  - `parse_event`: `todo!()` con un dato no fiable del kernel; hoy tumbaría
    Swivel.
  - `Event::from_raw`: `todo!()`.
- [ ] Añadir `RawNetIPv6Payload` a `test_struct_sizes`.
- [x] Limpieza: `EventError::InvalidNetDirection` sin uso, `NETv4_SZ` sin
      mayúsculas, imports sin usar en `user_space/common.rs` y `sock` en
      `main.rs`.
- [ ] Test de ida y vuelta con el productor real: `EventBuilder → parse_event →
      from_raw`, para detectar divergencias de ABI. Es el hueco de tests más valioso. 
- [ ] Consumir eventos de verdad en Swivel (hoy solo los imprime). Ver §6.
- [x] Adjuntar en Swivel los hooks `file_open` y `socket_connect` (están
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
- [x] ~~Semántica de `direction` y `protocol` en red~~: `direction` se
      sustituye por `NetOperation` (lo pasa quien llama, según el hook);
      `protocol` sale de `sk_protocol`.
- [ ] `result` en un hook LSM: el hook se ejecuta *antes* de la operación, así
      que hoy se manda siempre `Success`. Decidir qué significa o si hace
      falta otro punto de enganche posterior.
- [ ] Extremo desconocido: en `connect` sin `bind` previo, la IP y el puerto
      locales todavía valen 0. Decidir cómo distingue Swivel "desconocido"
      de `0.0.0.0:0` (hoy `from_raw` siempre da `Some`).

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
      porque los binarios de test ya no están bajo `/deps/` (ahora salen en
      `target/debug/build/<crate>/<hash>/out/`) y acaba pidiendo `sudo`.
