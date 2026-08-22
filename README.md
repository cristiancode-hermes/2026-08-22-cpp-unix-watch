# unix-watch

Monitor de la tabla de sockets AF_UNIX de Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/unix` para mostrar tipo (STREAM / DGRAM / SEQPACKET), estado
(UNCONN / CONNING / CONN / DISCONN), flags SO_ACCEPTCON, inode, refcount y path.
Clasifica sockets abstractos (`@name`), pathname y unnamed.

## Features

- **Parse de `/proc/net/unix`**: Num, RefCount, Protocol, Flags, Type, St, Inode, Path
- **Tipos**: 0001 STREAM, 0002 DGRAM, 0005 SEQPACKET
- **Estados**: 01 UNCONN, 02 CONNING, 03 CONN, 04 DISCONN
- **Listen**: flag `0x10000` (`SO_ACCEPTCON`) → `L`
- **Namespace**: abstract (`@…`), pathname (`/run/…`) o unnamed (sin path)
- **Watch mode**: refresco periódico con deltas de conteo entre snapshots
- **JSON output**: `summary` + array `sockets` validable
- **Demo mode**: tabla multi-kind (dbus, udev, journal, mysql, X11, containerd)
- **Filtros**: `--type`, `--listen`, `--abstract`, `--unnamed`, `--path PREFIX`
- **`--file`**: parsea un dump (tolera comentarios `#`)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 57 checks (parser, flags, demo, JSON y `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o unix-watch
```

## Usage

```bash
# Snapshot único (tabla real del host)
./unix-watch

# Modo watch (cada 2s)
./unix-watch --watch 2

# Solo listeners
./unix-watch --listen

# Solo STREAM / DGRAM / SEQPACKET
./unix-watch --type stream

# Solo abstractos (@name)
./unix-watch --abstract

# Paths que empiezan por /run/
./unix-watch --path /run/

# JSON
./unix-watch --json

# Demo (tabla sintética multi-kind)
./unix-watch --demo

# Parsear un dump con comentarios
./unix-watch --file sample-unix.table --no-color

# Sin colores
./unix-watch --no-color

# Auto-tests
./unix-watch --selftest
```

## Data Source

| Archivo | Campos |
|---------|--------|
| `/proc/net/unix` | Num, RefCount, Protocol, Flags, Type, St, Inode, Path |

Formato kernel (`unix_seq_show`): `%pK: %08X %08X %08X %04X %02X %5lu [Path]`

- RefCount / Protocol / Flags / Type / St → hex
- Inode → decimal (`%5lu`)
- Path opcional; primer byte `\0` se imprime como `@` (namespace abstracto)

### Flags y tipos

| Valor | Nombre | Significado |
|-------|--------|-------------|
| 0x10000 | SO_ACCEPTCON | socket en listen |
| 0001 | SOCK_STREAM | stream (como TCP) |
| 0002 | SOCK_DGRAM | datagrama (como UDP) |
| 0005 | SOCK_SEQPACKET | seqpacket (journal, etc.) |

## Example Output

```
+================================================+
|     Linux AF_UNIX Socket Table Monitor        |
+================================================+
  Source: /proc/net/unix

  -- Aggregate --
  Sockets        10
  STREAM         7
  DGRAM          2
  SEQPACKET      1
  Listening      4
  Connected      2
  Abstract       3
  Pathname       5
  Unnamed        2

  -- Sockets (10) --
  Type       State  Flg     Refs    Inode  Path
  stream     UNCONN L          2    12345  @/tmp/dbus-abc
  stream     CONN   -          3    12346  /run/user/1000/bus
  dgram      UNCONN -          2    12352  /dev/log
  ...
```

## License

MIT
