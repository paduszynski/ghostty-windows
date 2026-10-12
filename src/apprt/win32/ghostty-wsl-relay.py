"""Run a command on a Linux pty inside WSL and relay it over stdin/stdout.

The Windows runtime starts `wsl.exe` with plain pipes instead of a ConPTY
when the configured command is wsl.exe, and runs this script inside the
distro. ConPTY re-encodes the terminal stream and drops sequences it
doesn't know, such as the APC strings used by the kitty graphics
protocol; relaying through a real Linux pty passes everything through
unchanged.

Usage: ghostty-wsl-relay.py --size ROWS,COLS,XPIXEL,YPIXEL
           [--version V] [--sh] [-- COMMAND...]

With no command, the user's login shell is started. With --sh, the
command is run by the user's shell like `wsl.exe -- COMMAND` does.

Ghostty reports window size changes in the input stream as
ESC _ GhosttyWinsize;ROWS;COLS;XPIXEL;YPIXEL ESC \\
which this script strips out and applies to the pty.

Kitty graphics commands that pass an image by file (t=f), temporary file
(t=t) or shared memory (t=s) name a Linux path, which Ghostty on Windows
can't open. This script reads those itself and sends the data inline
(t=d) instead, following the protocol's rules for each medium.
"""

import base64
import errno
import fcntl
import os
import pwd
import select
import signal
import struct
import sys
import termios

WINSIZE_START = b"\x1b_GhosttyWinsize;"
WINSIZE_END = b"\x1b\\"

# How long to hold back input that might be the start of a size message
# split across reads, before passing it through as typed input. Output
# that might start a graphics command is held back the same way.
HOLD_TIMEOUT = 0.05

GRAPHICS_START = b"\x1b_G"
STRING_END = b"\x1b\\"
# Base64 bytes per chunk of inline image data, the protocol's maximum.
GRAPHICS_CHUNK = 4096
# Larger graphics commands are passed through unchanged.
GRAPHICS_MAX = 256 * 1024 * 1024
# Directories a temporary file (t=t) must be in to be read and deleted.
TEMP_DIRS = ["/tmp", "/dev/shm", os.environ.get("TMPDIR", "/tmp")]


def set_winsize(fd, rows, cols, xpixel, ypixel):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, xpixel, ypixel))


def has_terminfo(name):
    dirs = [os.path.expanduser("~/.terminfo")]
    dirs += [d for d in os.environ.get("TERMINFO_DIRS", "").split(":") if d]
    dirs += ["/etc/terminfo", "/lib/terminfo", "/usr/share/terminfo", "/usr/lib/terminfo"]
    for d in dirs:
        for sub in (name[0], "%02x" % ord(name[0])):
            if os.path.exists(os.path.join(d, sub, name)):
                return True
    return False


def child_argv(command, via_shell):
    shell = pwd.getpwuid(os.getuid()).pw_shell or "/bin/sh"
    if not command:
        # A login shell, as wsl.exe starts by default.
        return shell, ["-" + os.path.basename(shell)]
    if via_shell:
        return shell, [shell, "-c", " ".join(command)]
    return command[0], command


def spawn(size, command, via_shell, version):
    master, slave = os.openpty()
    set_winsize(slave, *size)
    path, argv = child_argv(command, via_shell)

    env = dict(os.environ)
    env["TERM"] = "xterm-ghostty" if has_terminfo("xterm-ghostty") else "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["TERM_PROGRAM"] = "ghostty"
    if version:
        env["TERM_PROGRAM_VERSION"] = version

    pid = os.fork()
    if pid == 0:
        try:
            os.close(master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for fd in (0, 1, 2):
                os.dup2(slave, fd)
            if slave > 2:
                os.close(slave)
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
            os.execvpe(path, argv, env)
        except Exception as e:
            os.write(2, ("ghostty-wsl-relay: cannot run %s: %s\r\n" % (path, e)).encode())
        os._exit(127)

    os.close(slave)
    return pid, master


def split_input(buf):
    """Split pending input into (bytes for the pty, size messages, rest to hold)."""
    out = bytearray()
    sizes = []
    while buf:
        start = buf.find(WINSIZE_START)
        if start < 0:
            # Hold back a tail that could be the start of a split message.
            hold = 0
            for n in range(min(len(buf), len(WINSIZE_START) - 1), 1, -1):
                if WINSIZE_START.startswith(buf[-n:]):
                    hold = n
                    break
            out += buf[: len(buf) - hold]
            return bytes(out), sizes, buf[len(buf) - hold :]
        end = buf.find(WINSIZE_END, start + len(WINSIZE_START))
        if end < 0:
            out += buf[:start]
            return bytes(out), sizes, buf[start:]
        out += buf[:start]
        fields = buf[start + len(WINSIZE_START) : end].split(b";")
        try:
            sizes.append(tuple(int(f) for f in fields[:4]))
        except ValueError:
            pass
        buf = buf[end + len(WINSIZE_END) :]
    return bytes(out), sizes, b""


def held_prefix(buf, marker):
    """The length of the longest tail of buf that starts marker."""
    for n in range(min(len(buf), len(marker) - 1), 0, -1):
        if marker.startswith(buf[-n:]):
            return n
    return 0


def in_dir(path, directory):
    directory = os.path.realpath(directory).rstrip("/") + "/"
    return path.startswith(directory)


def read_medium(medium, payload, keys):
    """The image data a file, temporary file or shared memory command
    refers to, or None to pass the command through unchanged."""
    name = base64.b64decode(payload).decode("utf-8", "surrogateescape")
    if medium == "s":
        path = "/dev/shm/" + name.lstrip("/")
    else:
        path = os.path.realpath(name)
        # The same blocklist as Ghostty and kitty.
        if path.startswith(("/proc/", "/sys/")) or (
            path.startswith("/dev/") and not path.startswith("/dev/shm/")
        ):
            return None
        if medium == "t" and not (
            "tty-graphics-protocol" in path and any(in_dir(path, d) for d in TEMP_DIRS)
        ):
            return None

    offset = int(keys.get("O", "0"))
    size = int(keys.get("S", "0"))
    with open(path, "rb") as f:
        if not os.path.isfile(path):
            return None
        f.seek(offset)
        data = f.read(size) if size > 0 else f.read()
    if medium in ("t", "s"):
        # The terminal owns these once it has read them.
        try:
            os.unlink(path)
        except OSError:
            pass
    return data


def rewrite_graphics(body):
    """Rewrite the graphics command `body` (between ESC _ G and ESC \\) to
    send its image inline, or return None to pass it through unchanged."""
    control, sep, payload = body.partition(b";")
    try:
        pairs = [kv.split(b"=", 1) for kv in control.split(b",") if kv]
        keys = {k.decode(): v.decode() for k, v in pairs}
    except (ValueError, UnicodeDecodeError):
        return None
    medium = keys.get("t", "d")
    if medium not in ("f", "t", "s") or not sep:
        return None
    try:
        data = read_medium(medium, payload, keys)
    except (OSError, ValueError):
        return None
    if data is None:
        return None

    for k in ("t", "S", "O", "m"):
        keys.pop(k, None)
    keys["t"] = "d"
    encoded = base64.b64encode(data)
    chunks = [encoded[i : i + GRAPHICS_CHUNK] for i in range(0, len(encoded), GRAPHICS_CHUNK)] or [b""]
    quiet = ",q=" + keys["q"] if "q" in keys else ""

    out = bytearray()
    for n, chunk in enumerate(chunks):
        more = "1" if n < len(chunks) - 1 else "0"
        if n == 0:
            control = ",".join("%s=%s" % kv for kv in keys.items()) + ",m=" + more
        else:
            # Later chunks may only carry m and q.
            control = "m=" + more + quiet
        out += GRAPHICS_START + control.encode() + b";" + chunk + STRING_END
    return bytes(out)


class OutputFilter:
    """Rewrites graphics commands in the pty output (see rewrite_graphics)."""

    def __init__(self):
        self.pending = b""

    def feed(self, data):
        buf = self.pending + data
        self.pending = b""
        out = bytearray()
        i = 0
        while True:
            start = buf.find(GRAPHICS_START, i)
            if start < 0:
                hold = held_prefix(buf[i:], GRAPHICS_START)
                out += buf[i : len(buf) - hold]
                self.pending = buf[len(buf) - hold :]
                return bytes(out)
            out += buf[i:start]
            end = buf.find(STRING_END, start + len(GRAPHICS_START))
            if end < 0:
                if len(buf) - start > GRAPHICS_MAX:
                    out += buf[start:]
                else:
                    self.pending = buf[start:]
                return bytes(out)
            body = buf[start + len(GRAPHICS_START) : end]
            rewritten = rewrite_graphics(body) if b"t=" in body else None
            out += rewritten if rewritten is not None else buf[start : end + len(STRING_END)]
            i = end + len(STRING_END)

    def holding_prefix(self):
        """Whether output is held only because it might start a command."""
        return 0 < len(self.pending) < len(GRAPHICS_START)

    def flush(self):
        data, self.pending = self.pending, b""
        return data


def write_all(fd, data):
    while data:
        n = os.write(fd, data)
        data = data[n:]


def relay(pid, master):
    fcntl.fcntl(master, fcntl.F_SETFL, fcntl.fcntl(master, fcntl.F_GETFL) | os.O_NONBLOCK)
    held = b""
    to_pty = b""
    stdin_open = True
    output = OutputFilter()

    while True:
        readers = [master] + ([0] if stdin_open else [])
        writers = [master] if to_pty else []
        timeout = HOLD_TIMEOUT if held or output.holding_prefix() else None
        r, w, _ = select.select(readers, writers, [], timeout)

        if not r and not w:
            # The held bytes were typed input or plain output after all.
            to_pty += held
            held = b""
            if output.holding_prefix():
                try:
                    write_all(1, output.flush())
                except OSError:
                    return

        if master in r:
            try:
                data = os.read(master, 65536)
            except OSError as e:
                if e.errno != errno.EIO:
                    raise
                data = b""
            if not data:
                return
            try:
                write_all(1, output.feed(data))
            except OSError:
                # Ghostty went away.
                return

        if 0 in r:
            data = os.read(0, 65536)
            if not data:
                # Ghostty closed the tab: closing the master hangs up the shell.
                return
            data, sizes, held = split_input(held + data)
            to_pty += data
            for size in sizes:
                if len(size) == 4:
                    set_winsize(master, *size)

        if master in w and to_pty:
            try:
                n = os.write(master, to_pty)
                to_pty = to_pty[n:]
            except BlockingIOError:
                pass


def main():
    args = sys.argv[1:]
    size = (24, 80, 0, 0)
    version = None
    via_shell = False
    command = []
    while args:
        arg = args.pop(0)
        if arg == "--size" and args:
            size = tuple(int(f) for f in args.pop(0).split(","))
        elif arg == "--version" and args:
            version = args.pop(0)
        elif arg == "--sh":
            via_shell = True
        elif arg == "--":
            command = args
            break
        else:
            command = [arg] + args
            break

    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    pid, master = spawn(size, command, via_shell, version)
    try:
        relay(pid, master)
    finally:
        os.close(master)

    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
    sys.exit(os.WEXITSTATUS(status))


if __name__ == "__main__":
    main()
