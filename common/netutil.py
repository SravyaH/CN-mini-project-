"""Small socket helpers shared by the application and the tests."""
import socket

from common.protocol import ProtocolError


class LineReader(object):
    """Buffered '\n'-terminated line reader with a hard length limit."""

    def __init__(self, sock, max_len=1024):
        self.sock, self.max_len, self.buf = sock, max_len, b""

    def readline(self):
        """Return one line (bytes, without newline) or None on clean EOF.

        Raises socket.timeout, ConnectionError, ProtocolError('too_long').
        """
        while True:
            idx = self.buf.find(b"\n")
            if idx >= 0:
                line, self.buf = self.buf[:idx], self.buf[idx + 1:]
                return line
            if len(self.buf) > self.max_len:
                self.buf = b""
                raise ProtocolError("too_long", "line exceeds %d bytes" % self.max_len)
            chunk = self.sock.recv(4096)
            if not chunk:
                if self.buf:                      # EOF in the middle of a line
                    line, self.buf = self.buf, b""
                    return line
                return None
            self.buf += chunk

    def read_exact(self, n):
        out = bytearray()
        take = min(len(self.buf), n)
        if take:
            out += self.buf[:take]
            self.buf = self.buf[take:]
        while len(out) < n:
            chunk = self.sock.recv(min(65536, n - len(out)))
            if not chunk:
                raise ConnectionError("peer closed after %d of %d bytes" % (len(out), n))
            out += chunk
        return bytes(out)

    def drain(self, n):
        """Discard n bytes without keeping them (for throughput tests)."""
        got = min(len(self.buf), n)
        self.buf = self.buf[got:]
        while got < n:
            chunk = self.sock.recv(min(262144, n - got))
            if not chunk:
                raise ConnectionError("peer closed after %d of %d bytes" % (got, n))
            got += len(chunk)
        return got


def set_nodelay(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
