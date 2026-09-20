"""A synthetic, inert i386 ELF that *mimics the shape* of IoT-bot behaviour so the service's
end-to-end test can exercise every result section. It is hand-assembled from a few opcodes
(see elfbuilder.py), contains no real malware, and uses only RFC 5737 documentation
addresses and .test hostnames. It is only ever emulated, never run.
"""
import struct

from test.unit.elfbuilder import Prog

C2_IP, C2_PORT = "198.51.100.7", 4444
RESOLVER_IP = "203.0.113.53"


def build_demo_bot() -> bytes:
    p = Prog()
    watchdog = p.cstr("/dev/watchdog")
    self_path = p.cstr("/tmp/sample")
    dropped = p.cstr("/tmp/dropped.bin")
    body = p.d(b"synthetic-payload")
    hello = p.d(b"HELLO-C2")
    name = p.cstr("scanbot")
    sh, dashc, cmd = p.cstr("/bin/sh"), p.cstr("-c"), p.cstr("echo synthetic")
    argv = p.ptrs(sh, dashc, cmd, 0)
    c2 = p.d(Prog.sockaddr_in(C2_IP, C2_PORT))
    resolver = p.d(Prog.sockaddr_in(RESOLVER_IP, 53))
    packet = (struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
              + b"\x02c2\x04test\x00" + struct.pack(">HH", 1, 1))   # A query for c2.test
    query = p.d(packet)

    p.sys(172, 15, name)                    # prctl(PR_SET_NAME, "scanbot")
    p.sys(5, watchdog, 2)                   # open("/dev/watchdog", O_RDWR)
    p.sys(10, self_path)                    # unlink(argv[0])

    p.sys(5, dropped, 0o101)                # open(O_WRONLY|O_CREAT)
    p.ebx_from_eax()
    p.mov(1, body); p.mov(2, 17); p.mov(0, 4)
    p.raw(b"\xcd\x80")                      # write(fd, body, 17)
    p.sys(15, dropped, 0o755)               # chmod +x

    p.sys(359, 2, 1, 0)                     # socket(AF_INET, SOCK_STREAM)
    p.ebx_from_eax()
    p.mov(1, c2); p.mov(2, 16); p.mov(0, 362)
    p.raw(b"\xcd\x80")                      # connect(C2)
    p.mov(1, hello); p.mov(2, 8); p.mov(6, 0); p.mov(7, 0); p.mov(5, 0); p.mov(0, 369)
    p.raw(b"\xcd\x80")                      # sendto(fd, "HELLO-C2", 8, 0, NULL, 0)

    p.sys(359, 2, 2, 0)                     # socket(AF_INET, SOCK_DGRAM)
    p.ebx_from_eax()
    p.mov(1, query); p.mov(2, len(packet)); p.mov(6, 0); p.mov(7, resolver); p.mov(5, 16); p.mov(0, 369)
    p.raw(b"\xcd\x80")                      # sendto(resolver:53, query)

    p.sys(2)                                # fork
    p.jnz("parent")
    p.sys(11, sh, argv, 0)                  # child: execve("/bin/sh", ["/bin/sh","-c",...])
    p.exit(1)
    p.label("parent")
    p.exit(0)
    return p.build()
