from pathlib import Path
import shutil
import subprocess
import sys
import struct


AGENT_STRING_REPLACEMENTS = {
    # Entry point and embedded agent ELF identity.
    b"frida_agent_main": b"android_mainloop",
    b"libfrida-agent-raw.so": b"libandroid-runtime.so",

    # Source-path / build-path breadcrumbs commonly left in rodata.
    b"subprojects/frida-gum": b"subprojects/androidfw",
    b"/frida/": b"/cache/",
    b"/frida-": b"/cache-",

    # DBus / RPC protocol strings. These must match the source-level
    # replacements in lib/base/session.vala, lib/base/rpc.vala, and gumjs.
    b"re.frida.": b"com.jdwp.",
    b"/re/frida/": b"/com/jdwp/",
    b"frida:rpc": b"jdwp:cmd!",

    # Vala/GObject implementation names commonly used as detector needles.
    # GumJS exposes compatibility aliases for legacy script names at runtime,
    # so these target-side implementation strings can use neutral names.
    b"FridaProcessInvader": b"AndroidProcessState",
    b"Interceptor": b"HookManager",

    # Last-resort catch-all for remaining Frida branding breadcrumbs in the
    # target-side blob. Keep these after the specific replacements above.
    b"frida": b"media",
    b"Frida": b"Media",
    b"FRIDA": b"MEDIA",
    b"media-gadget": b"system-codec",
    b"media-agent": b"media-codec",
    b"Media.Agent": b"Media.Codec",
    b"MediaAgentStopReason": b"MediaCodecExitReason",
    b"MediaAgent": b"MediaCodec",
    b"MediaDirListCloaker": b"MediaPathListReader",
    b"BaseAgentSession": b"BaseCodecSession",
    b"LiveAgentSession": b"LiveCodecSession",
    b"EmulatedAgentSession": b"EmulatedCodecSession",
    b"AgentSessionDetached": b"CodecSessionDetached",
    b"AgentSessionProvider": b"CodecSessionProvider",
    b"AgentMessageSink": b"CodecMessageSink",
    b"AgentController": b"CodecController",
    b"AgentSession": b"CodecSession",
    b"ScriptEngine": b"RenderEngine",
    b"ThreadListCloaker": b"ThreadStateLogger",
    b"subprojects/cache-core": b"frameworks/runtime-lib",
    b"payload/cloak.vala": b"runtime/codec.vala",
    b"prepare_for_termination": b"prepare_for_close_state",
    b"Uninjected": b"RuntimeLib",
    b"InjectLibraryFile": b"RuntimeLibraryJob",
    b"EnumeratePendingSpawn": b"EnumeratePendingTasks",
    b"ChildGatingChanged": b"ChildPolicyChanged",

    # Thread names commonly observed in /proc/<pid>/task/*/comm after attach.
    # Replacements must be the same length so we can safely patch the ELF blob
    # after it has been linked.
    b"gum-js-loop": b"RenderLoop1",
    b"gum-modify-thread-worker": b"art-modify-thread-worker",

    # Gum implementation names embedded in CModule headers, symbol tables,
    # GObject type names, and diagnostic strings. CModule installs runtime
    # aliases, so legacy user code can still include/call the old API names.
    b"gum_": b"art_",
    b"Gum": b"Art",
    b"GUM_": b"ART_",
    b"gumjs": b"artjs",
    b"gumv8": b"artv8",
    b"gum-%d": b"art-%d",

    b"gmain": b"HeapT",
    b"gdbus": b"HwBnd",
    b"frida-agent-container": b"AsyncTaskWorkerThread",
    b"frida-eternal-agent": b"FinalizerDaemonLoop",
    b"frida-agent-emulated": b"ReferenceQueueDaemon",
}


def main(argv):
    args = argv[1:]
    host_os = args.pop(0)
    host_arch = args.pop(0)
    host_toolchain = args.pop(0)
    resource_compiler = args.pop(0)
    lipo = pop_cmd_array_arg(args)
    output_dir = Path(args.pop(0))
    priv_dir = Path(args.pop(0))
    resource_config = args.pop(0)
    agent_modern, agent_legacy, \
            agent_emulated_modern, agent_emulated_legacy, \
            agent_dbghelp_prefix, agent_symsrv_prefix \
            = [Path(p) if p else None for p in args[:6]]

    if agent_modern is None and agent_legacy is None:
        print("At least one agent must be provided", file=sys.stderr)
        sys.exit(1)

    priv_dir.mkdir(exist_ok=True)

    embedded_assets = []
    if host_os == "windows":
        pending_archs = {"arm64", "x86_64", "x86"}
        for agent in {agent_modern, agent_legacy, agent_emulated_modern, agent_emulated_legacy}:
            if agent is None:
                continue
            arch = detect_pefile_arch(agent)
            embedded_agent = priv_dir / f"frida-agent-{arch}.dll"
            embedded_dbghelp = priv_dir / f"dbghelp-{arch}.dll"
            embedded_symsrv = priv_dir / f"symsrv-{arch}.dll"

            shutil.copy(agent, embedded_agent)

            if agent_dbghelp_prefix is not None:
                shutil.copy(agent_dbghelp_prefix / arch / "dbghelp.dll", embedded_dbghelp)
            else:
                embedded_dbghelp.write_bytes(b"")

            if agent_symsrv_prefix is not None:
                shutil.copy(agent_symsrv_prefix / arch / "symsrv.dll", embedded_symsrv)
            else:
                embedded_symsrv.write_bytes(b"")

            embedded_assets += [embedded_agent, embedded_dbghelp, embedded_symsrv]
            pending_archs.remove(arch)
        for missing_arch in pending_archs:
            embedded_agent = priv_dir / f"frida-agent-{missing_arch}.dll"
            embedded_dbghelp = priv_dir / f"dbghelp-{missing_arch}.dll"
            embedded_symsrv = priv_dir / f"symsrv-{missing_arch}.dll"
            for asset in {embedded_agent, embedded_dbghelp, embedded_symsrv}:
                asset.write_bytes(b"")
                embedded_assets += [asset]
    elif host_os in {"macos", "ios", "watchos", "tvos", "xros"}:
        embedded_agent = priv_dir / "frida-agent.dylib"
        if agent_modern is not None and agent_legacy is not None:
            subprocess.run(lipo + [agent_modern, agent_legacy, "-create", "-output", embedded_agent],
                           check=True)
        elif agent_modern is not None:
            shutil.copy(agent_modern, embedded_agent)
        else:
            shutil.copy(agent_legacy, embedded_agent)
        embedded_assets += [embedded_agent]
    elif host_os in {"linux", "android"}:
        for agent, flavor in [(agent_modern, "64"),
                              (agent_legacy, "32"),
                              (agent_emulated_modern, "arm64"),
                              (agent_emulated_legacy, "arm")]:
            embedded_agent = priv_dir / f"libjitcache-{flavor}.so"
            if agent is not None:
                shutil.copy(agent, embedded_agent)
                cloak_agent_strings(embedded_agent)
            else:
                embedded_agent.write_bytes(b"")
            embedded_assets += [embedded_agent]
    elif host_os in {"freebsd", "qnx"}:
        embedded_agent = priv_dir / "frida-agent.so"
        agent = agent_modern if agent_modern is not None else agent_legacy
        shutil.copy(agent, embedded_agent)
        embedded_assets += [embedded_agent]
    else:
        print("Unsupported OS", file=sys.stderr)
        sys.exit(1)

    subprocess.run([
        resource_compiler,
        f"--toolchain={host_toolchain}",
        f"--machine={host_arch}",
        "--config-filename", resource_config,
        "--output-basename", output_dir / "frida-data-agent",
    ] + embedded_assets, check=True)


def pop_cmd_array_arg(args):
    result = []
    first = args.pop(0)
    assert first == ">>>"
    while True:
        cur = args.pop(0)
        if cur == "<<<":
            break
        result.append(cur)
    if len(result) == 1 and not result[0]:
        return None
    return result


def detect_pefile_arch(location):
    with location.open(mode="rb") as pe:
        pe.seek(0x3c)
        e_lfanew, = struct.unpack("<I", pe.read(4))
        pe.seek(e_lfanew + 4)
        machine, = struct.unpack("<H", pe.read(2))
    return PE_MACHINES[machine]


def cloak_agent_strings(location):
    data = location.read_bytes()
    for old, new in AGENT_STRING_REPLACEMENTS.items():
        assert len(old) == len(new)
        data = data.replace(old, new)
    location.write_bytes(data)


PE_MACHINES = {
    0x014c: "x86",
    0x8664: "x86_64",
    0xaa64: "arm64",
}


if __name__ == "__main__":
    main(sys.argv)
