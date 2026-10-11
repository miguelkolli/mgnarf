"""Fresh-process checks of host-capable contenders, not Unix-account isolation."""
from dataclasses import asdict
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest


def drop_dac_bypass():
    if os.geteuid() != 0:
        return
    if sys.platform != "linux":
        raise RuntimeError("root permission test requires Linux capabilities")
    import ctypes

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    lib = ctypes.CDLL(None, use_errno=True)
    header, values = Header(0x20080522, 0), (Data * 2)()
    if lib.capget(ctypes.byref(header), ctypes.byref(values)) != 0:
        raise RuntimeError("capget unavailable")
    values[0].effective &= ~6  # CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH
    if lib.capset(ctypes.byref(header), ctypes.byref(values)) != 0:
        raise RuntimeError("capset unavailable")
    checked = (Data * 2)()
    if lib.capget(ctypes.byref(header), ctypes.byref(checked)) != 0 or checked[0].effective & 6:
        raise RuntimeError("DAC bypass capability drop could not be verified")


def worker(config):
    sys.dont_write_bytecode = True
    source = Path(config["source"])
    sys.path.insert(0, str(source / "src"))
    from narf import (EffectBinding, FrozenState, NARFGate, ReceiptStore,
                      VerifierBinding, VerifierResult)

    root = Path(config["root"])
    receipt = root / "receipts" / (config["contract_id"] + ".json")
    result = {"pid": os.getpid(), "uid": os.geteuid(), "mode": config["mode"],
              "source_loaded": sys.modules["narf.gate"].__file__}
    if config["mode"] == "tamper":
        envelope = json.loads(receipt.read_text())
        envelope["payload"]["evidence"]["task_id"] = "tampered-task"
        receipt.write_text(json.dumps(envelope))
        return result

    store = ReceiptStore(root / "receipts", bytes.fromhex(config["key_hex"]))
    if config["mode"] == "wrong-key":
        raw = receipt.read_bytes()
        result.update(raw_bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(),
                      authenticated=store.load(config["contract_id"]) is not None)
        return result

    state = FrozenState(**config["state"])

    def callback():
        for name in ("callbacks.jsonl", "targets.jsonl"):
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                event = (json.dumps({"pid": os.getpid(), "uid": os.geteuid()}) + "\n").encode()
                if os.write(fd, event) != len(event):
                    raise RuntimeError("short event write")
                os.fsync(fd)
            finally:
                os.close(fd)
        return "published"

    session = NARFGate(store).open_session(
        config["contract_id"], config["task"],
        verifier_bindings=[
            VerifierBinding("host-tests", "1", lambda: VerifierResult("PASS", b"unit")),
            VerifierBinding("policy-check", "1", lambda: VerifierResult("PASS", b"policy")),
        ], effect_binding=EffectBinding("publish", "1", callback), state_probe=lambda: state,
    )
    for requirement in session.requirements():
        session.execute(requirement)
    result["finalize"] = session.finalize()
    if result["finalize"]["result"] != "PASS":
        raise RuntimeError("worker failed to obtain a real PASS decision")

    if config["mode"] == "race":
        # PINKY: Both fresh host processes must reach PASS before the release.
        (root / ("ready-" + config["worker_id"])).touch()
        deadline = time.monotonic() + 10
        while not (root / "release").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("barrier timeout")
            time.sleep(0.01)
    elif config["mode"] == "write-denied":
        try:
            drop_dac_bypass()
        except RuntimeError as error:
            result["unsupported"] = str(error)
            return result
        store.directory.chmod(0o500)

    try:
        result["effect"] = session.execute_effect()
        result["error"] = None
    except Exception as error:
        result["effect"] = None
        result["error"] = {"type": type(error).__name__, "message": str(error),
                           "errno": getattr(error, "errno", None)}
    finally:
        if config["mode"] == "write-denied":
            store.directory.chmod(0o700)
    return result


class WorkerProcessTests(unittest.TestCase):
    def setUp(self):
        from test_gate import Fixture
        self.fixture = Fixture()
        self.records = []
        self.processes = []
        self.addCleanup(self.fixture.close)
        self.addCleanup(self.save_evidence)
        self.addCleanup(self.stop_workers)

    def stop_workers(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def save_evidence(self):
        target = os.environ.get("NARF_WORKER_EVIDENCE_DIR")
        if target:
            destination = Path(target) / self._testMethodName
            shutil.copytree(self.fixture.root, destination)
            (destination / "processes.json").write_text(json.dumps(self.records, indent=2) + "\n")

    def launch(self, mode, **extra):
        config = {"source": str(Path(__file__).resolve().parents[1]),
                  "root": str(self.fixture.root), "mode": mode,
                  "contract_id": self.fixture.contract_id, "task": self.fixture.task,
                  "state": asdict(self.fixture.state), **extra}
        if mode != "tamper":
            config.setdefault("key_hex", (b"k" * 32).hex())
        process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        process.stdin.write(json.dumps(config))
        process.stdin.close()
        process.stdin = None
        return process

    def collect(self, process):
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, stderr)
        result = json.loads(stdout)
        self.records.append({"exit": process.returncode, "stderr": stderr, "result": result})
        self.assertNotEqual(result["pid"], os.getpid())
        self.assertEqual(result["uid"], os.geteuid())
        self.assertEqual(Path(result["source_loaded"]).resolve(),
                         Path(__file__).resolve().parents[1] / "src/narf/gate.py")
        return result

    def event_count(self, name):
        path = self.fixture.root / name
        return len(path.read_text().splitlines()) if path.exists() else 0

    def consumption_count(self):
        return sum((self.fixture.store.load(path.stem) or {}).get("evidence_type") == "narf.effect"
                   for path in self.fixture.store.directory.glob("*.json"))

    def assert_no_effect(self):
        self.assertEqual(self.event_count("callbacks.jsonl"), 0)
        self.assertEqual(self.event_count("targets.jsonl"), 0)
        self.assertEqual(self.consumption_count(), 0)

    def test_wrong_key_rejects_authentication_but_raw_bytes_are_readable(self):
        result = self.collect(self.launch("wrong-key", key_hex=(b"x" * 32).hex()))
        self.assertFalse(result["authenticated"])
        self.assertGreater(result["raw_bytes"], 0)
        receipt = self.fixture.store.directory / (self.fixture.contract_id + ".json")
        self.assertEqual(result["raw_sha256"], hashlib.sha256(receipt.read_bytes()).hexdigest())
        self.assertIsNotNone(self.fixture.store.load(self.fixture.contract_id))
        self.assert_no_effect()

    def test_two_synchronized_host_processes_consume_one_effect(self):
        contenders = [self.launch("race", worker_id=str(number)) for number in range(2)]
        deadline = time.monotonic() + 10
        while not all((self.fixture.root / ("ready-" + str(n))).exists() for n in range(2)):
            self.assertTrue(all(p.poll() is None for p in contenders), "worker exited before barrier")
            self.assertLess(time.monotonic(), deadline, "worker readiness timeout")
            time.sleep(0.01)
        (self.fixture.root / "release").touch()
        results = [self.collect(process) for process in contenders]
        self.assertEqual(len({item["pid"] for item in results}), 2)
        self.assertEqual(sum(item["error"] is None for item in results), 1)
        loser = next(item["error"] for item in results if item["error"] is not None)
        self.assertEqual(loser["type"], "NARFError")
        self.assertIn("already consumed", loser["message"])
        self.assertEqual(self.event_count("callbacks.jsonl"), 1)
        self.assertEqual(self.event_count("targets.jsonl"), 1)
        self.assertEqual(self.consumption_count(), 1)

    def test_keyless_same_uid_tampering_invalidates_contract(self):
        from narf import NARFError
        self.collect(self.launch("tamper"))
        self.assertIsNone(self.fixture.store.load(self.fixture.contract_id))
        with self.assertRaisesRegex(NARFError, "authenticated NARF contract required"):
            self.fixture.session()
        self.assert_no_effect()

    def test_real_reservation_permission_error_prevents_callback(self):
        result = self.collect(self.launch("write-denied"))
        if "unsupported" in result:
            self.skipTest(result["unsupported"])
        # BRAIN: The real filesystem denial must occur before callback entry.
        self.assertEqual(result["finalize"]["result"], "PASS")
        self.assertIsNone(result["effect"])
        self.assertEqual(result["error"]["errno"], errno.EACCES)
        self.assertEqual(result["error"]["type"], "PermissionError")
        self.assert_no_effect()


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        print(json.dumps(worker(json.load(sys.stdin))))
    else:
        unittest.main()
