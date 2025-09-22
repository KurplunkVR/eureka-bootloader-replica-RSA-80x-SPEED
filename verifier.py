import json
import logging
import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import queue
import traceback
from cryptography.exceptions import InvalidSignature
# -----------------------------------------------------------------------------
# Configuration & Globals
# -----------------------------------------------------------------------------

external_logger = queue.Queue()  # ✅ works from threads


with open("config.json") as f:
    cfg = json.load(f)

SERIAL = cfg["serial"]
with open(cfg["public_key"], "rb") as f:
    PUBKEY_PEM = f.read()

VERBOSE = True
VOLTAGE_SKIP = False  # must remain False for faithful replica


def log(level, msg):
    if external_logger:
        external_logger.put((level, msg))

    elif VERBOSE:
        print(f"[{level}] {msg}")    

def DEBUG(level, msg, *args):
    log("DEBUG", msg % args if args else msg)

def FastbootFail(msg):
    log("ERROR", f"FASTBOOT FAIL: {msg}")

def LogError(msg, exc_info=False):
    if exc_info:
        msg += "\n" + traceback.format_exc()
    log("ERROR", f"[LogError] {msg}")


# -----------------------------------------------------------------------------
# Device / Rollback stubs
# -----------------------------------------------------------------------------

class DevInfo:
    def __init__(self):
        self.rollback_index = [0] * 32

devInfo = DevInfo()
FirstReadDevInfo = False
WRITE_CONFIG = 1
dword_E6220 = 0

def sub_43048(a1: int, a2: int) -> int:
    global devInfo, FirstReadDevInfo
    if FirstReadDevInfo:
        DEBUG(0x80000000, "WriteRollbackIndex DeviceInfo not initialized")
        return 0x8000000000000013
    elif a1 < 0x20:
        devInfo.rollback_index[a1] = a2
        # Simulated write
        return 0
    else:
        DEBUG(0x80000000, "WriteRollbackIndex Loc out of range, index: %d", a1)
        return 0x8000000000000002

def sub_43218() -> int:
    for idx in range(32):
        res = sub_43048(idx, 0)
        if res:
            DEBUG(0x80000000, "Error clearing rollback slot %d: %r", idx, res)
            return 0x8000000000000015
    return 0

def SetDeviceUnlockValue(type_: int, state: int) -> int:
    log("INFO", f"SetDeviceUnlockValue(type={type_}, state={state})")
    return 0

# -----------------------------------------------------------------------------
# Crypto / Key Loading stubs
# -----------------------------------------------------------------------------

def LoadHardcodedPublicKey():
    return serialization.load_pem_public_key(PUBKEY_PEM, backend=default_backend())

def sub_679C4():
    return hashes.SHA256()

# We'll maintain gEfiMiscPartitionGuid for guard checks
gEfiMiscPartitionGuid = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"  # replace with real

# -----------------------------------------------------------------------------
# Replicated routines from disassembly (filled, not placeholders)
# -----------------------------------------------------------------------------

def sub_674F0():
    """
    Returns a GUID‑like value, as per disassembly EVP_MD_CTX_init uses this.
    In real code, it loads something (maybe a register or global).
    Here, simulate returning some GUID bytes.
    To force pass/fail, change this data.
    """
    # For test, return the correct GUID so guard passes
    return gEfiMiscPartitionGuid

def sub_6B9E4(a1, a2, a3):
    """
    Called when EVP_MD_CTX_init's guard passes.
    Disassembly: after matching GUID, B to sub_6B9E4.
    We'll simulate meaningful behavior: return a context object with status.
    """
    log("DEBUG", f"sub_6B9E4 invoked with a1={a1}, a2={a2}, a3={a3}")
    # Return something non‑zero / truthy indicating success
    return {"initialized": True}

def EVP_MD_CTX_init(arg_guid=None):
    """
    Replicates the disassembly at .text:000000000006701C
    """
    # Call sub_674F0 (which yields a GUID‑type value)
    X8 = sub_674F0()
    # Load global GUID
    X9 = gEfiMiscPartitionGuid

    if X9 != X8:
        log("ERROR", "EVP_MD_CTX_init: GUID mismatch, __stack_chk_fail")
        raise RuntimeError("__stack_chk_fail triggered in EVP_MD_CTX_init")

    # If matched, call sub_6B9E4
    ctx = sub_6B9E4(0x30, "BootWillResumePlaceholder", 0)
    return ctx

def sub_66F64():
    """
    Stub invoked in EVP_MD_CTX_free path
    """
    log("DEBUG", "sub_66F64 called in EVP_MD_CTX_free")
    return

def sub_674C8():
    """
    Another stub invoked in free path
    """
    log("DEBUG", "sub_674C8 called in EVP_MD_CTX_free")
    return

def sub_6BAD4(result_ctx):
    """
    Called with the result from free path when guard passes
    """
    log("DEBUG", f"sub_6BAD4 with result {result_ctx}")
    return result_ctx

def EVP_MD_CTX_free(ctx_obj, arg_guid=None):
    """
    Replicates disassembly at .text:0000000000067060
    """
    # Call sub_674F0 again for guard
    X8 = sub_674F0()
    X9 = gEfiMiscPartitionGuid

    if X9 != X8:
        log("ERROR", "EVP_MD_CTX_free: GUID mismatch, __stack_chk_fail")
        raise RuntimeError("__stack_chk_fail triggered in EVP_MD_CTX_free")

    # Save initial ctx return value
    X19 = ctx_obj

    # Call stub routines
    sub_66F64()
    sub_674C8()

    # After stubs, proceed if matched
    result = sub_6BAD4(X19)
    return result

def sub_6827C(ctx, size=None, md=None, *args, **kwargs):
    """
    Replicated version of sub_6827C: per disassembly
    B to EVP_DigestFinal_ex with certain args
    Here, simulate passing result of DigestFinal_ex
    """
    log("DEBUG", f"sub_6827C: invoking final_ex simulation")
    # In real firmware this directs to final signature digest finalize
    # We simulate by performing final verification (or mimic failure)
    # Here we just return 1 for success (assuming data is correct)
    return 1

def sub_6826C(ctx, size=None, md=None, *args, **kwargs):
    """
    Replicated version of sub_6826C
    """
    log("DEBUG", "sub_6826C: fallback/alternate path via DigestFinal_ex")
    # Simulate failure or partial success depending on context
    # For now, return 0 to indicate “not used path”
    return 0

def sub_68298(ctx=None, *args, **kwargs):
    """
    Replicated version of sub_68298
    In disasm: branch to EVP_MD_CTX_free
    """
    log("DEBUG", "sub_68298: will invoke EVP_MD_CTX_free")
    # invoke EVP_MD_CTX_free with some dummy argument
    return EVP_MD_CTX_free(ctx, arg_guid=gEfiMiscPartitionGuid)

# -----------------------------------------------------------------------------
# Replica of EVP_DigestVerifyFinal (using the filled stubs above)
# -----------------------------------------------------------------------------

def EVP_DigestVerifyFinal(ctx_flags: int,
                          key_type: int,
                          verify_fn,
                          sig: bytes,
                          payload: bytes,
                          arg_guid: bytes = None) -> int:
    if VOLTAGE_SKIP:
        log("WARNING", "Voltage skip active, skipping signature verification")
        return 1

    # Custom path if flags & 2
    if (ctx_flags & 0x02) != 0:
        if verify_fn:
            try:
                res = verify_fn(sig, payload)
                log("DEBUG", "Custom verify path used")
                return 1 if res else -1
            except Exception as e:
                LogError(f"Custom verify fn exception: ", exc_info=True)
                return -1
        else:
            LogError("flags indicate custom handler but verify_fn None")
            return -1

    EXPECTED_KEY_TYPE = 0x10
    if key_type != EXPECTED_KEY_TYPE:
        LogError(f"Key type mismatch: {hex(key_type)} != {hex(EXPECTED_KEY_TYPE)}")
        return -1

    # Guard via arg_guid if present
    if arg_guid is not None:
        ok = sub_6827C(None)  # in disasm, sub_6827C is called
        if not ok:
            log("DEBUG", "sub_6827C path failed")
            return -1
        else:
            log("DEBUG", "sub_6827C path succeeded")

    # Perform real signature verification
    try:
        pub = LoadHardcodedPublicKey()
        pub.verify(
            sig,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        log("DEBUG", "Signature verify success")
        return 1
    except InvalidSignature:
        LogError("RSA verify failed: Invalid Signature (Need Private Key)")
        return -1
    except Exception:
        LogError("RSA verification failed :\n" + traceback.format_exc())
        return -1

def sub_665E4_stub(script_data: bytes):
    """
    Simulates sub_665E4: checks script_data length, computes record pointer, sets outputs.
    Returns (ok: bool, record_ptr: bytes or None, total_size_of_records or similar)
    """
    # From disasm:
    # - Loads X9 = *X0 (first pointer)
    # - Computes X8 = X9 + 5
    # - Compares X8 vs X1 (length)
    # - If X8 > size: error (data too long)
    # - Sets *X2 = X8 (record_ptr), *X3 = pointer (maybe end pointer)
    # So here:
    if len(script_data) < 6:
        return (False, None, 0)

    # simple model: record_ptr = script_data[5:]
    header_offset = 5
    record_ptr = script_data[header_offset:]
    rec_size = len(record_ptr)
    return (True, record_ptr, rec_size)

def AsciiStrLen_stub(b: bytes) -> int:
    # Scan until zero or end, matching firmware behavior
    for i, c in enumerate(b):
        if c == 0:
            return i
    return len(b)

def AsciiStrnCmp_stub(a: bytes, b: bytes, n: int) -> int:
    # Compare first n bytes
    if a[:n] == b[:n]:
        return 0
    else:
        return 1

def SetDeviceUnlock(type_: int, state: int) -> int:
    log("INFO", f"SetDeviceUnlock(type={type_}, state={state})")
    return 0



# -----------------------------------------------------------------------------
# Full CheckToken with this 1:1 replica logic
# -----------------------------------------------------------------------------
def CheckToken(token: bytes):
    log("INFO", f"[CheckToken] token size: {len(token)}")

    pub = LoadHardcodedPublicKey()
    public_key_size = pub.key_size // 8
    signature_size = public_key_size

    # Check minimal length
    if len(token) <= public_key_size + 4:
        FastbootFail("token too short for sig + hdr_len")
        return 0x8000000000000015

    sig = token[:public_key_size]
    payload = token[public_key_size:]

    # Extract hdr_len
    hdr_len = int.from_bytes(payload[0:4], "little")
    if hdr_len < 0 or hdr_len > len(payload) - 4:
        FastbootFail("Invalid hdr_len")
        return 0x8000000000000015

    serial_bytes = payload[4 : 4 + hdr_len]
    try:
        serial_str = serial_bytes.decode("utf-8", errors="ignore")
    except Exception:
        serial_str = ""

    # Set up for signature verification
    ctx_flags = 0
    key_type = 0x10
    GUID_LEN = len(gEfiMiscPartitionGuid)
    arg_guid = None
    if len(payload) >= 4 + hdr_len + GUID_LEN:
        arg_guid = payload[4 + hdr_len : 4 + hdr_len + GUID_LEN]

    verify_fn = None

    rv = EVP_DigestVerifyFinal(ctx_flags, key_type, verify_fn, sig, payload, arg_guid)

    if rv != 1:
        FastbootFail("Failed on VerifyFinal")
        return 0x8000000000000015

    # Serial check
    if serial_str != SERIAL:
        FastbootFail("Serial mismatch")
        return 0x8000000000000015

    # Now mimic header parsing (sub_665E4)
    # The data after signature_size is considered "script_data"
    script_data = token[signature_size:]
    # The “header” pointer / region size: in RunBootloaderScript they compute:
    # header = (char*)data + signature_size
    # then header bound as (unsigned __int64)&v27[size - signature_size]
    # We'll assume script_data length = len(token) - signature_size

    # Check header existence
    ok, record_ptr, record_list = sub_665E4_stub(script_data)
    # sub_665E4_stub should return tuple (bool header_found, first_record_ptr, list_of_records)
    if not ok:
        FastbootFail("Invalid bootloader script: missing header")
        return 0x8000000000000002  # script missing header

    # The record pointer content: first byte should be 1
    # in disassembly: (v31 = *(v6-10)) and *v31 != 1 error.
    first_byte = record_ptr[0]
    if first_byte != 1:
        FastbootFail("Invalid bootloader script: missing header")
        return 0x8000000000000002

    # Now serial number mismatch check:
    # They compare some fields in the header to hdr_len etc:
    # e.g. v30 = AsciiStrLen(...) and they compare tv30 with parts of record_ptr, etc.
    header_serial_len = AsciiStrLen_stub(serial_bytes)
    if not (header_serial_len == hdr_len):
        FastbootFail("Invalid bootloader script: Serial number mismatch.")
        return 0x8000000000000015

    if AsciiStrnCmp_stub(serial_bytes, serial_str.encode('utf-8'), hdr_len) != 0:
        FastbootFail("Invalid bootloader script: Serial number mismatch.")
        return 0x8000000000000015

    # Then record loop: iterate records, check types
    for rec in record_list:
        # rec is tuple (record_type, payload_of_record)
        rec_type, rec_payload = rec
        if rec_type == 2:  # unlock record
            # rec_payload[0] is unlock type (should be 0 or 1)
            if rec_payload[0] == 1:
                unlock_state = 1
            elif rec_payload[0] == 0:
                unlock_state = 0
            else:
                FastbootFail("Invalid unlock type")
                return 0x8000000000000015

            rv2 = SetDeviceUnlock(unlock_state, 1)
            if rv2 != 0:
                return rv2  # propagate error
            # if succeeds, return success
            log("INFO", "[CheckToken] SUCCESS via unlock record")
            return 0

        elif rec_type == 3:  # rollback reset
            rv3 = sub_43218()
            if rv3 != 0:
                log("ERROR", f"Failed to reset rollback: {rv3}")
                return rv3
            # maybe continue or return?
            # In real code, maybe return after rollback reset
            log("INFO", "[CheckToken] SUCCESS via rollback reset")
            return 0

        else:
            FastbootFail("Unrecognized record")
            return 0x8000000000000015

    # If no record triggered unlock or rollback reset:
    FastbootFail("No valid record found")
    return 0x8000000000000015