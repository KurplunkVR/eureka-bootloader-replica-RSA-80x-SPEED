import json
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


with open("config.json") as f:
    cfg = json.load(f)

SERIAL = cfg["serial"]

with open(cfg["public_key"], "rb") as f:
    PUBKEY_PEM = f.read()

VERBOSE = True

external_logger = None  # Optional shared logger

def log(level, msg):
    if external_logger:
        external_logger.put((level, msg))
    elif VERBOSE:
        print(f"[{level}] {msg}")

def DEBUG(level, msg, *args):
    log("DEBUG", msg % args if args else msg)

def FastbootFail(msg):
    log("ERROR", f"FASTBOOT FAIL: {msg}")

def LogError(val, msg):
    log("ERROR", f"[LogError] {msg}")


# -----------------------------------------------------------------------------
# Globals (bootloader-style)
# -----------------------------------------------------------------------------
class DevInfo:
    def __init__(self):
        self.rollback_index = [0] * 32

devInfo = DevInfo()
FirstReadDevInfo = False
WRITE_CONFIG = 1
dword_E6220 = 0


# -----------------------------------------------------------------------------
# Debug / logging helpers
# -----------------------------------------------------------------------------
def AllowDebugLogs(): return True
def AllowMoreDebugLogs(): return True
def AllowMoreDebugLogs_0(val): return AllowMoreDebugLogs()

def DEBUG(level, msg, *args):
    log("DEBUG", msg % args if args else msg)

def FastbootFail(msg):
    log("ERROR", f"FASTBOOT FAIL: {msg}")

def LogError(val, msg):
        log("ERROR",f"[LogError] {msg}")

# -----------------------------------------------------------------------------
# Memory / string helpers
# -----------------------------------------------------------------------------
def AsciiStrLen(data): return len(str(data))

def FortifyFail(msg, line):
    raise RuntimeError(f"FortifyFail at {line}: {msg}")

def AsciiStrnCpyS(a1, a2, a3, *args):
    s = str(args[0])
    return s[:a2]

def strncpySth(a1, a2):
    return AsciiStrnCpyS(a1, a2, "%a", devInfo)

# -----------------------------------------------------------------------------
# Device Info + Rollback
# -----------------------------------------------------------------------------
def ReadWriteDeviceInfo(mode, dev, size):
    if VERBOSE:
        logging.debug(f"ReadWriteDeviceInfo(mode={mode}, size={size})")
    return 0

def sub_43048(a1: int, a2: int) -> int:
    global devInfo, FirstReadDevInfo
    if FirstReadDevInfo:
        DEBUG(0x80000000, "WriteRollbackIndex DeviceInfo not initialized")
        return 0x8000000000000013
    elif a1 < 0x20:
        devInfo.rollback_index[a1] = a2
        v3 = ReadWriteDeviceInfo(WRITE_CONFIG, devInfo, 0xA20)
        if v3:
            DEBUG(0x80000000, "Unable to Write Device Info: %r", v3)
            return v3
        return 0
    else:
        DEBUG(0x80000000, "WriteRollbackIndex Loc out of range, index: %d, array len: %d", a1, 32)
        return 0x8000000000000002

def sub_43218() -> int:
    for idx in range(32):
        res = sub_43048(idx, 0)
        if res:
            DEBUG(0x80000000, "(Standard) Error clear rollback slot %d: %r\n", idx, res)
            return 0x8000000000000015
    return 0

def sub_666B8(a1: int) -> int:
    global dword_E6220
    dword_E6220 = a1
    return 0

def EraseUserPartitions():
    logging.info("Erasing user partitions (userdata, metadata, uefivarstore, etc.)")
    return 0

def SetDeviceUnlockValue(type_: int, state: int) -> int:
    logging.info(f"SetDeviceUnlockValue(type={type_}, state={state})")
    return 0

def cmp_some_regs() -> bool:
    return True

# -----------------------------------------------------------------------------
# Crypto (RSA / SHA256)
# -----------------------------------------------------------------------------
def LoadHardcodedPublicKey():
    return serialization.load_pem_public_key(PUBKEY_PEM, backend=default_backend())

def sub_679C4():
    return hashes.SHA256()

def EVP_MD_CTX_init(_): return object()
def EVP_MD_CTX_free(ctx): return
def EVP_DigestVerifyInit(ctx, blah, alg, x, pubkey): return 1
def EVP_PKEY_CTX_set_rsa_padding(*args): return 1

def EVP_PKEY_size(pubkey):
    return pubkey.key_size // 8

def EVP_DigestVerifyUpdate(ctx, data, size):
    return 1


def EVP_DigestVerifyFinal(ctx, data, sig_size):
    try:
        pub = LoadHardcodedPublicKey()
        signature = data[:sig_size]
        payload = data[sig_size:]
        pub.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return 1
    except Exception as e:
        LogError("ERROR", f"RSA verification failed: {e}")
        return -1    

# -----------------------------------------------------------------------------
# Token verifier (CheckToken replica)
# -----------------------------------------------------------------------------
def CheckToken(signature: bytes, sth: int = 0):
    log("INFO", f"[CheckToken] Public key size: {256}")
    log("INFO", f"[CheckToken] Input token size: {len(signature)}")

    md_context = EVP_MD_CTX_init(None)
    if not md_context:
        FastbootFail("Failed to create MD_CTX")
        return 0x8000000000000015

    public_key = LoadHardcodedPublicKey()
    if EVP_DigestVerifyInit(md_context, None, sub_679C4(), 0, public_key) != 1:
        FastbootFail("Verify Init error")
        return 0x8000000000000015

    if EVP_PKEY_CTX_set_rsa_padding(None, 0, 0, 0, 0) <= 0:
        FastbootFail("Failed to set to PSS padding mode")
        return 0x8000000000000015

    public_key_Size = EVP_PKEY_size(public_key)
    signature_size = public_key_Size
    if public_key_Size > len(signature):
        FastbootFail("invalid script size")
        return 0x8000000000000015

    if public_key_Size == len(signature):
        FastbootFail("Signature token format is not supported; use a script token instead")
        return 0x8000000000000015

    if EVP_DigestVerifyUpdate(md_context, signature[public_key_Size:], len(signature) - public_key_Size) != 1:
        FastbootFail("Failed on VerifyUpdate")
        return 0x8000000000000015

    if EVP_DigestVerifyFinal(md_context, signature, signature_size) != 1:
        FastbootFail("Failed on VerifyFinal")
        return 0x8000000000000015

    # serial check
    hdr_len = int.from_bytes(signature[public_key_Size:public_key_Size+4], "little")
    serial = signature[public_key_Size+4:public_key_Size+4+hdr_len].decode(errors="ignore")
    if serial != SERIAL:
        FastbootFail("Invalid bootloader script: Serial number mismatch.")
        return 0x8000000000000015

    SetDeviceUnlockValue(0, 1)
    log("INFO", "[CheckToken] SUCCESS")
    return 0
