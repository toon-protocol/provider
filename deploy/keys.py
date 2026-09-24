#!/usr/bin/env python3
"""The key material a box needs, and every address it has to fund.

Run through ./keys.sh, never directly: keys.sh sources .env the way
bootstrap.sh and render.sh do and hands this the values, so there is one
reading of that file and not two.

    keys.sh init            generate every missing key file and .env secret
    keys.sh addresses       print every address to fund, and what with
    keys.sh check-funded    refuse (exit 1) if a key that must be funded is not

Why Python, and why everything below is written out by hand: this runs BEFORE
bootstrap.sh, on a host that has no Docker yet, so it cannot ask the
connector's or the publisher's image to derive anything. python3 ships with
every Ubuntu release a box runs on (cloud-init is written in it), and its
standard library already has SHA-2, HMAC, PBKDF2, a CSPRNG and an HTTP client.
The three things it lacks -- ed25519 and secp256k1 public-key derivation, and
Keccak-256 -- are a few dozen lines each, below, and depend on nothing. A
public key is not a secret operation: there is no signing here, so constant
time does not matter, and correctness is pinned by tests against each
component's own derivation (tests/deploy_keys.rs in the provider,
deploy/keys.test.mjs in the gateway).

What each address is, and whose derivation it has to equal:

  * The connector's Solana settlement address. settlement-solana.key is an
    ed25519 SEED (connector `read_settlement_key_bytes`, then
    `keypair_from_seed`); the address is its public key in base58.
  * The connector's EVM settlement address. settlement.key is a secp256k1
    secret; the address is the last 20 bytes of Keccak-256 over the
    uncompressed public key (connector-signer `derive_evm_address`), printed
    here with EIP-55 casing. `GET /ilp` prints the same address in lowercase.
  * The operator write key's keyid: the ed25519 public key of a seed, in hex --
    exactly `connector send --operator-key <file> --print-keyid`.
  * The publisher's Solana wallet (provider only): the BIP-39 seed of
    PUBLISHER_MNEMONIC, SLIP-0010 ed25519 at m/44'/501'/0'/0', in base58 --
    @toon-protocol/client's `deriveFullIdentity(mnemonic.trim(),
    {accountIndex: 0})`, which is what the publisher pays from.
  * The provider's npub (provider only): NIP-19 bech32 of the x-only
    secp256k1 public key of NOSTR_PRIVATE_KEY.
"""

import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import unicodedata
import urllib.error
import urllib.request

# ── ed25519 (RFC 8032 §5.1) ─────────────────────────────────────────────────

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_add(a, b):
    # Extended coordinates (X, Y, Z, T), RFC 8032's reference formula.
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(scalar, point):
    acc = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            acc = _ed_add(acc, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return acc


def _ed_base():
    y = 4 * pow(5, _P - 2, _P) % _P
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if x & 1:
        x = _P - x
    return (x, y, 1, x * y % _P)


_ED_G = _ed_base()


def ed25519_public_key(seed):
    """The 32-byte public key of a 32-byte ed25519 seed (a "secret key")."""
    if len(seed) != 32:
        raise ValueError("an ed25519 seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    x, y, z, _ = _ed_mul(scalar, _ED_G)
    zinv = pow(z, _P - 2, _P)
    x, y = x * zinv % _P, y * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


# ── secp256k1 ───────────────────────────────────────────────────────────────

_SECP_P = 2**256 - 2**32 - 977
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _secp_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _SECP_P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], _SECP_P - 2, _SECP_P)
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], _SECP_P - 2, _SECP_P)
    x = (slope * slope - a[0] - b[0]) % _SECP_P
    return (x, (slope * (a[0] - x) - a[1]) % _SECP_P)


def secp256k1_valid_secret(secret):
    return len(secret) == 32 and 0 < int.from_bytes(secret, "big") < _SECP_N


def secp256k1_public_point(secret):
    """(x, y) of a 32-byte secp256k1 secret, refusing one outside [1, n)."""
    if not secp256k1_valid_secret(secret):
        raise ValueError("not a secp256k1 secret key (zero, or not below the group order)")
    scalar, point, acc = int.from_bytes(secret, "big"), _SECP_G, None
    while scalar:
        if scalar & 1:
            acc = _secp_add(acc, point)
        point = _secp_add(point, point)
        scalar >>= 1
    return acc


# ── Keccak-256 (the pre-NIST padding Ethereum uses; NOT hashlib.sha3_256) ─────

_MASK = (1 << 64) - 1


def _rol(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_tables():
    # Both tables generated, not transcribed: the rotation offsets from the
    # (x, y) -> (y, 2x + 3y) walk, the round constants from the rc LFSR
    # (FIPS 202 §3.2.2 and §3.2.5).
    rotations = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        rotations[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    lfsr, constants = 1, []
    for _ in range(24):
        rc = 0
        for j in range(7):
            if lfsr & 1:
                rc |= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ 0x171) if lfsr & 0x80 else (lfsr << 1)
        constants.append(rc)
    return rotations, constants


_ROT, _RC = _keccak_tables()


def _keccak_f(lanes):
    for rc in _RC:
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        lanes = [lanes[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(lanes[x + 5 * y], _ROT[x][y])
        lanes = [
            b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)] & _MASK)
            for i in range(25)
        ]
        lanes[0] ^= rc
    return lanes


def keccak256(data, pad=0x01):
    """Keccak-256. `pad=0x06` makes it SHA3-256, which is how it is tested."""
    rate = 136
    padded = bytearray(data)
    padded.append(pad)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    lanes = [0] * 25
    for block in range(0, len(padded), rate):
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(padded[block + 8 * i:block + 8 * i + 8], "little")
        lanes = _keccak_f(lanes)
    return b"".join(lane.to_bytes(8, "little") for lane in lanes[:4])


def evm_address(secret):
    """The EIP-55 checksummed address of a secp256k1 secret."""
    x, y = secp256k1_public_point(secret)
    lower = keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:].hex()
    nibbles = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if int(n, 16) >= 8 else c for c, n in zip(lower, nibbles))


# ── Encodings ───────────────────────────────────────────────────────────────

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data):
    value, out = int.from_bytes(data, "big"), ""
    while value:
        value, digit = divmod(value, 58)
        out = _B58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32(hrp, data):
    """BIP-173 bech32 (not bech32m), which is what NIP-19 uses."""
    acc, bits, words = 0, 0, []
    for byte in data:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            words.append((acc >> bits) & 31)
    if bits:
        words.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    poly = _bech32_polymod(expanded + words + [0] * 6) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[w] for w in words + checksum)


def npub(secret):
    x, _ = secp256k1_public_point(secret)
    return bech32("npub", x.to_bytes(32, "big"))


def nostr_secret(value):
    """NOSTR_PRIVATE_KEY as the provider reads it (nostr-sdk `Keys::parse`):
    64 hex characters, or a NIP-19 `nsec1...`."""
    if value.startswith("nsec1"):
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        words = [charset.index(c) for c in value[5:]]
        expanded = [ord(c) >> 5 for c in "nsec"] + [0] + [ord(c) & 31 for c in "nsec"]
        if _bech32_polymod(expanded + words) != 1:
            raise ValueError("NOSTR_PRIVATE_KEY is an nsec with a bad checksum")
        acc, bits, out = 0, 0, bytearray()
        for w in words[:-6]:
            acc, bits = (acc << 5) | w, bits + 5
            if bits >= 8:
                bits -= 8
                out.append((acc >> bits) & 255)
        return bytes(out)
    return bytes.fromhex(value)


# ── BIP-39 and SLIP-0010 ────────────────────────────────────────────────────

WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bip39-english.txt")


def _wordlist():
    with open(WORDLIST, encoding="utf-8") as handle:
        words = handle.read().split()
    if len(words) != 2048:
        raise ValueError(f"{WORDLIST} is not the 2048-word BIP-39 English list")
    return words


def generate_mnemonic():
    """12 words, from 128 bits: what @toon-protocol/client generates."""
    entropy = secrets.token_bytes(16)
    bits = int.from_bytes(entropy, "big") << 4 | hashlib.sha256(entropy).digest()[0] >> 4
    words = _wordlist()
    return " ".join(words[(bits >> (11 * i)) & 2047] for i in reversed(range(12)))


def mnemonic_checksum_ok(phrase):
    words = _wordlist()
    try:
        indices = [words.index(w) for w in phrase.split(" ")]
    except ValueError:
        return False
    total = len(indices) * 11
    ent_bits = total * 32 // 33
    value = 0
    for index in indices:
        value = value << 11 | index
    entropy = (value >> (total - ent_bits)).to_bytes(ent_bits // 8, "big")
    check = value & ((1 << (total - ent_bits)) - 1)
    return hashlib.sha256(entropy).digest()[0] >> (8 - (total - ent_bits)) == check


def mnemonic_seed(phrase):
    """@scure/bip39's mnemonicToSeedSync, including the phrase it refuses."""
    normalized = unicodedata.normalize("NFKD", phrase)
    if len(normalized.split(" ")) not in (12, 15, 18, 21, 24):
        raise ValueError("not a BIP-39 phrase: 12, 15, 18, 21 or 24 words separated by single spaces")
    return hashlib.pbkdf2_hmac("sha512", normalized.encode(), b"mnemonic", 2048)


def solana_address_from_mnemonic(phrase, account_index=0):
    """m/44'/501'/{account}'/0', SLIP-0010 ed25519, all hardened."""
    digest = hmac.new(b"ed25519 seed", mnemonic_seed(phrase.strip()), hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in (44, 501, account_index, 0):
        data = b"\0" + key + (0x80000000 + index).to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return base58(ed25519_public_key(key))


# ── Key files ───────────────────────────────────────────────────────────────


def decode_key(raw):
    """The connector's own reading of a key file (connector-cli runtime.rs
    `decode_secret_key`): 64 hex characters with surrounding whitespace
    ignored, else exactly 32 raw bytes, else nothing."""
    try:
        text = raw.decode("utf-8").strip()
        if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
            return bytes.fromhex(text)
    except UnicodeDecodeError:
        pass
    return raw if len(raw) == 32 else None


def read_key(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        raise KeyError(f"{path} is missing -- run ./keys.sh init") from None
    key = decode_key(raw)
    if key is None:
        raise KeyError(f"{path} is not 64 hex characters or 32 raw bytes, the only formats the connector reads")
    return key


def fresh_secp256k1_hex():
    # Every 32-byte string is an ed25519 seed; a secp256k1 secret must also be
    # nonzero and below n, which one draw in 2^128 is not. One rule for all.
    while True:
        secret = secrets.token_bytes(32)
        if secp256k1_valid_secret(secret):
            return secret.hex()


# ── The roles ───────────────────────────────────────────────────────────────

KEY_FILES = {
    "signer.key": "the connector's sealing key (what a tenant seals to)",
    "settlement.key": "the connector's EVM settlement key",
    "settlement-solana.key": "the connector's Solana settlement key",
}

# 0.005 SOL: an associated token account's rent (~0.00204 SOL) plus fees,
# which is what the connector spends at boot, with room to spare. The
# README asks for 1-2 SOL; this is the floor below which a first boot is
# certain to fail, not a recommendation.
MIN_LAMPORTS = 5_000_000
# The publisher deposits TOON_DEPOSIT (docker-compose.yml) into the channel it
# opens on first publish: 10 USDC at 6 decimals.
PUBLISHER_DEPOSIT = 10_000_000

DEVNET_SOLANA_RPC = "https://api.devnet.solana.com"
TOON_FAUCET = "https://faucet.devnet.toonprotocol.dev"


def env(name):
    return os.environ.get(name, "").strip()


def is_devnet_preset():
    return env("SETTLEMENT_SOLANA_RPC_URL") == DEVNET_SOLANA_RPC


def set_env_line(name, value, quote=False):
    """Fill NAME in .env: its first uncommented `NAME=` line if there is one,
    else a new line at the end. Only ever called for a NAME whose sourced
    value is empty, so nothing an operator wrote is replaced."""
    rendered = f"{name}='{value}'" if quote else f"{name}={value}"
    with open(".env", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"{name}="):
            lines[i] = rendered
            break
    else:
        lines.append(rendered)
    with open(".env", "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def write_key_file(path, hex_value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as handle:
        handle.write(hex_value + "\n")


def cmd_init(role):
    made = []
    for path, what in KEY_FILES.items():
        if os.path.exists(path):
            print(f"    {path:<24} kept (exists)")
            continue
        write_key_file(path, fresh_secp256k1_hex())
        made.append(path)
        print(f"    {path:<24} generated -- {what}")

    secrets_in_env = [("OPERATOR_BEARER_TOKEN", lambda: secrets.token_hex(32), False)]
    if role == "provider":
        secrets_in_env.insert(0, ("NOSTR_PRIVATE_KEY", fresh_secp256k1_hex, False))
        secrets_in_env.append(("PUBLISHER_MNEMONIC", generate_mnemonic, True))
    for name, make, quote in secrets_in_env:
        if env(name):
            print(f"    {name:<24} kept (set in .env)")
            continue
        set_env_line(name, make(), quote)
        made.append(name)
        print(f"    {name:<24} generated into .env")

    operator_private = None
    if env("OPERATOR_WRITE_KEY"):
        print(f"    {'OPERATOR_WRITE_KEY':<24} kept (set in .env)")
    else:
        seed = secrets.token_bytes(32)
        operator_private = seed.hex()
        set_env_line("OPERATOR_WRITE_KEY", ed25519_public_key(seed).hex())
        made.append("OPERATOR_WRITE_KEY")
        print(f"    {'OPERATOR_WRITE_KEY':<24} generated into .env (the public half)")

    print()
    if not made:
        print("Nothing was missing; nothing was changed.")
    backup = [n for n in made if n in KEY_FILES or n in ("NOSTR_PRIVATE_KEY", "PUBLISHER_MNEMONIC")]
    if backup:
        print("Back these up somewhere off this box; losing one loses what it identifies or holds:")
        print("    " + ", ".join(backup))
    if operator_private is not None:
        print()
        print("THE OPERATOR WRITE KEY'S PRIVATE HALF -- shown once, and stored nowhere on this box.")
        print("Save it on the machine you administer from, as a file of its own:")
        print()
        print(f"    {operator_private}")
        print()
        print("That file is what `connector send --operator-key <file>` signs operator writes with.")
        print("Lose it and you generate a new pair: empty OPERATOR_WRITE_KEY in .env and re-run this.")
    print()
    print("Next: fund what ./keys.sh addresses prints, then run ./bootstrap.sh.")


def addresses(role):
    """[(label, address, required_for, funding_lines)] plus the unfunded facts."""
    solana = base58(ed25519_public_key(read_key("settlement-solana.key")))
    evm = evm_address(read_key("settlement.key"))
    devnet = is_devnet_preset()
    rows = [(
        "The connector's Solana settlement address",
        solana,
        "REQUIRED TO BOOT: the connector pays for a transaction at startup",
        [
            "1-2 devnet SOL, from https://faucet.solana.com (paste the address, pick devnet)",
            f"or, with the Solana CLI: solana airdrop 1 {solana} --url devnet",
        ] if devnet else [f"SOL on the chain {env('SETTLEMENT_SOLANA_RPC_URL')} serves (0.01 SOL or more)"],
    )]
    if role == "provider":
        mnemonic = env("PUBLISHER_MNEMONIC")
        if not mnemonic:
            raise KeyError("PUBLISHER_MNEMONIC is empty in .env -- run ./keys.sh init")
        publisher = solana_address_from_mnemonic(mnemonic)
        if not mnemonic_checksum_ok(mnemonic.strip()):
            # The publisher derives from it anyway (@scure/bip39 checks only
            # the word count there), so the address below is still the one it
            # pays from -- but no wallet will import the phrase.
            print("::warning:: PUBLISHER_MNEMONIC fails the BIP-39 word list or checksum; "
                  "the publisher still derives the address below, but no wallet will import the phrase.",
                  file=sys.stderr)
        rows.append((
            "The publisher's Solana wallet (PUBLISHER_MNEMONIC)",
            publisher,
            "REQUIRED TO BE LISTED: it pays the relay for every directory write",
            [
                "1 devnet SOL, from https://faucet.solana.com, and mock USDC:",
                f"curl -X POST {TOON_FAUCET}/api/solana/usdc-request \\",
                "  -H 'content-type: application/json' -d '{\"address\":\"" + publisher + "\"}'",
            ] if devnet else [
                f"SOL, and at least {PUBLISHER_DEPOSIT / 1e6:g} of the token {env('SETTLEMENT_SOLANA_TOKEN')}",
            ],
        ))
    rows.append((
        "The connector's EVM settlement address",
        evm,
        "Not needed to boot: only to redeem earnings on chain",
        [
            "Base Sepolia ETH, before your first redeem:",
            "https://www.alchemy.com/faucets/base-sepolia or https://portal.cdp.coinbase.com/products/faucet",
        ] if env("SETTLEMENT_EVM_CHAIN_ID") in ("", "84532") and devnet else [
            "the native coin of the chain SETTLEMENT_EVM_RPC_URL serves, before your first redeem",
        ],
    ))
    facts = []
    if role == "provider" and env("NOSTR_PRIVATE_KEY"):
        try:
            facts.append(("This provider's Nostr identity", npub(nostr_secret(env("NOSTR_PRIVATE_KEY")))))
        except ValueError:
            # Informational only; render.sh and the provider refuse a bad key
            # by name, and a funding check is no place to fail on it.
            facts.append(("This provider's Nostr identity", "(NOSTR_PRIVATE_KEY does not parse)"))
    if env("OPERATOR_WRITE_KEY"):
        facts.append(("OPERATOR_WRITE_KEY (the public half)", env("OPERATOR_WRITE_KEY")))
    return rows, facts


def cmd_addresses(role):
    rows, facts = addresses(role)
    print("Fund these before ./bootstrap.sh. None of this is secret.")
    for n, (label, address, why, funding) in enumerate(rows, 1):
        print()
        print(f"{n}. {label}")
        print(f"   {address}")
        print(f"   {why}")
        print("   Fund with: " + funding[0])
        for line in funding[1:]:
            print(f"     {line}")
    if facts:
        print()
        print("Not funded, but yours:")
        for label, value in facts:
            print(f"   {label}: {value}")


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        answer = json.load(response)
    if "error" in answer:
        raise RuntimeError(answer["error"].get("message", str(answer["error"])))
    return answer["result"]


def lamports(url, address):
    return rpc(url, "getBalance", [address, {"commitment": "confirmed"}])["value"]


def token_units(url, owner, mint):
    result = rpc(url, "getTokenAccountsByOwner", [owner, {"mint": mint}, {"encoding": "jsonParsed", "commitment": "confirmed"}])
    return sum(int(a["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"]) for a in result["value"])


def cmd_check_funded(role, warn_only):
    """Exit 0 funded, 1 short (unless warn_only), 3 could not ask the chain.

    A hidden box asks only its OWN Solana node (HIDDEN_SETTLEMENT_SOLANA_RPC_URL):
    a getBalance to a public RPC from its address would link that address to
    its settlement keys, which is the one thing hiding it is for."""
    hidden = env("HIDDEN") == "1"
    connector_rpc = env("HIDDEN_SETTLEMENT_SOLANA_RPC_URL") if hidden else env("SETTLEMENT_SOLANA_RPC_URL")
    publisher_rpc = connector_rpc if hidden else (env("SOLANA_RPC_URL") or DEVNET_SOLANA_RPC)
    rows, _ = addresses(role)
    short = []
    try:
        balance = lamports(connector_rpc, rows[0][1])
        print(f"    connector  {rows[0][1]}  {balance / 1e9:.4f} SOL")
        if balance < MIN_LAMPORTS:
            short.append(f"the connector's Solana settlement address holds {balance / 1e9:.4f} SOL")
        if role == "provider":
            publisher = rows[1][1]
            balance = lamports(publisher_rpc, publisher)
            usdc = token_units(publisher_rpc, publisher, env("SETTLEMENT_SOLANA_TOKEN"))
            print(f"    publisher  {publisher}  {balance / 1e9:.4f} SOL, {usdc / 1e6:g} USDC")
            if balance < MIN_LAMPORTS:
                short.append(f"the publisher's wallet holds {balance / 1e9:.4f} SOL")
            if usdc < PUBLISHER_DEPOSIT:
                short.append(f"the publisher's wallet holds {usdc / 1e6:g} USDC, less than the {PUBLISHER_DEPOSIT / 1e6:g} it deposits")
    except (OSError, urllib.error.URLError, RuntimeError, KeyError, ValueError) as error:
        print(f"::warning:: could not read a balance from the Solana RPC ({error}); not checked.")
        return 3
    if not short:
        return 0
    for reason in short:
        print(f"    short: {reason}")
    if warn_only:
        print("::warning:: this box's connector is already running, so this is a warning, not a refusal.")
        return 0
    print()
    print("REFUSED before anything starts: an unfunded Solana settlement key is a connector")
    print("that restart-loops. Fund what is listed below, then re-run ./bootstrap.sh.")
    print()
    cmd_addresses(role)
    return 1


def main(argv):
    if len(argv) < 3 or argv[1] not in ("provider", "gateway"):
        print("usage: keys.py provider|gateway init|addresses|check-funded [--warn-only]", file=sys.stderr)
        return 2
    role, command = argv[1], argv[2]
    try:
        if command == "init":
            cmd_init(role)
            return 0
        if command == "addresses":
            cmd_addresses(role)
            return 0
        if command == "check-funded":
            return cmd_check_funded(role, "--warn-only" in argv[3:])
        # The derivations alone, one per line, for the tests that pin them.
        if command == "derive":
            print(json.dumps(derive_all(role)))
            return 0
    except KeyError as error:
        print(f"keys.sh: {error.args[0]}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"keys.sh: {error}", file=sys.stderr)
        return 1
    print(f"keys.sh: unknown command {command!r}", file=sys.stderr)
    return 2


def derive_all(role):
    out = {
        "connector_solana": base58(ed25519_public_key(read_key("settlement-solana.key"))),
        "connector_solana_hex": ed25519_public_key(read_key("settlement-solana.key")).hex(),
        "connector_evm": evm_address(read_key("settlement.key")),
    }
    if os.path.exists("operator-write.key"):
        out["operator_keyid"] = ed25519_public_key(read_key("operator-write.key")).hex()
    if role == "provider":
        if env("PUBLISHER_MNEMONIC"):
            out["publisher_solana"] = solana_address_from_mnemonic(env("PUBLISHER_MNEMONIC"))
        if env("NOSTR_PRIVATE_KEY"):
            out["npub"] = npub(nostr_secret(env("NOSTR_PRIVATE_KEY")))
    return out


if __name__ == "__main__":
    sys.exit(main(sys.argv))
