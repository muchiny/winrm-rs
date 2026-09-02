#!/usr/bin/env python3
"""Regenerate the committed fuzz seed corpus under `fuzz/seeds/`.

The seeds are valid-ish protocol messages: real NTLM Type 1/2/3 frames, WS-Man
SOAP responses, and hand-built CredSSP DER. They exist so a cold fuzzer starts
past the "guess the magic bytes" phase — libFuzzer reaches the interesting
branches in seconds instead of minutes.

Idempotent: rerun after adding a target, commit whatever changes.

    python3 scripts/gen-fuzz-seeds.py
"""

from __future__ import annotations

import base64
import hashlib
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEEDS = ROOT / "fuzz" / "seeds"


def unhex(s: str) -> bytes:
    return bytes.fromhex("".join(s.split()))


# --- NTLM ------------------------------------------------------------------
# Captured from the pywinrm oracle vectors used in `src/ntlm/mod.rs` tests.

TYPE1 = unhex(
    "4e544c4d5353500001000000378208e200000000280000000000000028000000"
    "000c01000000000f"
)

TYPE2 = unhex(
    "4e544c4d53535000020000001e001e003800000035828ae28dc091106adfffd0"
    "00000000000000009800980056000000 0a00f4650000000f"
    "570049004e002d00540054005300540041004e0055005100300038005300"
    "02001e00570049004e002d00540054005300540041004e00550051003000380053"
    "01001e00570049004e002d00540054005300540041004e00550051003000380053"
    "04001e00570049004e002d00540054005300540041004e00550051003000380053"
    "03001e00570049004e002d00540054005300540041004e00550051003000380053"
    "0700080000f8c4ba9dc7dc010000 0000"
)

TYPE3 = unhex(
    "4e544c4d53535000030000001800180058000000f600f6007000000000000000"
    "660100000e000e00660100001e001e0074010000100010009201000035828ae2"
    "000c01000000000f00000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000008d3613113b1608b1afb92a5f"
    "0eb02477010100000000000000f8c4ba9dc7dc0120212223242526270000000002"
    "001e00570049004e002d00540054005300540041004e005500510030003800"
    "5300010000"
)

# The AV_PAIR list carried in the Type 2 TargetInfo, standalone.
AV_PAIRS = unhex(
    "02001e00570049004e002d00540054005300540041004e00550051003000380053"
    "01001e00570049004e002d00540054005300540041004e00550051003000380053"
    "04001e00570049004e002d00540054005300540041004e00550051003000380053"
    "03001e00570049004e002d00540054005300540041004e00550051003000380053"
    "0700080000f8c4ba9dc7dc010000000000000000"
)


# --- DER helpers -----------------------------------------------------------


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    return bytes([0x83, n >> 16 & 0xFF, n >> 8 & 0xFF, n & 0xFF])


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def ctx(tag: int, body: bytes) -> bytes:
    return tlv(0xA0 | tag, body)


def seq(body: bytes) -> bytes:
    return tlv(0x30, body)


def octets(body: bytes) -> bytes:
    return tlv(0x04, body)


def integer(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return tlv(0x02, body)


def ts_request(version: int, nego: bytes | None, pub_key: bytes | None,
               auth_info: bytes | None, nonce: bytes | None) -> bytes:
    body = ctx(0, integer(version))
    if nego is not None:
        body += ctx(1, seq(seq(ctx(0, octets(nego)))))
    if auth_info is not None:
        body += ctx(2, octets(auth_info))
    if pub_key is not None:
        body += ctx(3, octets(pub_key))
    if nonce is not None:
        body += ctx(5, octets(nonce))
    return seq(body)


SPNEGO_OID = unhex("06 06 2b 06 01 05 05 02")
NTLM_OID = unhex("06 0a 2b 06 01 04 01 82 37 02 02 0a")


def spnego_init(token: bytes) -> bytes:
    inner = ctx(0, seq(NTLM_OID)) + tlv(0xA2, octets(token))
    return tlv(0x60, SPNEGO_OID + ctx(0, seq(inner)))


def spnego_resp(token: bytes, mic: bytes | None = None) -> bytes:
    body = ctx(0, unhex("0a 01 01")) + tlv(0xA2, octets(token))
    if mic is not None:
        body += tlv(0xA3, octets(mic))
    return tlv(0xA1, seq(body))


def fake_certificate() -> bytes:
    """A DER shape with the nesting `extract_subject_public_key` walks."""
    algorithm = seq(unhex("06 09 2a 86 48 86 f7 0d 01 01 01") + unhex("05 00"))
    public_key = tlv(0x03, b"\x00" + b"\xAB" * 64)  # BIT STRING, 0 unused bits
    spki = seq(algorithm + public_key)
    tbs = seq(
        ctx(0, integer(2))          # version [0]
        + integer(0x1234)           # serialNumber
        + algorithm                 # signature
        + seq(b"")                  # issuer
        + seq(b"")                  # validity
        + seq(b"")                  # subject
        + spki                      # subjectPublicKeyInfo
    )
    return seq(tbs + algorithm + tlv(0x03, b"\x00" + b"\xCD" * 32))


# --- SOAP ------------------------------------------------------------------

ENVELOPE_NS = (
    'xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
    'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"'
)

SHELL_RESPONSE = f"""<s:Envelope {ENVELOPE_NS}><s:Body>
  <rsp:Shell><rsp:ShellId>C1D2E3F4-0000-0000-0000-000000000001</rsp:ShellId></rsp:Shell>
</s:Body></s:Envelope>"""

COMMAND_RESPONSE = f"""<s:Envelope {ENVELOPE_NS}><s:Body>
  <rsp:CommandResponse><rsp:CommandId>AAAA1111-2222-3333-4444-555566667777</rsp:CommandId></rsp:CommandResponse>
</s:Body></s:Envelope>"""

RECEIVE_RESPONSE = f"""<s:Envelope {ENVELOPE_NS}><s:Body>
  <rsp:ReceiveResponse>
    <rsp:Stream Name="stdout" CommandId="AAAA1111">{base64.b64encode(b'hello from winrm').decode()}</rsp:Stream>
    <rsp:Stream Name="stderr" CommandId="AAAA1111">{base64.b64encode(b'a warning').decode()}</rsp:Stream>
    <rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
      <rsp:ExitCode>0</rsp:ExitCode>
    </rsp:CommandState>
  </rsp:ReceiveResponse>
</s:Body></s:Envelope>"""

CLIXML_RESPONSE = f"""<s:Envelope {ENVELOPE_NS}><s:Body>
  <rsp:ReceiveResponse>
    <rsp:Stream Name="stderr" CommandId="AAAA1111">{base64.b64encode(b'#< CLIXML<Objs><S S="Error">boom_x000D__x000A_</S></Objs>').decode()}</rsp:Stream>
  </rsp:ReceiveResponse>
</s:Body></s:Envelope>"""

FAULT_RESPONSE = f"""<s:Envelope {ENVELOPE_NS}><s:Body>
  <s:Fault>
    <s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>wsman:InvalidSelectors</s:Value></s:Subcode></s:Code>
    <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot process the request.</s:Text></s:Reason>
  </s:Fault>
</s:Body></s:Envelope>"""

ENUMERATE_RESPONSE = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body>
  <n:EnumerateResponse>
    <n:EnumerationContext>uuid:8A3B0000-0000-0000-0000-000000000042</n:EnumerationContext>
    <w:Items><p:Win32_Process><p:Name>explorer.exe</p:Name></p:Win32_Process></w:Items>
  </n:EnumerateResponse>
</s:Body></s:Envelope>"""

ENUMERATE_END = ENUMERATE_RESPONSE.replace(
    "</n:EnumerateResponse>", "<w:EndOfSequence/></n:EnumerateResponse>"
)


# --- Seed table ------------------------------------------------------------

SEED_SETS: dict[str, list[bytes]] = {
    "fuzz_ntlm_parse": [TYPE1, TYPE2, TYPE3, b"NTLMSSP\x00\x02\x00\x00\x00", b""],
    "fuzz_ntlm_challenge_header": [TYPE2, TYPE2[12:], AV_PAIRS],
    "fuzz_ntlm_header_decode": [
        b"Negotiate " + base64.b64encode(TYPE2),
        b"Negotiate " + base64.b64encode(TYPE1),
        b"NTLM " + base64.b64encode(TYPE2),
        b"Negotiate",
        b"Negotiate !!!not base64!!!",
    ],
    "fuzz_ntlm_av_pairs": [
        AV_PAIRS,
        unhex("0000 0000"),
        unhex("0700 0800 0000000000000000"),
        unhex("02 00 ff ff") + b"A" * 16,
    ],
    "fuzz_ntlm_seal": [bytes(range(16)) + b"SOAP body", bytes(16), bytes(32)],
    "fuzz_ntlm_session": [bytes(range(32)), bytes(64), b"\x01" * 48],
    "fuzz_ntlm_crypto": [bytes(range(64)), b"Administrator\x00P@ssw0rd\x00WORKGROUP\x00"],
    "fuzz_ntlm_type3": [TYPE2, bytes(range(96)), AV_PAIRS],
    "fuzz_soap_parse": [
        SHELL_RESPONSE.encode(),
        COMMAND_RESPONSE.encode(),
        RECEIVE_RESPONSE.encode(),
        CLIXML_RESPONSE.encode(),
        FAULT_RESPONSE.encode(),
    ],
    "fuzz_soap_enumerate": [
        ENUMERATE_RESPONSE.encode(),
        ENUMERATE_END.encode(),
        FAULT_RESPONSE.encode(),
    ],
    "fuzz_soap_envelope": [
        b"http://host:5985/wsman\x00Shell-1\x00Cmd-1\x00ipconfig\x00",
        b"<injected/>\x00&amp;\x00'\"\x00",
        bytes(range(128)),
    ],
    "fuzz_xml_escape": [
        b"<script>alert(1)</script>",
        b"a<b>c&d\"e'f",
        b"&amp;&lt;&gt;&quot;&apos;",
        b"plain text",
        "accentu\u00e9 \u4e2d\u6587 \U0001f600".encode(),
    ],
    "fuzz_transport_host": [
        b"win-server",
        b"10.0.0.1",
        b"[fe80::1]",
        b"https://evil.example.com:1234/path",
        b"user:pw@host.example.com",
        b"host.example.com:5986",
    ],
    "fuzz_transfer_path": [
        rb"C:\Windows\Temp\payload.bin",
        rb"C:\Users\it's mine\file.txt",
        b"C:\\a\tb",
        b"C:\\a\x00b",
        b"C:\\" + b"A" * 300,
    ],
    "fuzz_powershell_encode": [
        b"Get-Process | ConvertTo-Json",
        b"Write-Output 'h\xc3\xa9llo'",
        b"",
        "\U0001f600 emoji".encode(),
    ],
    "fuzz_asn1_ts_request": [
        ts_request(6, TYPE1, None, None, None),
        ts_request(6, None, b"\xAA" * 32, None, b"\xBB" * 32),
        ts_request(2, None, None, b"\xCC" * 64, None),
        ts_request(0x8000_0001, None, None, None, None),
        seq(b""),
    ],
    "fuzz_asn1_spnego": [
        spnego_init(TYPE1),
        spnego_resp(TYPE3),
        spnego_resp(TYPE3, unhex("0100000002f81117bb3953f700000000")),
        SPNEGO_OID,
    ],
    "fuzz_asn1_cert": [fake_certificate(), seq(b""), b"\x30\x82\xff\xff"],
}


def main() -> None:
    if SEEDS.exists():
        shutil.rmtree(SEEDS)
    total = 0
    for target, seeds in sorted(SEED_SETS.items()):
        out = SEEDS / target
        out.mkdir(parents=True)
        for blob in seeds:
            name = hashlib.sha1(blob).hexdigest()[:16]
            (out / name).write_bytes(blob)
            total += 1
        print(f"{target}: {len(seeds)} seeds")
    print(f"\n{total} seeds written to {SEEDS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
