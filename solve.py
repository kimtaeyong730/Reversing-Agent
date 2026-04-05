"""
rev-agent v5 — py_eval-first architecture
==========================================
MCP 응답 파싱 문제를 근본적으로 해결:
  - 데이터 수집은 전부 py_eval (IDA Python 직접 실행)
  - decompile만 MCP 도구 사용 (result.code 필드가 명확)
  - callees, globals, imports, strings 전부 py_eval

Phase 1 (LLM 0회): py_eval + decompile로 수집
Phase 2 (LLM 1회): solver 코드 생성
Phase 3 (LLM 0회): py_eval로 실행
"""

import asyncio, json, re, sys, os, logging
from pathlib import Path
import httpx

# ── .env ─────────────────────────────────────────
for p in [Path.cwd() / ".env", Path(__file__).parent / ".env"]:
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip("'\"")
            for sep in ["  #", "\t#"]:
                if sep in v: v = v[:v.index(sep)].strip()
            os.environ.setdefault(k, v)
        break

API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
MCP_URL = os.getenv("IDA_MCP_BASE_URL", "http://127.0.0.1:13337").rstrip("/") + "/mcp"
MCP_TIMEOUT = int(os.getenv("IDA_MCP_TIMEOUT", "60"))
MODEL = {"claude-sonnet-4-6": "claude-sonnet-4-20250514"}.get(MODEL, MODEL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("agent")


# ══════════════════════════════════════════════════
#  IDA MCP — py_eval + decompile만 사용
# ══════════════════════════════════════════════════

class IDA:
    def __init__(self):
        self._id = 0

    async def _mcp(self, tool: str, args: dict) -> dict:
        self._id += 1
        async with httpx.AsyncClient(timeout=MCP_TIMEOUT) as c:
            r = await c.post(MCP_URL, json={
                "jsonrpc": "2.0", "id": self._id, "method": "tools/call",
                "params": {"name": tool, "arguments": args}
            }, headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
            ct = r.headers.get("content-type", "")
            if "text/event-stream" in ct:
                last = None
                for ln in r.text.splitlines():
                    if ln.startswith("data: "):
                        try: last = json.loads(ln[6:])
                        except: pass
                return last or {}
            return r.json()

    async def py_eval(self, code: str) -> str:
        """py_eval → stdout 문자열 반환"""
        d = await self._mcp("py_eval", {"code": code})
        r = d.get("result", {})
        if not isinstance(r, dict): return str(r)
        sc = r.get("structuredContent")
        if isinstance(sc, dict):
            parts = []
            if sc.get("stdout"): parts.append(sc["stdout"].rstrip("\n"))
            if sc.get("stderr"): parts.append(f"[STDERR] {sc['stderr']}")
            return "\n".join(parts) if parts else ""
        for item in r.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                tv = item.get("text", "")
                try:
                    p = json.loads(tv)
                    if isinstance(p, dict):
                        parts = []
                        if p.get("stdout"): parts.append(p["stdout"].rstrip("\n"))
                        if p.get("stderr"): parts.append(f"[STDERR] {p['stderr']}")
                        return "\n".join(parts) if parts else ""
                except: return tv
        return ""

    async def py_json(self, code: str) -> any:
        """py_eval → stdout의 JSON을 파싱해서 반환"""
        raw = await self.py_eval(code)
        for ln in raw.splitlines():
            ln = ln.strip()
            if ln.startswith("{") or ln.startswith("["):
                return json.loads(ln)
        return None

    async def decompile(self, addr: str) -> str:
        """decompile만 MCP 직접 사용 (result.code가 명확)"""
        d = await self._mcp("decompile", {"addr": addr})
        r = d.get("result", {})
        if isinstance(r, dict):
            if r.get("code"): return r["code"]
            if r.get("error"): return f"[DECOMPILE ERROR] {r['error']}"
        return str(r)

    async def disasm(self, addr: str) -> str:
        """disassemble → assembly text"""
        d = await self._mcp("disasm", {"addr": addr})
        r = d.get("result", {})
        if isinstance(r, dict) and "asm" in r:
            asm = r["asm"]
            if isinstance(asm, dict) and "lines" in asm:
                return asm["lines"]
        return ""


# ══════════════════════════════════════════════════
#  Phase 1: 수집 (LLM 0회)
# ══════════════════════════════════════════════════

async def phase1(ida: IDA) -> dict:
    info = {}

    # 1) 바이너리 정보 + main
    log.info("[Phase 1] Binary info...")
    info["binary"] = await ida.py_json(
        'import idc,ida_nalt,idautils,json\n'
        'bi={"file":ida_nalt.get_input_file_path(),"name":ida_nalt.get_root_filename(),'
        '"bits":64 if idc.__EA64__ else 32,"entry":hex(idc.get_inf_attr(idc.INF_START_EA))}\n'
        'funcs=[{"a":hex(ea),"n":idc.get_func_name(ea)} for ea in idautils.Functions()]\n'
        'bi["func_count"]=len(funcs)\n'
        'bi["main"]=next((f["a"] for f in funcs if f["n"]=="main"),None)\n'
        'print(json.dumps(bi))')
    if not info.get("binary"):
        log.error("Failed to get binary info"); return info
    main = info["binary"].get("main") or info["binary"].get("entry")
    info["main_addr"] = main
    log.info(f"  {info['binary']['name']} ({info['binary']['bits']}bit), "
             f"{info['binary']['func_count']} funcs, main={main}")

    # 2) imports
    log.info("[Phase 1] Imports...")
    info["imports"] = await ida.py_eval(
        'import ida_nalt,json\nimp=[]\n'
        'for i in range(ida_nalt.get_import_module_qty()):\n'
        '    mod=ida_nalt.get_import_module_name(i)\n'
        '    def cb(ea,name,ordinal,_o=imp,_m=mod):\n'
        '        if name:_o.append(f"{_m}::{name}")\n'
        '        return True\n'
        '    ida_nalt.enum_import_names(i,cb)\n'
        'print(json.dumps(imp))')

    # 3) 문자열
    log.info("[Phase 1] Strings...")
    info["strings"] = await ida.py_eval(
        'import idautils,json\n'
        'strs=[str(s) for s in idautils.Strings() if any(k in str(s).lower() '
        'for k in ["flag","correct","wrong","password","key","input","check","secret","dh{","ctf{"])]\n'
        'print(json.dumps(strs[:30]))')

    # 4) main 디컴파일
    log.info(f"[Phase 1] Decompile main @ {main}...")
    info["main_code"] = await ida.decompile(main)

    # 5) callees via py_eval (2-depth)
    log.info("[Phase 1] Callees (2-depth)...")
    callees_1 = await ida.py_json(
        f'import idautils,idc,json\n'
        f'cs=set()\n'
        f'for item in idautils.FuncItems({main}):\n'
        f'    for xref in idautils.CodeRefsFrom(item,0):\n'
        f'        fn=idc.get_func_name(xref)\n'
        f'        if fn and fn!=idc.get_func_name({main}):\n'
        f'            cs.add((hex(idc.get_func_attr(xref,idc.FUNCATTR_START)),fn))\n'
        f'print(json.dumps([{{"addr":a,"name":n}} for a,n in sorted(cs)]))')
    callees_1 = callees_1 or []

    info["callee_codes"] = {}
    info["decompile_failed"] = []  # 디컴파일 실패한 함수 추적
    seen = {main}
    all_callee_addrs = []

    for c in callees_1:
        addr, name = c.get("addr", ""), c.get("name", "")
        if not addr or addr in seen: continue
        # PLT/외부 함수 스킵
        if name.startswith("."): continue
        if name.startswith("__") and name not in ("__main",): continue
        if name in ("puts", "printf", "scanf", "memset", "memcpy", "strlen", "strcmp",
                     "memcmp", "__security_check_cookie", "__stack_chk_fail"): continue
        seen.add(addr)
        log.info(f"  {name} @ {addr}")
        code = await ida.decompile(addr)
        is_failed = (
            not code
            or code == "None"
            or "[DECOMPILE ERROR]" in code
            or "[ERROR]" in code
            or code.startswith("None")
            or code.startswith("{")  # raw JSON returned
            or len(code) < 20  # too short to be real code
        )
        if is_failed:
            # 함수 크기 확인
            size_raw = await ida.py_eval(
                f'import idc;print(idc.find_func_end({addr})-{addr})')
            fsize = 0
            for ln in size_raw.splitlines():
                try: fsize = int(ln.strip()); break
                except: pass
            log.warning(f"  {name} decompile FAILED (size={fsize})")
            info["decompile_failed"].append({"name": name, "addr": addr, "size": fsize})
            # 디스어셈블리로 대체 (5000 명령어 이하인 함수만)
            if fsize < 50000:
                log.info(f"  {name} — collecting disassembly instead")
                asm_code = await ida.disasm(addr)
                if asm_code:
                    info["callee_codes"][f"{name}@{addr}"] = f"/* DISASSEMBLY (decompile failed) */\n{asm_code}"
        else:
            info["callee_codes"][f"{name}@{addr}"] = code
        all_callee_addrs.append(addr)

    # depth-2
    for parent_addr in all_callee_addrs:
        d2 = await ida.py_json(
            f'import idautils,idc,json\n'
            f'cs=set()\n'
            f'for item in idautils.FuncItems({parent_addr}):\n'
            f'    for xref in idautils.CodeRefsFrom(item,0):\n'
            f'        fn=idc.get_func_name(xref)\n'
            f'        if fn and fn!=idc.get_func_name({parent_addr}):\n'
            f'            cs.add((hex(idc.get_func_attr(xref,idc.FUNCATTR_START)),fn))\n'
            f'print(json.dumps([{{"addr":a,"name":n}} for a,n in sorted(cs)]))')
        for c in (d2 or []):
            addr, name = c.get("addr", ""), c.get("name", "")
            if not addr or addr in seen: continue
            if name in ("puts", "printf", "scanf", "memset", "memcpy", "strlen", "strcmp",
                         "memcmp", "__security_check_cookie", "__stack_chk_fail"): continue
            seen.add(addr)
            log.info(f"    {name} @ {addr}")
            info["callee_codes"][f"{name}@{addr}"] = await ida.decompile(addr)

    # 6) 글로벌 데이터
    log.info("[Phase 1] Globals...")
    all_code = info["main_code"] + "\n" + "\n".join(info["callee_codes"].values())
    # 모든 글로벌 변수명 추출
    gnames = list(dict.fromkeys(
        m.group(1) for m in re.finditer(
            r'\b(byte_[0-9a-fA-F]+|dword_[0-9a-fA-F]+|qword_[0-9a-fA-F]+'
            r'|s2|aC\w*|aS\w*|unk_[0-9a-fA-F]+)\b', all_code)
        if m.group(1) != "s1"
    ))

    if gnames:
        info["globals"] = {}
        for g in gnames:
            code = (
                'import idc,ida_bytes,json\n'
                f'ea=idc.get_name_ea_simple("{g}")\n'
                'if ea!=idc.BADADDR:\n'
                '  raw=[ida_bytes.get_byte(ea+i) for i in range(256)]\n'
                '  str_key=[]\n'
                '  for b in raw:\n'
                '    if b==0:break\n'
                '    str_key.append(b)\n'
                '  dwords=[]\n'
                '  for i in range(0,256,4):\n'
                '    v=raw[i]|(raw[i+1]<<8)|(raw[i+2]<<16)|(raw[i+3]<<24)\n'
                '    dwords.append(v)\n'
                '  dc=""\n'
                '  for v in dwords:\n'
                '    if 0x20<=v<=0x7e:dc+=chr(v)\n'
                '    elif v==0:break\n'
                '    else:break\n'
                '  r=dict(addr=hex(ea),str_key=str_key,raw32=raw[:32],raw=raw,dwords=dwords[:64],dword_str=dc)\n'
                '  ptr=idc.get_qword(ea)\n'
                '  if 0x1000<ptr<0x7FFFFFFFFFFF:\n'
                '    r["ptr"]=hex(ptr)\n'
                '    r["ptr_data"]=[ida_bytes.get_byte(ptr+i) for i in range(256)]\n'
                '  print(json.dumps(r))\n'
                'else:\n'
                '  print("{}")\n'
            )
            raw_out = await ida.py_eval(code)
            for ln in raw_out.splitlines():
                if ln.strip().startswith("{"):
                    try: info["globals"][g] = json.loads(ln.strip())
                    except: pass
                    break

            v = info["globals"].get(g, {})
            if v.get("dword_str"):
                log.info(f"  {g} @ {v.get('addr','?')}: dword_str=\"{v['dword_str']}\"")
            elif v.get("str_key"):
                log.info(f"  {g} @ {v.get('addr','?')}: str_key({len(v['str_key'])})={[hex(b) for b in v['str_key'][:8]]}")
            else:
                r32 = v.get("raw32", [])
                log.info(f"  {g} @ {v.get('addr','?')}: raw32={[hex(b) for b in r32[:8]]}...")
            if v.get("ptr"):
                log.info(f"  {g}: ptr={v['ptr']}")
    else:
        info["globals"] = {}

    log.info("[Phase 1] Done.")

    # 서버 접속 문제 감지: fopen("flag")/fgets+strcmp 패턴 or 플래그가 바이너리에 없음
    main_code = info.get("main_code", "")
    all_callee = "\n".join(info.get("callee_codes", {}).values())
    all_code_combined = main_code + "\n" + all_callee

    info["needs_server"] = False
    server_indicators = [
        'fopen("flag"', 'fopen("flag.txt"', 'open("flag"',
        'read(0,', 'fgets(', 'scanf(',  # 입력을 받아서
    ]
    flag_file_read = any(ind in all_code_combined for ind in ['fopen("flag"', 'fopen("flag.txt"'])
    has_comparison = any(ind in all_code_combined for ind in ['strcmp', 'memcmp', 'strncmp'])

    if flag_file_read and has_comparison:
        info["needs_server"] = True
        info["server_type"] = "flag_file_compare"
        log.info("[Phase 1] ** SERVER PROBLEM detected: reads flag file + compares with input **")

    return info


# ══════════════════════════════════════════════════
#  Phase 2: LLM 1회
# ══════════════════════════════════════════════════

PROMPT = """\
You are a CTF reverse engineering expert. Below is ALL info from a binary.
Write a Python solver that prints the flag.

RULES:
- Runs in IDA Python (py_eval via exec()). Can use idc/ida_bytes but prefer pure Python.
- **CRITICAL py_eval SCOPING BUG**: Functions defined at top-level CANNOT access other top-level
  variables/functions/lambdas. This is because exec() runs in a restricted scope.
  WORKAROUND: Do NOT define helper functions. Write ALL logic inline or use default argument binding:
  ```
  # BAD - will cause NameError:
  ror1 = lambda v,b: ((v>>b)|(v<<(8-b)))&0xFF
  def decrypt(block):
      x = ror1(block[0], 5)  # NameError: ror1 not defined
  
  # GOOD - inline everything:
  for j in range(8):
      rolled = ((cur << 5) | (cur >> 3)) & 0xFF  # inline ROL
  ```
- Global data JSON fields per variable:
  "addr": hex address, "str_key": null-terminated byte list (TRUNCATED at first 0x00 — may be shorter than actual data!),
  "raw32": first 32 raw bytes (ALWAYS present — use this for comparison targets),
  "raw": first 256 raw bytes, "dwords": DWORD array (first 64),
  "dword_str": decoded string if DWORDs are printable ASCII.
  Some have "ptr" and "ptr_data" entries with pointer dereference data.
- CRITICAL: str_key stops at the first 0x00 byte. If the code uses memcmp with a specific size (e.g., 0x19=25),
  use raw[:25] instead of str_key. Always check the memcmp/comparison size in the decompiled code.
- IMPORTANT: str_key can be empty if the data starts with 0x00. Always use raw32 or raw in that case.
- If a variable is a DWORD array (like _DWORD *&aC[4*i]), use "dword_str" or "dwords" field.
- DO NOT reverse/reorder any byte arrays. Use them EXACTLY as provided.
- Reverse ALL transforms in EXACT REVERSE ORDER from main().
- Byte math: (val + x) & 0xFF, (val - x) & 0xFF

SOLVING STRATEGIES (try in order):
1. **Direct comparison**: If check function just compares input to a global array, the flag IS that data (possibly as dword_str).
2. **Reverse from end**: For chained constraints like input[i]+input[i+1]==target[i]:
   The target array is the str_key field. Let N = len(str_key). Input has N+1 chars, last is null.
   EXACT CODE TO USE:
   ```
   N = len(target)  # e.g. if str_key has 23 elements, N=23
   flag = [0] * (N + 1)
   flag[N] = 0  # null terminator
   for i in range(N - 1, -1, -1):  # i goes from N-1 down to 0
       flag[i] = (target[i] - flag[i + 1]) & 0xFF
   print(''.join(chr(b) for b in flag if b != 0))
   ```
   WARNING: target has N elements (indices 0..N-1). Do NOT access target[N].
3. **S-box / lookup table**: If check does `sbox[input[i]] == target[i]`, build inverse:
   `input[i] = sbox.index(target[i])`. The sbox is usually 256 bytes (str_key len ~82-256).
   Target is a SEPARATE global array. Make sure you use the right one for each role.
4. **Block cipher / Feistel**: If input is processed in 8-byte blocks with rounds of ROR/sbox/add:
   Pattern: `v2 = ROR1(b[(j+1)&7] + sbox[key[j] ^ v2], N)` then `b[(j+1)&7] = v2`
   IMPORTANT: Get the comparison size from memcmp (e.g., memcmp(a1, target, 0x19) means 25 bytes).
   Use raw[:memcmp_size] for target data. num_blocks = memcmp_size // 8 (integer division, ignore remainder).
   EXACT DECRYPT CODE (inline, no helper functions):
   ```
   import ida_bytes
   cmp_size = 25  # from memcmp 3rd arg (0x19=25)
   target = [ida_bytes.get_byte(TARGET_ADDR + i) for i in range(cmp_size)]
   sbox = [ida_bytes.get_byte(SBOX_ADDR + i) for i in range(256)]
   key = [ord(c) for c in "KEY_STRING"]
   num_blocks = cmp_size // 8
   result = bytearray()
   for blk in range(num_blocks):
       b = bytearray(target[blk*8:(blk+1)*8])
       for rnd in range(num_rounds-1, -1, -1):
           for j in range(7, -1, -1):
               idx = (j+1) & 7
               cur = b[idx]
               v2_old = b[0] if j == 0 else b[j]  # CRITICAL: j==0 uses b[0], else b[j]
               rolled = ((cur << N) | (cur >> (8-N))) & 0xFF  # ROL to undo ROR
               old_val = (rolled - sbox[key[j] ^ v2_old]) & 0xFF
               b[idx] = old_val
       result.extend(b)
   print(result.rstrip(b'\\x00').decode(errors='ignore'))
   ```
   Where N = rotation amount (commonly 5). num_rounds = outer loop count (commonly 16).
5. **XOR/ADD/SUB chains**: Apply all transforms in reverse order starting from the comparison target bytes.
   XOR keys are null-terminated (use str_key). For multi-step chains, reverse each step.
6. **Constraint solving**: If constraints are independent per-character (e.g., i ^ input[i] + 2*i == target[i]),
   solve each character independently.
7. **Brute-force per character**: If reversing is complex, try all 0x20-0x7E values for each position.
8. **Server flag-file problem**: If the binary reads from "flag" or "flag.txt" and does a direct strcmp/memcmp
   with user input WITHOUT any transformation, the flag is only on the server. In this case:
   - If there's a key/password derived from transforms (like previous challenges), print that key.
   - If the comparison is just `strcmp(user_input, flag_from_file)` with NO transforms, print "SERVER_ONLY"
     because the flag cannot be extracted from the binary.

OUTPUT:
- print() ONLY the flag on the last line. No other output.
- ```python``` block only, no explanation.

## Binary
{binary}

## main()
```c
{main_code}
```

## Sub-functions
Some functions may show DISASSEMBLY instead of decompiled code (marked with "DISASSEMBLY (decompile failed)").
For assembly code, analyze the instructions to understand the function's logic:
- `memmove` + loop = likely a rotate/shift operation on a byte array
- `shift_right` = rotate array right (last byte moves to front)
- `shift_left` = rotate array left (first byte moves to end)
- XOR loop = XOR each byte with a key (cycling through key bytes)
{callees}

## Globals
```json
{globals}
```

## Strings
{strings}

## Imports
{imports}
"""

async def phase2(info: dict) -> str:
    ct = ""
    for n, c in info.get("callee_codes", {}).items():
        ct += f"\n### {n}\n```c\n{c}\n```\n"
    prompt = PROMPT.format(
        binary=json.dumps(info.get("binary", {}), indent=2),
        main_code=info.get("main_code", "N/A"),
        callees=ct or "N/A",
        globals=json.dumps(info.get("globals", {}), indent=2, ensure_ascii=False),
        strings=info.get("strings", "N/A"),
        imports=info.get("imports", "N/A"))

    log.info("[Phase 2] Calling LLM...")
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post("https://api.anthropic.com/v1/messages", headers={
            "Content-Type": "application/json", "x-api-key": API_KEY, "anthropic-version": "2023-06-01"},
            json={"model": MODEL, "max_tokens": 4096, "temperature": 0,
                  "messages": [{"role": "user", "content": prompt}]})
        data = r.json()
        if r.status_code != 200:
            log.error(f"LLM: {data.get('error',{}).get('message',data)}"); return ""
        raw = "\n".join(b["text"] for b in data.get("content",[]) if b.get("type")=="text")
    if "```python" in raw:
        s = raw.index("```python")+9; return raw[s:raw.index("```",s)].strip()
    if "```" in raw:
        s = raw.index("```")+3; return raw[s:raw.index("```",s)].strip()
    return raw.strip()


# ══════════════════════════════════════════════════
#  Phase 3: 실행 + 1회 재시도
# ══════════════════════════════════════════════════

# 에러 패턴 — 이런 결과는 플래그가 아님
_ERROR_PATTERNS = [
    "Error", "Traceback", "NameError", "TypeError", "IndexError", "ValueError",
    "KeyError", "AttributeError", "SyntaxError", "ImportError", "RuntimeError",
    "NOT_FOUND", "not found", "not defined", "no module", "Insufficient",
    "placeholder", "FLAG_NOT_FOUND", "unable to", "cannot determine", "cannot be determined",
    "cannot be found", "not enough", "failed to", "could not", "SERVER_ONLY",
]

def _extract_flag(result: str) -> str | None:
    """py_eval 결과에서 유효한 플래그를 추출. 에러/깨진 결과는 None 반환."""
    lines = [l.strip() for l in result.splitlines()
             if l.strip() and not l.startswith("[STDERR]")]
    if not lines:
        return None
    candidate = lines[-1]
    # printable ASCII 3자 이상
    if len(candidate) < 3 or not all(0x20 <= ord(c) <= 0x7e for c in candidate):
        log.warning(f"[validate] Non-printable: {repr(candidate[:50])}")
        return None
    # 에러 패턴 체크
    for pat in _ERROR_PATTERNS:
        if pat in candidate:
            log.warning(f"[validate] Error pattern '{pat}' in result: {candidate[:60]}")
            return None
    # 너무 긴 결과도 의심 (500자 이상)
    if len(candidate) > 500:
        log.warning(f"[validate] Too long ({len(candidate)} chars)")
        return None
    return candidate

async def phase3(ida: IDA, solver: str, phase2_prompt: str = "") -> str | None:
    log.info("[Phase 3] Running solver...")
    for ln in solver.splitlines()[:15]:
        log.info(f"  {ln}")
    if solver.count("\n") > 15:
        log.info(f"  ... ({solver.count(chr(10))-15} more)")

    result = await ida.py_eval(solver)
    log.info(f"[Phase 3] => {result}")

    flag = _extract_flag(result)
    if flag: return flag

    # 재시도 (에러든 깨진 결과든)
    log.warning("[Phase 3] Failed, retry with full context...")
    fix = (
        f"The solver produced wrong output.\n"
        f"Error/Output:\n```\n{result}\n```\n\n"
        f"Failed solver:\n```python\n{solver}\n```\n\n"
        f"REMINDER:\n"
        f"- Do NOT define helper functions (exec() scoping bug). Write ALL logic inline.\n"
        f"- For ROR1(x,5): ((x>>5)|(x<<3))&0xFF. For ROL1(x,5): ((x<<5)|(x>>3))&0xFF.\n"
        f"- The result must be printable ASCII.\n"
        f"- print() ONLY the flag. ```python``` block only.\n"
    )
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post("https://api.anthropic.com/v1/messages", headers={
            "Content-Type": "application/json", "x-api-key": API_KEY, "anthropic-version": "2023-06-01"},
            json={"model": MODEL, "max_tokens": 4096, "temperature": 0,
                  "messages": [{"role": "user", "content": fix}]})
        if r.status_code == 200:
            raw = "\n".join(b["text"] for b in r.json().get("content",[]) if b.get("type")=="text")
            if "```python" in raw:
                fixed = raw[raw.index("```python")+9:raw.index("```",raw.index("```python")+9)].strip()
                log.info("[Phase 3] Retry...")
                for ln in fixed.splitlines()[:10]:
                    log.info(f"  {ln}")
                result = await ida.py_eval(fixed)
                log.info(f"[Phase 3] => {result}")
                flag = _extract_flag(result)
                if flag: return flag
    return None


# ══════════════════════════════════════════════════
#  Phase 4: angr fallback (디컴파일 실패 시)
# ══════════════════════════════════════════════════

async def phase4_angr(ida: IDA, info: dict) -> str | None:
    """디컴파일 실패한 큰 함수가 있으면 angr로 시도"""
    failed = info.get("decompile_failed", [])
    if not failed:
        return None

    log.info(f"[Phase 4] angr fallback — {len(failed)} function(s) failed decompile")

    # 바이너리 경로 가져오기
    binary_path = info.get("binary", {}).get("file", "")
    if not binary_path:
        log.error("No binary path"); return None

    # main에서 success/fail 분기 주소 찾기 (puts("Good")/puts("Correct") 등)
    main_code = info.get("main_code", "")
    main_addr = info.get("main_addr", "0x0")

    # success/fail 문자열 xref로 주소 자동 탐지
    addrs_raw = await ida.py_eval(
        'import idc, idautils, json\n'
        'good = []\n'
        'bad = []\n'
        'for s in idautils.Strings():\n'
        '    txt = str(s).lower()\n'
        '    is_good = False\n'
        '    is_bad = False\n'
        '    if "incorrect" in txt or "wrong" in txt or "try again" in txt or "fail" in txt or "error" in txt:\n'
        '        is_bad = True\n'
        '    elif "correct" in txt or "good job" in txt or "congrat" in txt or "here is your flag" in txt or "success" in txt:\n'
        '        is_good = True\n'
        '    if is_good or is_bad:\n'
        '        for xref in idautils.XrefsTo(s.ea):\n'
        '            if is_good: good.append(hex(xref.frm))\n'
        '            if is_bad: bad.append(hex(xref.frm))\n'
        'print(json.dumps({"good": good, "bad": bad}))\n'
    )
    branch_addrs = None
    for ln in addrs_raw.splitlines():
        if ln.strip().startswith("{"):
            branch_addrs = json.loads(ln.strip()); break

    if not branch_addrs or not branch_addrs.get("good"):
        log.error("Cannot find success/fail branch addresses for angr")
        return None

    good_addrs = branch_addrs["good"]
    bad_addrs = branch_addrs["bad"]
    log.info(f"  Good: {good_addrs}, Bad: {bad_addrs}")

    # 입력 크기 추측 (main 코드에서 scanf format 또는 strlen 비교)
    input_size = 16  # default
    m = re.search(r'strlen.*?!=\s*(\d+)', main_code)
    if m:
        input_size = int(m.group(1))
    m2 = re.search(r'%(\d+)s', main_code)
    if m2:
        input_size = int(m2.group(1))
    # fgets가 있으면 newline 포함
    uses_fgets = "fgets" in main_code
    log.info(f"  Input size: {input_size}, fgets={uses_fgets}")

    # angr 스크립트 생성
    if uses_fgets:
        stdin_setup = (
            f'flag = claripy.BVS("flag", 8 * {input_size})\n'
            f'nl = claripy.BVV(0x0a, 8)\n'
            f'inp = claripy.Concat(flag, nl)\n'
            f'state = proj.factory.entry_state(\n'
            f'    stdin=angr.SimFile("stdin", content=inp),\n'
            f'    add_options={{angr.options.LAZY_SOLVES}}\n'
            f')\n'
        )
    else:
        stdin_setup = (
            f'flag = claripy.BVS("flag", 8 * {input_size})\n'
            f'inp = claripy.Concat(flag, claripy.BVV(0x0a, 8))\n'
            f'state = proj.factory.entry_state(\n'
            f'    stdin=angr.SimFile("stdin", content=inp),\n'
            f'    add_options={{angr.options.LAZY_SOLVES}}\n'
            f')\n'
        )

    # good/bad 주소를 미리 계산
    good_offsets = [int(a, 16) for a in good_addrs]
    bad_offsets = [int(a, 16) for a in bad_addrs]

    angr_script = f'''import angr, claripy, sys
binary = r"{binary_path}"
proj = angr.Project(binary, auto_load_libs=False)
base = proj.loader.main_object.mapped_base

{stdin_setup}
for i in range({input_size}):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20)
    state.solver.add(b <= 0x7e)

simgr = proj.factory.simulation_manager(state)
good = [base + x for x in {good_offsets}]
bad = [base + x for x in {bad_offsets}]
print(f"Exploring... find={{[hex(a) for a in good]}}, avoid={{[hex(a) for a in bad]}}", flush=True)
simgr.explore(find=good, avoid=bad)
if simgr.found:
    result = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print(f"FLAG:{{result.decode()}}", flush=True)
else:
    print(f"NOT_FOUND active={{len(simgr.active)}} errored={{len(simgr.errored)}}", flush=True)
'''
    # 스크립트를 파일로 저장하고 subprocess로 실행
    script_path = Path("logs") / "angr_auto.py"
    Path("logs").mkdir(exist_ok=True)
    script_path.write_text(angr_script, encoding="utf-8")
    log.info(f"[Phase 4] Running angr subprocess... (may take minutes)")
    log.info(f"  Script: {script_path}")

    import subprocess
    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True, text=True, timeout=300  # 5분 타임아웃
        )
        log.info(f"[Phase 4] stdout: {proc.stdout.strip()}")
        if proc.stderr:
            # angr 경고는 무시, 에러만 로그
            for ln in proc.stderr.splitlines():
                if "error" in ln.lower() and "WARNING" not in ln:
                    log.warning(f"  stderr: {ln}")

        # FLAG:xxx 패턴 찾기
        for ln in proc.stdout.splitlines():
            if ln.startswith("FLAG:"):
                flag = ln[5:].strip()
                if len(flag) >= 3 and all(0x20 <= ord(c) <= 0x7e for c in flag):
                    return flag
        log.error("[Phase 4] angr did not find solution")
    except subprocess.TimeoutExpired:
        log.error("[Phase 4] angr timed out (5 min)")
    except FileNotFoundError:
        log.error("[Phase 4] Python not found for subprocess")

    return None


# ══════════════════════════════════════════════════
#  Phase 5: 동적 분석 (pwntools — 서버 접속 문제)
# ══════════════════════════════════════════════════

async def phase5_dynamic(ida: IDA, info: dict, solver_result: str,
                         host: str = "", port: int = 0) -> str | None:
    """
    Phase 3에서 얻은 key/password를 서버에 전송해서 플래그를 받아오는 Phase.
    
    동작 유형:
    1. solver_result가 key/password이고 서버가 있으면 → nc 접속해서 전송
    2. 서버 없으면 → 바이너리를 직접 실행해서 입력 전달
    """
    if not host and not port:
        log.warning("[Phase 5] No host:port provided. Use --host and --port args.")
        log.info("[Phase 5] Trying local binary execution instead...")

    main_code = info.get("main_code", "")
    binary_path = info.get("binary", {}).get("file", "")

    # LLM에게 pwntools 스크립트 생성 요청
    all_callee = "\n".join(f"### {n}\n```c\n{c}\n```" for n, c in info.get("callee_codes", {}).items())

    pwn_prompt = f"""You are a CTF expert. The binary reads a flag file from the server and compares user input against it.
A previous static analysis found that the correct input/key is: "{solver_result}"
But the actual flag is in the server's flag file, not in the binary.

Write a pwntools Python script that:
1. Connects to the server (host="{host}", port={port}) {'using remote()' if host else 'using process() on the local binary'}
2. Sends the key/password when prompted
3. Receives and prints the flag from the server response

Binary path: {binary_path}

## main()
```c
{main_code}
```

## Sub-functions
{all_callee}

RULES:
- Use pwntools (from pwn import *)
- {'remote(host, port)' if host else f'process("{binary_path}")'} to connect
- After sending the key, recv all remaining data and look for flag patterns (DH{{...}}, flag{{...}}, etc.)
- print() ONLY the flag on the last line
- ```python``` block only, no explanation
"""

    log.info("[Phase 5] Generating pwntools script...")
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post("https://api.anthropic.com/v1/messages", headers={
            "Content-Type": "application/json", "x-api-key": API_KEY, "anthropic-version": "2023-06-01"},
            json={"model": MODEL, "max_tokens": 4096, "temperature": 0,
                  "messages": [{"role": "user", "content": pwn_prompt}]})
        data = r.json()
        if r.status_code != 200:
            log.error(f"LLM: {data.get('error',{}).get('message',data)}"); return None
        raw = "\n".join(b["text"] for b in data.get("content",[]) if b.get("type")=="text")

    if "```python" in raw:
        pwn_script = raw[raw.index("```python")+9:raw.index("```",raw.index("```python")+9)].strip()
    elif "```" in raw:
        pwn_script = raw[raw.index("```")+3:raw.index("```",raw.index("```")+3)].strip()
    else:
        pwn_script = raw.strip()

    # 스크립트를 파일로 저장하고 subprocess로 실행
    import subprocess
    name = info.get("binary",{}).get("name","unknown")
    script_path = Path("logs") / f"{name}_pwn.py"
    Path("logs").mkdir(exist_ok=True)
    script_path.write_text(pwn_script, encoding="utf-8")
    log.info(f"[Phase 5] Running pwntools script: {script_path}")
    for ln in pwn_script.splitlines()[:10]:
        log.info(f"  {ln}")

    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True, text=True, timeout=30
        )
        output = proc.stdout.strip()
        log.info(f"[Phase 5] stdout: {output}")
        if proc.stderr:
            for ln in proc.stderr.splitlines():
                if "error" in ln.lower():
                    log.warning(f"  stderr: {ln}")

        # 플래그 패턴 찾기
        for ln in output.splitlines():
            ln = ln.strip()
            # DH{...} or flag{...} 패턴
            m = re.search(r'(DH\{[^}]+\}|flag\{[^}]+\}|FLAG\{[^}]+\})', ln)
            if m:
                return m.group(1)
        # 마지막 줄이 printable이면 플래그일 수 있음
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        if lines:
            candidate = lines[-1]
            if len(candidate) >= 3 and all(0x20 <= ord(c) <= 0x7e for c in candidate):
                return candidate
    except subprocess.TimeoutExpired:
        log.error("[Phase 5] pwntools script timed out")
    except FileNotFoundError:
        log.error("[Phase 5] Python or pwntools not found")

    return None


# ══════════════════════════════════════════════════

async def solve():
    if not API_KEY: print("Set ANTHROPIC_API_KEY in .env"); sys.exit(1)

    # CLI 인자 파싱
    import argparse
    parser = argparse.ArgumentParser(description="CTF Reversing Agent")
    parser.add_argument("--host", default="", help="Remote host for nc connection")
    parser.add_argument("--port", type=int, default=0, help="Remote port for nc connection")
    parser.add_argument("--desc", default="", help="Challenge description")
    args = parser.parse_args()

    ida = IDA()

    log.info("=" * 50)
    log.info("PHASE 1: Collect (0 LLM calls)")
    log.info("=" * 50)
    info = await phase1(ida)
    if not info.get("main_code"): log.error("No data"); return
    if args.desc:
        info["description"] = args.desc

    # 디컴파일 실패 감지
    significant_failures = [f for f in info.get("decompile_failed", []) if f.get("size", 0) > 1000]
    needs_angr = bool(significant_failures)
    if needs_angr:
        log.info("=" * 50)
        log.info(f"Large function decompile failed: {[f['name'] for f in significant_failures]}")
        log.info("Trying LLM first, angr as fallback")
        log.info("=" * 50)

    # 서버 문제 감지
    needs_server = info.get("needs_server", False)
    if needs_server:
        if args.host and args.port:
            log.info(f"Server problem detected. Will connect to {args.host}:{args.port}")
        else:
            log.info("Server problem detected. Use --host HOST --port PORT for remote, or will try local.")

    log.info("=" * 50)
    log.info("PHASE 2: Solver (1 LLM call)")
    log.info("=" * 50)
    solver = await phase2(info)
    if not solver: log.error("No solver"); return

    log.info("=" * 50)
    log.info("PHASE 3: Execute")
    log.info("=" * 50)
    flag = await phase3(ida, solver)

    # Phase 3 결과가 key이고 서버 문제이면 → Phase 5
    if flag and needs_server:
        log.info("=" * 50)
        log.info(f"PHASE 5: Dynamic — sending key '{flag}' to server")
        log.info("=" * 50)
        server_flag = await phase5_dynamic(ida, info, flag, args.host, args.port)
        if server_flag:
            flag = server_flag

    # Phase 3 실패 + 서버 문제이면 → Phase 5 (key 없이 시도)
    if not flag and needs_server:
        log.info("=" * 50)
        log.info("PHASE 5: Dynamic — no key, trying direct connection")
        log.info("=" * 50)
        flag = await phase5_dynamic(ida, info, "", args.host, args.port)

    # Phase 3 실패 + 디컴파일 실패 → Phase 4 angr
    if not flag and needs_angr:
        log.info("=" * 50)
        log.info("PHASE 4: angr fallback")
        log.info("=" * 50)
        flag = await phase4_angr(ida, info)

    name = info.get("binary",{}).get("name","unknown")
    Path("logs").mkdir(exist_ok=True)
    Path(f"logs/{name}_solver.py").write_text(solver, encoding="utf-8")
    Path(f"logs/{name}_collected.json").write_text(
        json.dumps(info, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    # ── 결과 출력 ──────────────────────────────
    print(f"\n{'='*50}")
    if flag:
        print(f"  FLAG: {flag}")
    else:
        print("  FLAG: Not found")
    print(f"{'='*50}")

    # 항상 분석 보고서 출력
    print(f"\n[Analysis Report]")
    print(f"  Binary: {info.get('binary',{}).get('name','?')} ({info.get('binary',{}).get('bits','?')}bit)")
    print(f"  Functions: {info.get('binary',{}).get('func_count','?')}")
    print(f"  Main: {info.get('main_addr','?')}")

    # 주요 문자열
    strings_raw = info.get("strings", "")
    if strings_raw:
        try:
            strs = json.loads(strings_raw) if isinstance(strings_raw, str) else strings_raw
            if strs:
                print(f"  Key strings: {strs[:5]}")
        except: pass

    # 디컴파일된 함수 목록
    callees = list(info.get("callee_codes", {}).keys())
    if callees:
        print(f"  Analyzed functions: {callees}")

    # 디컴파일 실패 함수
    failed = info.get("decompile_failed", [])
    if failed:
        print(f"  Decompile failed: {[(f['name'], f['size']) for f in failed]}")

    # 글로벌 데이터 요약
    globs = info.get("globals", {})
    if globs:
        print(f"  Globals found: {list(globs.keys())}")
        for gname, gval in globs.items():
            if isinstance(gval, dict):
                if gval.get("dword_str"):
                    print(f"    {gname}: \"{gval['dword_str']}\"")
                elif gval.get("str_key"):
                    key_preview = bytes(gval["str_key"][:16])
                    print(f"    {gname}: {key_preview} (len={len(gval['str_key'])})")

    # 서버 문제 감지 결과
    if info.get("needs_server"):
        print(f"  ** Server problem: flag is read from file on server **")
        print(f"     Use --host HOST --port PORT to connect")

    # main 코드 핵심 (변환 함수 호출 순서)
    main_code = info.get("main_code", "")
    # 함수 호출 순서 추출
    calls = re.findall(r'(sub_[0-9a-fA-F]+|[a-zA-Z_]\w+)\s*\(', main_code)
    interesting_calls = [c for c in calls if c not in (
        'strlen', 'printf', 'puts', 'scanf', 'memset', 'memcmp', 'strcmp',
        'fopen', 'fclose', 'fgets', 'read', 'fputs', 'fflush', 'exit',
        'setvbuf', '__readfsqword', '__isoc99_scanf', '_printf_chk',
        '_isoc99_scanf')]
    if interesting_calls:
        print(f"  Transform chain: {' -> '.join(interesting_calls)}")

    # 비교 대상 데이터
    cmp_match = re.search(r'(?:memcmp|strcmp)\s*\([^,]+,\s*[&"]?([^,)"]+)', main_code)
    if cmp_match:
        print(f"  Comparison target: {cmp_match.group(1)}")
    str_match = re.search(r'"([^"]{4,})"', main_code)
    if str_match:
        print(f"  Embedded string: \"{str_match.group(1)}\"")

    print(f"\n  Full data: logs/{name}_collected.json")
    print(f"  Solver: logs/{name}_solver.py")

    if flag:
        Path(f"logs/{name}_flag.txt").write_text(flag, encoding="utf-8")
    log.info("Done.")

if __name__ == "__main__":
    asyncio.run(solve())
