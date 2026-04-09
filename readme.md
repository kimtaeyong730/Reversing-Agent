# rev-agent

IDA Pro + Claude API를 활용한 CTF 리버싱 자동 풀이 에이전트.

바이너리를 IDA에 로드한 상태에서 `solve.py`를 실행하면, MCP(Model Context Protocol)를 통해 IDA의 디컴파일/디스어셈블리/글로벌 데이터를 자동 수집하고, Claude API로 solver 코드를 생성·실행하여 플래그를 도출합니다.

## 동작 방식

```
Phase 1 (LLM 0회)  →  IDA MCP로 바이너리 정보 수집
Phase 2 (LLM 1회)  →  수집 데이터 기반 solver 코드 생성
Phase 3 (LLM 0~1회) →  IDA py_eval로 solver 실행 + 실패 시 1회 재시도
Phase 4 (fallback)  →  디컴파일 실패 시 angr 심볼릭 실행
Phase 5 (dynamic)   →  서버 접속 문제일 경우 pwntools로 flag 수신
```

### Phase 1 — 정적 수집

`py_eval`을 통해 IDA Python을 직접 실행하여 다음을 수집합니다:

- 바이너리 메타데이터 (아키텍처, 비트, 함수 수, entry point)
- import 목록
- 플래그 관련 문자열 (`flag`, `correct`, `wrong`, `dh{` 등)
- `main()` 디컴파일 코드
- 2-depth callee 함수 디컴파일 (실패 시 디스어셈블리로 대체)
- 글로벌 데이터 (byte/dword/qword 배열, 포인터 역참조)

### Phase 2 — Solver 생성

수집된 전체 데이터를 단일 프롬프트로 Claude API에 전달합니다. 프롬프트에는 XOR chain, S-box, Feistel cipher, constraint solving 등 리버싱 패턴별 풀이 전략이 내장되어 있어, LLM 호출 1회만으로 solver를 생성합니다.

### Phase 3 — 실행 및 검증

생성된 solver를 IDA의 `py_eval`로 실행합니다. 결과가 유효한 printable ASCII인지 검증하고, 에러 발생 시 에러 컨텍스트를 포함하여 1회 재시도합니다.

### Phase 4 — angr Fallback

디컴파일이 실패한 대형 함수(1000+ bytes)가 있을 경우, success/fail 분기 주소를 자동 탐지하여 angr 심볼릭 실행 스크립트를 생성·실행합니다.

### Phase 5 — 서버 접속 (Dynamic)

바이너리가 `fopen("flag")` + `strcmp` 패턴(서버에서 flag 파일을 읽어 비교)일 경우, pwntools 스크립트를 자동 생성하여 원격 서버에 접속합니다.

## 요구 사항

- **IDA Pro** + [IDA MCP Server](https://github.com/mrexodia/ida-mcp-server) (SSE 모드, 기본 포트 `13337`)
- **Python 3.10+**
- **Anthropic API Key**

```bash
pip install httpx
# angr fallback 사용 시
pip install angr
# Phase 5 (서버 접속) 사용 시
pip install pwntools
```

## 설정

`.env` 파일을 프로젝트 루트에 생성:

```env
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
CLAUDE_MODEL=claude-sonnet-4-6

IDA_MCP_BASE_URL=http://127.0.0.1:13337
IDA_MCP_TIMEOUT=60
```

## 사용법

1. IDA Pro에서 대상 바이너리를 열고 분석 완료 대기
2. IDA MCP Server 플러그인 활성화 (SSE 모드)
3. 실행:

```bash
# 기본 실행
python solve.py

# 서버 접속 문제
python solve.py --host host.dreamhack.games --port 12345

# 문제 설명 전달
python solve.py --desc "Find the hidden flag in the binary"
```

## 출력

```
logs/
├── {binary_name}_collected.json   # Phase 1 수집 데이터 전체
├── {binary_name}_solver.py        # Phase 2 생성 solver
├── {binary_name}_flag.txt         # 도출된 플래그
├── {binary_name}_pwn.py           # Phase 5 pwntools 스크립트 (해당 시)
└── angr_auto.py                   # Phase 4 angr 스크립트 (해당 시)
```

실행 종료 시 Analysis Report가 출력됩니다:

```
==================================================
  FLAG: DH{s0m3_fl4g_h3r3}
==================================================

[Analysis Report]
  Binary: challenge.exe (64bit)
  Functions: 42
  Main: 0x140001000
  Key strings: ["Correct!", "Wrong!"]
  Analyzed functions: [check@0x140001100, encrypt@0x140001200]
  Globals found: [byte_140003000, dword_140003100]
  Transform chain: encrypt -> check
  Comparison target: byte_140003000
```

## 풀이 가능한 패턴

| 패턴 | 설명 |
|------|------|
| Direct comparison | `strcmp(input, "flag")` — 글로벌 데이터에서 직접 추출 |
| XOR / ADD / SUB chain | 단일 또는 다단계 바이트 연산 역추적 |
| Chained constraints | `input[i] + input[i+1] == target[i]` — 역방향 풀이 |
| S-box lookup | `sbox[input[i]] == target[i]` — 역 테이블 구축 |
| Block cipher / Feistel | ROR/ROL + S-box + key mixing 라운드 역연산 |
| Brute-force per char | 복잡한 독립 제약 조건 — 문자별 전수 탐색 |
| Constructor chain | C++ 생성자 기반 초기화 파이프라인 |
| Shared stack counter | 스택 프레임 공유 카운터 패턴 |
| AES S-box cipher | 커스텀 AES S-box 기반 암호화 |

```

## 아키텍처 설계 원칙

- **LLM 호출 최소화**: 데이터 수집은 전부 `py_eval` (LLM 0회), solver 생성은 1회, 재시도 최대 1회 → 총 1~2회
- **py_eval-first**: MCP 응답 파싱 문제를 근본적으로 해결. `decompile`만 MCP 전용 도구 사용 (result.code 필드가 명확), 나머지는 전부 IDA Python 직접 실행
- **단일 파일**: 의존성 최소화, `solve.py` 하나로 동작

## License

MIT
