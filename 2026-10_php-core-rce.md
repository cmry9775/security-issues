# PHP 코어 원격코드실행 심층 분석 — CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")

> 작성일: 2026-10-27 · 자료 기준일: 2026-10-27
> 분류: 메모리 손상(Memory Corruption) → 인증 불필요 원격코드실행(RCE) + 메모리 정보 노출
> 심각도: CVSS v4.0 **9.2 (Critical)** · CISA KEV 등재(CVE-2026-109618, 2026-10-26)

---

## 1. 한눈에 보기

2026년 10월 21일, PHP 코어 런타임에서 **인증이 필요 없는 원격코드실행** 취약점 2건이 공개·패치됐다.
연구사 watchTowr·Wiz Research가 "PHP2Shell"로 명명했고, 공개 당일부터 허니팟에서 **실제 악용**이 관측됐다.
PHP는 전 세계 웹 서버의 큰 비중을 차지하며, 두 취약점 모두 **설정만으로는 완전 완화가 불가능**(코드 경로 자체의 결함)해 패치가 유일한 근본 대책이다.

| 항목 | 내용 |
| --- | --- |
| CVE | CVE-2026-109618, CVE-2026-109619 |
| GHSA | GHSA-w8hw-w9fx-j79w (…618), GHSA-6wmf-4rv5-p3rp (…619) |
| 유형 | 메모리 손상(불완전 초기화 / Use-After-Free) → RCE, 메모리 정보 노출 |
| 인증 필요 | 없음 (unauthenticated) |
| 공격 벡터 | 네트워크 / 요청 파싱 단계(스크립트 실행 이전) |
| CVSS | v4.0 9.2 (두 건 모두) |
| 영향 버전 | PHP 5.4 ~ 8.5.11 (구버전·PHP 5 포함, 사실상 현역 전 버전) |
| 패치 버전 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (2026-10-21) |
| 미패치(EOL) | PHP 8.1 이하 공식 릴리스 없음 → 배포판 백포트 또는 8.2+ 업그레이드 |
| 악용 현황 | 공개 당일부터 악용 관측, CVE-2026-109618 CISA KEV 등재 |
| 발견 | PHP + Wiz Research 공동(발견 과정에 AI 모델 활용 보고) |

---

## 2. 타임라인

| 날짜(2026) | 내용 |
| --- | --- |
| 10-21 | PHP·Wiz Research 공개, CVE 할당, PHP 보안 권고·패치 릴리스. 벤더 블로그 최초 게시 |
| 10-21~ | watchTowr 허니팟에서 악용 관측 시작 |
| 10-22 | 주요 클라우드 보안 권고 개정(WAF·노출 점검 룰 추가) |
| 10-23 | 컨설팅/대응 가이드(모니터링·패치·복구) 보강 |
| 10-26 | CISA KEV 카탈로그에 CVE-2026-109618 등재 |

---

## 3. 기술 배경 — PHP 실행·메모리 모델

두 취약점을 이해하려면 PHP가 요청을 어떻게 처리하고 메모리를 관리하는지부터 알아야 한다.

### 3-1. 요청 단위 메모리 (Zend Memory Manager)
- PHP는 요청이 들어오면 **요청 전용 메모리 풀**을 잡고, 내부적으로 `emalloc()`/`efree()`(Zend MM)로 할당·해제한다.
- 요청이 끝나면 풀 전체를 정리(cleanup)한다. 즉 "요청 수명" 동안만 유효한 메모리가 많다.
- 핵심 전제: **요청 소유(request-owned) 데이터는 요청이 끝나면 사라져야 한다.** 이 전제가 깨지면 메모리 손상이 생긴다.

### 3-2. OOM 처리와 `_zend_bailout()` / `longjmp()`
- 요청 처리 중 `memory_limit`을 넘기거나 시스템 메모리가 부족하면(OOM), PHP는 정상 흐름을 멈추고
  `_zend_bailout()`(내부적으로 **`longjmp()`**)으로 **현재 요청을 즉시 중단**한다.
- `longjmp`은 스택을 건너뛰어 미리 설정된 지점으로 점프하기 때문에, **중간에 진행되던 초기화가 끝나지 않은 상태**로 남을 수 있다.
- 이 "per-request OOM longjmp 실패 경로"가 CVE-2026-109618의 무대다.
- 메모리 제한을 `ulimit -v`(`RLIMIT_AS`)로 걸면 `mmap()`이 `NULL`을 반환하며 취약한 OOM 경로가 더 쉽게 유발된다 → 그래서 **cgroup(`MemoryMax`)으로 제한**하도록 권고된다.

### 3-3. 워커 프로세스 재사용
- PHP-FPM, Apache(mod_php) 등은 **워커 프로세스를 여러 요청에 재사용**한다(long-lived).
- 따라서 요청 A가 남긴 오염된 상태가 정리되지 않으면 **같은 워커의 요청 B**가 그 영향을 받는다.
- CVE-2026-109619는 정확히 이 "요청 간 상태 공유"를 악용한다. 완화책으로 `pm.max_requests = 1`(요청 1건마다 워커 교체)이 제시된다.

### 3-4. 요청 파싱은 스크립트 실행보다 먼저 일어난다
- RFC 1867 `multipart/form-data` 파싱, 쿠키 처리 등은 **애플리케이션 PHP 코드가 실행되기 전**에 일어난다.
- 그래서 애플리케이션 레벨의 입력 검증으로는 막을 수 없고, **WAF/리버스 프록시**가 중요한 방어선이 된다.

---

## 4. 취약점 상세

### 4-1. CVE-2026-109618 — OOM 중 불완전 초기화로 인한 메모리 손상
- **메커니즘:** 요청 설정(request setup) 도중 메모리가 바닥나 `_zend_bailout()`으로 중단되면,
  내부 요청 구조체가 **부분적으로만 초기화**된 상태로 남는다. 이후 **정리(cleanup) 로직**이 이 구조체를
  "정상적으로 초기화됐다"고 신뢰하고 접근 → **유효하지 않은/미완성 포인터를 사용**해 메모리가 손상된다.
- **본질:** *오류 경로(error path)에서의 정리 결함*. 정상 경로만 검증하고, OOM 같은 예외 경로의 상태 일관성을 보장하지 못했다.
- **트리거:** 공격자가 대량 입력·중첩 구조로 **의도적으로 OOM을 유발**해 이 경로에 진입시킨다.

### 4-2. CVE-2026-109619 — 요청 간 stale global state (Use-After-Free)
- **메커니즘:** 요청 A가 소유한 객체가 해제된 뒤에도, **내부 전역 상태**가 그 해제된 메모리를 계속 가리키는
  **댕글링 포인터**로 남는다. 같은 워커가 처리하는 **요청 B**가 정상 초기화 이전에 이 잔여(stale) 상태를 참조 →
  해제된 메모리 사용(**Use-After-Free**)으로 정보 누출·제어 흐름 탈취가 가능하다.
- **본질:** *수명(lifetime) 불일치*. 전역 상태의 수명이 요청 메모리보다 길어서 생기는 전형적 UAF이며,
  워커 재사용 모델이 피해 범위를 "다음 요청"으로 넓힌다.

### 4-3. 메모리 정보 노출 경로 (RCE의 디딤돌)
RCE 체인은 보통 "메모리 레이아웃 파악(누출) → 정밀 조작"으로 진행된다. 다음이 누출·stale 포인터 생산자로 지목됐다.
- **과도하게 긴 `PHPSESSID` 쿠키**: 힙 일부가 `Set-Cookie` 응답으로 되돌아오는 **Heartbleed형 누출**(수백 KB 규모 언급).
- **`session.upload_progress`**, **`fatal_error_backtraces`**: 요청 소유 포인터를 남기는 stale pointer 생산자.
- `display_errors = Off`만으로는 차단되지 않는다(특수 에러 페이지·큰 쿠키 경로로 추출 가능).

---

## 5. 이론 심화 — 메모리 안전성 취약점 분류

이번 건은 "웹 취약점"이면서 동시에 "시스템/메모리 안전성 취약점"이다. 관련 개념을 정리한다.

- **Use-After-Free (UAF):** 해제된 메모리를 계속 참조. 공격자가 해제된 자리에 자신이 통제하는 데이터를
  채워 넣으면, 프로그램이 그것을 유효 객체로 오인해 **제어권 탈취**가 가능하다. (→ CVE-2026-109619)
- **불완전/미초기화 사용(uninitialized / partial use):** 초기화가 끝나지 않은 메모리를 유효하다고 신뢰.
  오류 경로(longjmp 등)에서 자주 발생. (→ CVE-2026-109618)
- **Out-Of-Bounds Read:** 할당 경계를 넘어 읽어 인접 힙 데이터(포인터 등)를 노출. 정보 누출의 전형.
- **`longjmp`/`setjmp`의 위험:** 스택 되감기 없이 점프하므로, 중간에 잡아둔 자원·반쯤 만든 구조가
  정합성을 잃기 쉽다. C 기반 런타임의 고질적 함정.
- **왜 설정으로 못 막나:** 특정 기능을 끄는 옵션의 문제가 아니라 **코드 경로 자체의 버그**다.
  일부 기능(`session.upload_progress` 등) 비활성화로 *공격 표면*은 줄일 수 있어도 **근본 제거는 패치뿐**이다.

---

## 6. 악용 정황 (관측된 기법 — 개념 수준)

> 아래는 방어·탐지를 위한 개념 설명이며, 재현/무기화 절차는 포함하지 않는다.

- **힙 증폭(heap grooming):** 중첩된 빈 파일명의 `$_FILES` 항목으로 힙 할당을 크게 부풀려(수백 배) OOM·레이아웃 조작을 쉽게 만드는 기법이 보고됐다.
- **워커 점유("PreforkParking"):** Apache `mpm_prefork` 워커풀을 다수의 keep-alive/느린 chunked multipart 요청으로 붙잡아, 같은 워커에서 여러 요청을 연쇄시키는 기법. CVE-2026-109619의 "요청 간" 조건을 만들기 위함.
- **무충돌(無-crash) RCE:** 충돌(SIGSEGV)이나 `error.log` 기록 없이 HTTP 200으로 명령 출력을 되돌리는 체인이 관측됐다 → 로그만 보면 놓치기 쉽다.
- **동향 포인트:** 이번 취약점은 발견·검증 과정에 **AI 모델이 활용**됐다고 보고됐다. 공격·방어 양쪽에서 AI 기반 취약점 발견이 빨라지는 흐름을 보여준다.

---

## 7. 대응 (방어)

### 7-1. 패치 + 재배포 (필수, 근본 대책)
- PHP를 **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 이상**으로 업데이트.
- **패키지 업데이트만으로는 부족**하다. 실행 중인 워커의 `libphp.so`/`php-fpm`이 교체되도록 **서비스 재시작·재배포** 필수.
  재시작 대상: `php8.x-fpm`, `apache2`/`httpd`, `frankenphp`, `lsws`.
- 패치 적용 확인:
```bash
apt-get changelog php-fpm | grep -E "CVE-2026-109618|CVE-2026-109619"
rpm -q --changelog php-fpm | grep -E "CVE-2026-109618|CVE-2026-109619"
```
- EOL(5.x, 7.2~7.4, 8.1)은 공식 패치가 없으므로 **배포판 보안 백포트** 또는 **8.2+ 업그레이드**.

### 7-2. 사전 완화 (임시, 전역 php.ini — 패치 전까지만)
> 요청 단위(.htaccess 등) 설정은 너무 일찍 로드돼 취약 경로를 켤 수 있으므로 **전역 php.ini**에 둔다.
```ini
; CVE-2026-109619 공격 표면 축소
session.upload_progress.enabled = 0
fatal_error_backtraces = 0            ; PHP < 8.5.12

; CVE-2026-109618 입력량 제한(OOM 유발 억제)
post_max_size = 8M
upload_max_filesize = 4M
max_input_nesting_level = 16
max_input_vars = 250
max_file_uploads = 10
max_multipart_body_parts = 100
; 업로드가 필요 없으면: file_uploads = Off

; 일반 하드닝
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
```
- FPM: `www.conf`에 `pm.max_requests = 1`(요청마다 워커 교체 → 요청 간 stale 상태 차단).
- 메모리 제한은 `ulimit -v`가 아니라 **cgroup `MemoryMax`**로.

### 7-3. 엣지 / WAF (보완 통제)
파싱이 스크립트보다 먼저 일어나므로 WAF가 유효하다. 권고된 규칙 예:
- 업로드 불필요 경로에서 `multipart/form-data` 차단: `(?i)^\s*multipart/form-data(?:[\s,;]|$)`
- `Transfer-Encoding: chunked` POST 거부, 본문 크기 상한(`client_max_body_size 8m;`)
- 과도 중첩 필드명 차단: `name\s*=\s*"?[^"\r\n]*(\[[^\]]*\]){8,}`
- `PHPSESSID` 형식 강제(그 외 차단): `^[A-Za-z0-9,-]{22,256}$`
- WAF는 보완책일 뿐, **패치가 근본 대책**임을 명확히.

### 7-4. OS / 컨테이너 격리 (피해 최소화)
- 비특권 계정으로 워커 실행, 문서 루트 **읽기 전용**(systemd `ProtectSystem=strict`, k8s `readOnlyRootFilesystem: true`), `NoNewPrivileges=yes`.
- PHP 서버의 **아웃바운드 인터넷 차단**, `sh`/`bash`/`curl`/`wget` 등 실행 제한·모니터링(웹쉘·리버스셸 억제).

### 7-5. 포렌식
- 침해 의심 호스트는 **재시작 전에 워커 메모리를 캡처**한다. 재시작하면 휘발성 힙 증거가 사라진다.

---

## 8. 탐지 지표 (Threat Hunting)

| 계층 | 탐지 신호 | 의미 |
| --- | --- | --- |
| 응답/WAF | `Set-Cookie: PHPSESSID=` 256바이트 초과(특히 `%` 포함) | 힙 메모리 누출(Heartbleed형) |
| 접근 로그 | `OPTIONS * HTTP/1.1` keep-alive 급증, 느린 chunked multipart POST | 워커 점유(PreforkParking) |
| 웹앱 | `/index.php/index.php/...`처럼 `.php/` 반복 404 | OOB 누출 시도 |
| 웹앱 | 동일 엔드포인트에 500/200 POST 빠른 교차 | 바이트 단위 메모리 누출 |
| EDR/auditd | `php-fpm`/`httpd`/`apache2`의 자식으로 `sh`·`bash`·`curl`·`wget`·`nc`·`python`·`chmod` | 명령 실행(RCE) |
| 호스트 | FPM 워커 재생성 급증, SIGSEGV(종료코드 139), 코어 덤프 | 실패한 힙 조작 |

---

## 9. 출처
- watchTowr — PHP CVE-2026-109618 FAQ (PHP2Shell): https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- CISA — Critical Vulnerabilities in PHP Require Immediate Patching (2026-10-21) 및 KEV 카탈로그
- Google Cloud — Responding to core PHP vulnerabilities CVE-2026-109618/109619: https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619
- PHP 보안 권고: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp
- Tenable — Microsoft October 2026 Patch Tuesday(동시기 패치 동향 참고)
