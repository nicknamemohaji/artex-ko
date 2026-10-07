# 아웃바운드 요청 기록 운영 가이드

이 구성은 세 종류의 기록을 분리한다.

- 채팅과 에이전트 대화는 기존 PostgreSQL 대화 테이블과 `data/transcripts`에 영구 저장되며, 대화 화면에서 조회한다.
- LLM 의미 단위 기록은 기존 **LLM 기록** 화면을 사용한다. 원문에는 프롬프트, 사고 내용, 도구 결과와 비밀값이 포함될 수 있으므로 기본값은 꺼짐이다.
- 새 **아웃바운드 로그** 화면은 별도 mitmproxy 컨테이너가 관찰한 LLM 및 원격 HTTP MCP의 네트워크 이벤트를 보여준다.

## 시작과 보존 정책

```sh
mkdir -p data/egress-proxy/logs
chmod 700 data/egress-proxy data/egress-proxy/logs
docker compose up -d --build
docker compose ps
```

프록시 이미지는 mitmproxy 11.0.2의 linux/amd64 manifest digest로 고정돼 있다. 다른 CPU 아키텍처에서 배포할 때는 같은 버전의 해당 플랫폼 digest를 검증해 교체해야 한다. 프록시는 CA 파일을 만든 뒤에만 healthy가 되고 ARTEX가 시작된다. ARTEX 시작 스크립트는 OS 신뢰 저장소와 이 CA를 임시 번들로 결합한다.

로그는 기본 50 MiB 파일 10개까지 순환한다. 환경변수로 조정할 수 있다.

- `ARTEX_EGRESS_BODY_LIMIT`: 이벤트당 기록할 본문 최대 바이트. 기본값 0으로 본문을 저장하지 않으며, 명시적으로 켤 때만 제한된 본문을 기록한다.
- `ARTEX_EGRESS_LOG_BYTES`: 파일 하나의 최대 크기, 기본 52,428,800
- `ARTEX_EGRESS_LOG_BACKUPS`: 보관할 순환 파일 수, 기본 10

Authorization, Proxy-Authorization, Cookie, Set-Cookie, API key 계열 헤더와 민감한 쿼리 필드는 저장 전에 마스킹한다. 본문 기록을 켜면 JSON·SSE JSON의 민감한 키, bearer 및 `sk-` 계열 토큰, PEM private key를 마스킹하고 바이너리 본문은 저장하지 않는다. 임의 형식 본문의 모든 비밀값을 완벽하게 식별할 수는 없으므로 로그 디렉터리와 대시보드는 관리자 데이터로 취급해야 한다.

SSE 응답은 원본 chunk를 그대로 반환하면서 제한된 복사본만 기록한다. 로그 기록 실패나 디스크 부족은 요청 전달을 중단하지 않는 fail-open 정책이다. 따라서 로그 누락 알림과 디스크 모니터링을 별도로 구성해야 한다.

## 캡처 범위와 강제 경계

Compose는 LLM 클라이언트를 `ARTEX_LLM_PROXY`, 원격 HTTP MCP 클라이언트를 `ARTEX_MCP_PROXY`로 명시 연결한다. Streamable HTTP의 POST SSE 응답과 legacy MCP의 장기 GET SSE가 같은 transport를 사용한다. 전역 `HTTP_PROXY`는 설정하지 않는다. 전역 프록시는 알림 URL의 SSRF 목적지 검사를 프록시 주소 검사로 바꿀 위험이 있기 때문이다.

다음 트래픽은 이 사이드카가 보장하지 않는다.

- SMTP, DNS, raw TCP/UDP 및 다른 비 HTTP 프로토콜
- 셸이 프록시 변수를 제거하거나 직접 소켓을 여는 경우
- 별도 프록시 설정을 가진 웹 검색, 사용자 정의 도구와 브라우저
- 업데이트, 알림과 자산 보강 등 명시적으로 배선하지 않은 Go 클라이언트
- 인증서 고정 또는 사용자 정의 신뢰 저장소 때문에 MITM을 거부하는 대상

따라서 이 기능만으로 “모든 아웃바운드”가 기록된다고 간주하면 안 된다. 이를 강제해야 하는 환경에서는 ARTEX 컨테이너의 직접 외부 egress를 방화벽/eBPF 정책으로 차단하고, 허용된 HTTP(S)는 프록시 컨테이너로만 나가게 구성해야 한다. PostgreSQL과 내부 DNS 등 필요한 내부 목적지는 별도로 허용한다. 차단 전 LLM/MCP의 정상·SSE·오류 응답, 알림 SSRF 거부, 업데이트와 작업 도구의 동작을 시험한다.

현재 Compose의 프록시는 요청 가용성을 우선해 fail-open 로깅을 사용하지만 네트워크 자체는 fail-closed다. 프록시가 내려가면 명시 연결된 LLM과 MCP 요청은 실패한다. 컨테이너 healthcheck와 restart 정책을 모니터링하고, 우회가 필요한 장애 대응에서는 `.env`의 `ARTEX_LLM_PROXY`와 `ARTEX_MCP_PROXY`를 명시적으로 변경한 뒤 감사 기록을 남긴다.
