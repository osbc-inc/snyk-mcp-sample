# Snyk MCP 스캐너 (Python)

이 도구는 [Snyk](https://snyk.io/) MCP(Model Context Protocol) 기반으로 SCA(소프트웨어 구성 분석) 및 코드 보안 스캔을 실행하는 간단한 Python 래퍼입니다.

## 기능
- `snyk mcp -t stdio --experimental --disable-trust`를 자동 실행
- SCA와 코드 스캔을 순차적으로 수행
- SCA 실패 시 코드 스캔만 실행
- Windows, macOS, Linux 지원
- JSON 형식의 원시 결과와 심각도 요약 출력

---

## 요구사항
- **Python** 3.8 이상
- **Snyk CLI** 설치 및 `PATH`에 등록  
  [Snyk CLI 설치 가이드](https://docs.snyk.io/snyk-cli/install-the-snyk-cli)

```bash
# Snyk 설치 확인
snyk --version
```

## Snyk 인증
```bash
snyk auth
```
이 명령은 기존 Snyk 인증 세션을 사용합니다.

## 사용 방법
```bash
python snyk-mcp.py <대상_경로>
```

예시:
```bash
python snyk-mcp.py ./my-project
```

## 출력 예시
- tools/list 호출 결과
- SCA 원시 JSON 응답
- CODE 원시 JSON 응답
- 심각도별 취약점 개수 요약

## 참고
- SCA 분석은 언어별 빌드 도구/환경이 필요할 수 있습니다. (예: Maven, npm 등)
- `SNYK_SEVERITY` 환경 변수를 통해 심각도 기준을 변경할 수 있습니다. (기본값: `low`)
