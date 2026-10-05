# 오픈소스 활용 / 확장 정책 (Upstream-Friendly Extension Policy)

## 목표

오픈소스를 기반으로 쓰되, 부족한 부분을 추가하더라도 **upstream 업데이트를 계속 따라갈 수 있어야 한다.**
판단 기준은 하나다: *"upstream 새 릴리스를 받았을 때 수정 없이(또는 몇 분 안에) 빌드와 테스트가 통과하는가?"*

---

## 1. 확장 방식 우선순위 (위에서부터 시도, 아래로 내려갈수록 비용이 큼)

| 순위 | 방식 | upstream 업데이트 영향 |
|---|---|---|
| 1 | **설정/공개 API만으로 해결** | 없음 |
| 2 | **Adapter / Wrapper (우리 코드에서 감싸기)** | 공개 인터페이스가 바뀔 때만 Adapter 수정 |
| 3 | **플러그인 / 훅 / 확장 포인트 사용** (OpenVPN plugin, management interface 등) | 확장 API가 안정적인 한 거의 없음 |
| 4 | **별도 프로세스/모듈로 분리** (IPC, shared memory) | 프로토콜 계약만 유지 |
| 5 | **upstream에 기여(PR)** 후 릴리스를 받아서 사용 | 수정이 upstream에 흡수되므로 이상적 |
| 6 | **패치 파일 유지** (`patches/`) | 업데이트마다 재적용 비용 발생. **최후 수단** |
| 금지 | upstream 소스를 직접 수정/복사 후 수정 (**hard fork**) | 업데이트가 사실상 불가능해짐 |

규칙: **6번을 쓰려면 "왜 1~5번이 불가능한지"를 PR 설명에 적고 리뷰를 받는다.**

---

## 2. 저장소 구조 규칙

```text
third_party/   upstream 원본. 수정 금지.
               (git submodule 또는 git subtree, 반드시 태그/커밋 고정)
patches/       불가피한 패치만. 프로젝트별 디렉터리 + 번호 순서
               patches/<project>/0001-short-desc.patch
adapters/      upstream과의 경계 코드 (우리 소유). 예: adapters/openvpn-dco/
core/ blocks/ 우리 코드. upstream 헤더를 직접 include하지 않고 adapters를 거친다.
```

- `third_party/<project>/` 안의 파일은 **절대 직접 편집하지 않는다.** CI에서 변경 여부를 검사한다(고정된 커밋과 diff가 있으면 실패).
- upstream 타입/함수는 `adapters/`에서만 참조한다. 코어와 Block은 우리 인터페이스에만 의존한다 → upstream이 바뀌어도 Adapter 한 곳만 고치면 된다.

---

## 3. 패치가 불가피할 때의 규칙

1. 패치는 작게, 한 가지 목적만. `patches/<project>/NNNN-*.patch`
2. 각 패치 상단에 메타데이터를 둔다.
   - 무엇을/왜, 대상 upstream 버전, **upstream 기여 여부와 링크(없으면 사유)**
3. 가능하면 **upstream에 먼저 제안**한다. 수용되면 패치를 삭제한다.
4. 패치 수와 크기를 추적한다(패치 예산). 프로젝트당 패치가 늘어나면 설계를 재검토한다.
5. 패치를 적용한 상태의 테스트 + 패치 없는 상태의 테스트를 둘 다 유지해서, 패치가 어디에 영향을 주는지 분리한다.

---

## 4. 업데이트 절차 (정기)

1. `third_party/<project>` 를 새 태그로 올리는 별도 브랜치 생성
2. `patches/` 재적용 → 충돌 나는 패치만 갱신
3. 전체 테스트 실행 (unit / flow / **regression** / protocol)
4. 실패 시 원인을 분류: ① Adapter 수정으로 해결 ② 패치 갱신 ③ 계약 변경 → 설계 검토
5. 변경 요약을 `third_party/README.md`의 버전 표에 기록

권장 CI 잡:
- **pinned**: 고정된 upstream 버전으로 빌드/테스트 (항상 통과해야 함)
- **canary (nightly)**: upstream 최신 릴리스/브랜치로 빌드/테스트. 실패해도 머지는 막지 않지만 알림을 보낸다 → 업데이트 부담을 조기에 발견

---

## 5. 계약 테스트 (TDD와 연결)

upstream과의 경계에는 **계약 테스트(contract test)** 를 둔다.

- Adapter가 의존하는 upstream 동작(패킷 포맷, 옵션, 반환값)을 테스트로 고정한다.
- 업데이트 후 계약 테스트가 깨지면 "upstream의 어떤 동작이 바뀌었는지"를 바로 알 수 있다.
- 기존 OpenVPN 결과와의 비교는 `tests/regression/golden/`, 상호운용은 `tests/protocol/`에 둔다.

---

## 6. 대상별 방침

| 대상 | 방침 |
|---|---|
| **OpenVPN (user mode)** | 소스는 수정하지 않는다. management interface, plugin, 설정 옵션, DCO 경계(`adapters/openvpn-dco/`)로 연동. 필요한 변경은 upstream 제안 우선 |
| **OpenVPN DCO (Linux `ovpn`, ovpn-dco-win)** | 커널 모듈은 upstream 그대로. 우리 Flow Runtime은 별도 모듈/프로세스로 두고 Adapter로 연결 |
| **Crypto (OpenSSL/BoringSSL)** | 시스템/패키지 버전 사용. 우리 Provider 인터페이스(`crypto/provider`)로 감싸 교체 가능하게 |
| **Wintun / tap-windows6** | 서명된 배포 바이너리를 그대로 사용. PAL Device 구현에서만 호출 |
| **Rete.js / React Flow (Editor)** | npm 의존성으로 사용, 소스 수정 금지. 커스텀 노드/검증은 우리 코드에서 확장 API로 구현 |
| **테스트/보조 도구 (Wireshark dissector, Scapy)** | 외부 도구로 호출만 한다 |

---

## 7. 라이선스 주의

> 독립 구현 시 **clean-room 원칙**과 **iOS 배포 시 GPL 코드 제외**는 `docs/Threat_Model_and_Key_Management.md` §6에 정리했다.

- OpenVPN, Linux 커널 모듈 등은 **GPL 계열**이다. 우리 코드와 **같은 프로세스에 링크**하는지, **별도 프로세스/IPC로 분리**하는지에 따라 의무가 달라진다. 이 점도 "별도 프로세스 분리(4순위)"를 선호하는 이유다.
- 각 의존성의 라이선스를 `third_party/README.md`에 기록하고, **상용 배포 전 법무 검토**를 한다. (본 문서는 법률 자문이 아니다.)
- 라이선스와 버전 정보는 `docs/References_OpenSource_Papers.md`의 주의사항과 동일하게, 각 저장소의 LICENSE를 직접 확인한다.

---

## 8. 체크리스트 (PR 템플릿용)

- [ ] `third_party/` 내부 파일을 수정하지 않았다
- [ ] upstream 타입은 `adapters/`에서만 사용했다
- [ ] 패치를 추가했다면 1~5순위가 불가능한 이유와 upstream 제안 여부를 적었다
- [ ] 경계 동작에 계약 테스트를 추가했다
- [ ] 새 의존성의 라이선스를 `third_party/README.md`에 기록했다

---

## 9. MVP 범위 제한

**MVP 마일스톤에서는 오픈소스를 수정/패치해야 하는 작업을 포함하지 않는다.** (§1의 6순위·금지 항목은 MVP에서 사용하지 않는다.)

- MVP에서 허용: 수정 없는 라이브러리 링크, 외부 도구 실행, 공개 API/설정/확장 포인트 사용, 상호운용 상대로 실행
- MVP에서 제외 (Post-MVP): OpenVPN/DCO 소스 패치, DCO Adapter 통합, 커널 데이터 경로 변경
- MVP 작업 중 오픈소스 수정이 필요해 보이면 구현하지 말고 Post-MVP 목록에 추가하고, 가능한 우회(Adapter/분리 구현)를 먼저 검토한다.
