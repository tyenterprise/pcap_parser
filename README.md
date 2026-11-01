# parse_pcap

PCAP/PCAPNG 파일을 5-tuple Flow로 나누고, 패킷마다 L3/L4 Header를 파싱해서
(L4, L3) 조합별 CSV 4개를 만든다. TLS(TCP)와 QUIC(UDP)의 SNI가 Label이 되고,
CSV의 마지막 열(`label`)에 들어간다.

## 설치와 실행

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

.venv/bin/python main.py input.pcap -o out_dir --idle-timeout 120
.venv/bin/python main.py a.pcap b.pcapng captures_dir/ -o out_dir   # 여러 파일 / 디렉터리
.venv/bin/python -m pytest -q                                       # 테스트
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `-o, --out-dir` | `out` | CSV 출력 디렉터리 |
| `--idle-timeout` | 120 | 이 시간(초) 동안 패킷이 없으면 Flow를 끝내고, 다음 패킷부터 새 Flow로 본다 |
| `--buffer-rows` | 500000 | CSV별로 메모리에 쌓아 두는 행 수. 넘으면 임시 파일로 내보내 외부 정렬한다 |
| `--tmp-dir` | out-dir 내부 | 정렬용 임시 파일 위치 |
| `-q` | | 진행 로그와 요약 출력 끄기 |

디렉터리를 입력하면 `.pcap .pcapng .cap .dmp` 파일을 재귀적으로 찾는다.

## 구조

| 파일 | 역할 |
|---|---|
| `main.py` | CLI, 2-pass 파이프라인, Label 결정, 요약 출력 |
| `pcapio.py` | PCAP(dpkt) / PCAPNG(자체 구현) 리더 |
| `headers.py` | Link layer 제거, IPv4/IPv6/TCP/UDP 헤더 파싱 |
| `flow.py` | 양방향 5-tuple Flow 추적 (idle timeout, FIN/RST 후 SYN, fragment 연결) |
| `sni.py` | TLS ClientHello 재조립과 파싱, QUIC v1 Initial 복호화 |
| `writer.py` | CSV 스키마, (flow_id, packet_index) 순 외부 정렬 writer |

- **Pass 1**: Flow를 나누고 Flow별 SNI 이벤트 `(packet_index, sni)`를 모은다.
- **Pass 2**: 같은 Flow 할당을 다시 재생하면서 헤더를 파싱하고 CSV에 쓴다.

Flow 할당은 결정적이라서 두 pass의 결과가 같다. 두 pass의 Flow 수가 다르면 실행이 중단된다.

## CSV 컬럼

파일마다 컬럼은 `[source_file] + 메타 + L3 + L4 + label` 순서다.

| 그룹 | 컬럼 |
|---|---|
| (입력 파일이 2개 이상일 때만) | `source_file` |
| 메타 (공통) | `flow_id, packet_index_in_flow, direction, pcap_timestamp, src_ip, dst_ip, captured_length` |
| IPv4 | `ipv4_version, ipv4_ihl, ipv4_tos, ipv4_dscp, ipv4_ecn, ipv4_total_length, ipv4_id, ipv4_flags, ipv4_flag_df, ipv4_flag_mf, ipv4_fragment_offset, ipv4_ttl, ipv4_protocol, ipv4_checksum` |
| IPv6 | `ipv6_version, ipv6_traffic_class, ipv6_flow_label, ipv6_payload_length, ipv6_next_header, ipv6_hop_limit` |
| TCP | `tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack, tcp_data_offset, tcp_header_length, tcp_flags, tcp_flag_fin, tcp_flag_syn, tcp_flag_rst, tcp_flag_psh, tcp_flag_ack, tcp_flag_urg, tcp_flag_ece, tcp_flag_cwr, tcp_window, tcp_checksum, tcp_urgent_pointer, tcp_options, tcp_opt_mss, tcp_opt_wscale, tcp_opt_sack_permitted, tcp_opt_sack_blocks, tcp_opt_ts_val, tcp_opt_ts_ecr` |
| UDP | `udp_src_port, udp_dst_port, udp_length, udp_checksum` |
| Label | `label` (항상 마지막 열) |

| 파일 | 컬럼 수 (source_file 제외) |
|---|---|
| `tcp_ipv4.csv` | 7 + 14 + 25 + 1 = 47 |
| `tcp_ipv6.csv` | 7 + 6 + 25 + 1 = 39 |
| `udp_ipv4.csv` | 7 + 14 + 4 + 1 = 26 |
| `udp_ipv6.csv` | 7 + 6 + 4 + 1 = 18 |

값의 의미:
- `direction`: 0 = Flow의 첫 송신자(client) → 상대, 1 = 반대 방향
- `pcap_timestamp`: 캡처 시각. epoch 초 단위이고 소수점 6자리(μs)까지 기록한다.
- TCP Timestamp option 값은 `tcp_opt_ts_val`, `tcp_opt_ts_ecr`에 따로 들어간다.
- `ipv4_flags`: 3비트 원본 값(reserved, DF, MF).
- `ipv4_fragment_offset`: 8바이트 단위의 원본 값.
- `tcp_flags`: 헤더 13번째 바이트(CWR..FIN)의 원본 값.
- `tcp_data_offset`: 4비트 원본 값. `tcp_header_length`는 이 값을 바이트로 환산한 것이다.
- `tcp_options` 예: `MSS=1460;SACK_OK;TS=123:0;NOP;WS=7`
  - SACK 블록은 `SACK=l-r,l-r` 형식이다.
  - 모르는 option은 `OPT<kind>=<hex>` 형식이다 (예: MPTCP, TFO).
- option이 없으면 해당 `tcp_opt_*` 칸은 비어 있다. `tcp_opt_sack_permitted`는 option이 있을 때 1이고, 없으면 빈 칸이다.
- 패킷이 잘려서 없는 필드도 빈 칸이다.

> **학습 시 주의**: `flow_id, packet_index_in_flow, pcap_timestamp, src_ip, dst_ip, source_file`은
> 분석용 메타 정보다. Feature로 쓰면 정답 정보가 새어 들어갈 수 있다(Label leakage).

## 출력 예시

`examples/sample.pcap`은 테스트용으로 직접 만든 패킷이다. 각 CSV의 첫 3행은 다음과 같다.

```
# tcp_ipv4.csv (TLS ClientHello가 두 segment로 나뉜 Flow)
0,0,0,1700000000.000000,10.0.0.1,93.184.216.34,74,4,5,0,0,0,60,1,2,1,0,0,64,6,48879,50000,443,100,0,10,40,2,0,1,0,0,0,0,0,0,64240,4660,0,MSS=1460;SACK_OK;TS=123:0;NOP;WS=7,1460,7,1,,123,0,www.example.com
0,1,1,1700000000.010000,93.184.216.34,10.0.0.1,74,4,5,0,0,0,60,1,2,1,0,0,64,6,48879,443,50000,900,101,10,40,18,0,1,0,0,1,0,0,0,64240,4660,0,MSS=1460;SACK_OK;TS=123:0;NOP;WS=7,1460,7,1,,123,0,www.example.com
0,2,0,1700000000.020000,10.0.0.1,93.184.216.34,54,4,5,0,0,0,40,1,2,1,0,0,64,6,48879,50000,443,101,901,5,20,16,0,0,0,0,1,0,0,0,64240,4660,0,,,,,,,,www.example.com

# tcp_ipv6.csv (VLAN 2중 태그)
1,0,0,1700000000.030000,2001:db8::1,2001:db8::2,82,6,40,703710,20,6,64,40000,443,5,1,5,20,2,0,1,0,0,0,0,0,0,64240,4660,0,,,,,,,,v6.example
1,1,0,1700000000.040000,2001:db8::1,2001:db8::2,153,6,40,703710,91,6,64,40000,443,6,1,5,20,24,0,0,0,1,1,0,0,0,64240,4660,0,,,,,,,,v6.example
1,2,1,1700000000.050000,2001:db8::2,2001:db8::1,89,6,40,703710,27,6,64,443,40000,77,1,5,20,16,0,0,0,0,1,0,0,0,64240,4660,0,,,,,,,,v6.example

# udp_ipv4.csv (DNS → Unknown, 그다음은 fragment된 datagram)
3,0,0,1700000000.130000,10.0.0.1,8.8.8.8,54,4,5,0,0,0,40,1,2,1,0,0,64,17,48879,5353,53,20,43981,Unknown
3,1,1,1700000000.140000,8.8.8.8,10.0.0.1,54,4,5,0,0,0,40,1,2,1,0,0,64,17,48879,53,5353,20,43981,Unknown
6,0,0,1700000000.210000,10.0.0.1,10.0.0.9,58,4,5,0,0,0,44,77,1,0,1,0,64,17,48879,7000,9000,24,43981,Unknown

# udp_ipv6.csv (RFC 9001 QUIC Initial → example.com, 이후 같은 5-tuple에서 other.example로 전환)
4,0,0,1700000000.150000,2001:db8::1,2001:db8::2,1262,6,0,0,1208,17,64,51000,443,1208,43981,example.com
4,1,1,1700000000.160000,2001:db8::2,2001:db8::1,112,6,0,0,58,17,64,443,51000,58,43981,example.com
4,2,0,1700000000.170000,2001:db8::1,2001:db8::2,103,6,0,0,49,17,64,51000,443,49,43981,example.com
```

## 요구사항 해석 (모호하거나 충돌한 부분)

1. **SNI가 여러 개인 Flow**: 요구사항 문서 안에서 규칙이 서로 충돌했다.
   - "다른 SNI가 나올 때까지 기존 SNI" 규칙
   - "Flow의 모든 패킷에 같은 값" 규칙
   - 부록의 "여러 SNI는 Unknown" 규칙

   이 중 본문의 첫 번째 규칙을 따랐다.
   - 첫 SNI 이전의 패킷(3-way handshake 등)은 첫 SNI를 Label로 받는다.
   - SNI k가 나온 패킷부터 다음 SNI가 나오기 전까지는 SNI k를 Label로 받는다.
   - SNI가 하나뿐인 Flow는 모든 행의 Label이 같다.
   - 같은 SNI가 다시 나오면(HelloRetryRequest, QUIC Retry 등) Label이 바뀌지 않는다.
2. **"SNI를 담은 패킷"의 기준**:
   - TCP: ClientHello의 첫 바이트를 담은 segment
   - QUIC: CRYPTO offset 0을 담은 Initial 패킷
3. **client 판정**: 명세대로 Flow의 첫 송신자를 client(direction 0)로 둔다. 다만 캡처가 서버 패킷부터 시작할 수도 있으므로, SNI 탐색은 두 방향 모두에서 한다.
4. **헤더 파싱 방식**: dpkt의 프로토콜 클래스 대신 `struct`로 직접 파싱한다.
   - dpkt는 잘린 헤더를 만나면 예외를 던져서, 남아 있는 필드까지 잃게 된다.
   - raw flag와 IHL 같은 원본 값도 그대로 노출하지 않는다.
   - dpkt는 PCAP 파일 리더로 사용한다.
5. **PCAPNG 리더**: dpkt의 pcapng Reader는 첫 인터페이스의 link type과 timestamp 해상도를 모든 패킷에 적용한다. 그래서 다중 인터페이스 캡처를 올바르게 읽도록 `pcapio.py`에 리더를 따로 구현했다. 명세의 5개 모듈 외에 추가한 모듈이다.
6. **Fragment**:
   - IPv4와 IPv6 fragment 모두, 첫 fragment가 아닌 fragment를 첫 fragment의 Flow에 연결한다. 연결된 행의 L4 칸은 비어 있다.
   - 연결할 수 없는 fragment는 `fragment_unlinked`로 집계하고 건너뛴다.
7. **잘린 패킷**: L4 포트까지 읽을 수 없으면 Flow를 정할 수 없으므로 건너뛴다(`truncated_l3`, `truncated_l4`). 포트를 읽을 수 있으면 행을 남기고, 없는 필드는 빈 칸으로 둔다.
8. **`source_file` 컬럼**: 명세대로 입력 파일이 2개 이상일 때만 추가한다. 이때 `flow_id`는 모든 파일에 걸쳐 고유하다.

## 검증

- **pytest 36개**:
  - TLS ClientHello: 분할, 순서 뒤바뀜, 재전송, seq wraparound, 여러 record에 걸친 경우
  - RFC 9001 A.1 키 유도와 A.2 실제 Client Initial 패킷
  - 여러 패킷에 나뉘고 Chrome처럼 CRYPTO frame 순서가 섞인 QUIC ClientHello
  - Flow 정규화, idle timeout, FIN 후 SYN, fragment
  - 4개 CSV의 컬럼 순서와 label이 마지막 열인지
  - Raw IP, SLL2, 다중 인터페이스·다중 섹션 PCAPNG, 잘린 파일
- **Wireshark 공식 테스트 캡처**:
  - `quic-with-secrets.pcapng` → `cloudflare-quic.com`
  - `tls12-dsb.pcapng` → `example.com`, `example.net`
  - `tls13-rfc8446.pcap`, `tls-renegotiation.pcap` → ClientHello에 SNI 확장이 없어서 `Unknown`
- **성능**: 합성 캡처 250 MB(20만 패킷, 2000 Flow)를 약 7초(약 27k pps), 최대 메모리 158 MB로 처리했다.

## 알려진 한계

- **ECH**(Encrypted Client Hello)를 쓰면 진짜 SNI를 얻을 수 없다. 이때 Label은 바깥 SNI(예: `cloudflare-ech.com`)가 된다.
- **QUIC v2와 draft 버전**은 지원하지 않는다. 해당 Flow는 Unknown이 된다.
- **DTLS ClientHello**의 SNI는 추출하지 않는다.
- **IP 리터럴 SNI**: 일부 클라이언트는 SNI에 IP 주소를 넣는다(규격 위반). 이 값도 그대로 Label이 된다. 실제 캡처에서 `10.42.0.243` 같은 Label이 나온 사례가 있다.
- **TCP 재조립 한도**: Flow 방향당 64 KB, 64 segment까지만 버퍼링한다. SYN 없이 중간부터 캡처했는데 첫 데이터 segment가 순서가 바뀌어 도착하면 ClientHello를 놓친다.
- **QUIC 재조립 범위**: 원래 DCID로 보낸 첫 flight의 Initial 패킷만 재조립한다. 보통 ClientHello는 이 안에 모두 들어 있다.
- **Fragment 도착 순서**: 첫 fragment보다 먼저 도착한 후속 fragment는 건너뛴다(`fragment_unlinked`).
- **터널링**: GRE, VXLAN, MPLS, PPPoE, IP-in-IP는 벗기지 않는다.
  - VXLAN은 바깥 UDP Flow로 기록된다.
  - GRE와 IP-in-IP는 `non_tcp_udp`로 집계된다.
  - MPLS와 PPPoE는 `non_ip`로 집계된다.
- **타임스탬프 정밀도**: float으로 처리하므로 μs 단위까지 정확하다. ns 해상도 캡처의 μs 미만 값은 반올림된다.
- **PCAPNG Simple Packet Block**: 타임스탬프가 없으므로 0으로 기록된다.
- **처리 속도**: 순수 Python이라 약 27k pps다. 수 GB 캡처는 수 분이 걸린다. 메모리는 활성 Flow 수와 `--buffer-rows`에 비례한다.
