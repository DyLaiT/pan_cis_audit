# Palo Alto PAN-OS CIS Benchmark 稽核報告

> 來源：`sample_config.xml`（機敏值已遮罩）· 檢查項對照 CIS Palo Alto Firewall Benchmark

| 項次 | 檢查項 | Lv | 結果 | 說明 | 證據 |
|---|---|:---:|:---:|---|---|
| 1.1.1.1 | Syslog logging 已設定 | 1 | ✅ PASS | system log 已設 syslog 轉送 | L22 |
| 1.1.1.2 | SNMPv3 traps 已設定 | 1 | ❌ FAIL | 未設定 SNMPv3 traps（或用 v1/v2c 明文） | 補在 L21（<log-settings> 下） |
| 1.1.2 | 登入警語 (Login Banner) | 1 | ✅ PASS | 已設定登入警語 | L28 |
| 1.1.3 | Log on High DP Load | 1 | ❌ FAIL | 未啟用 Log on High DP Load | 補在 L35（<management> 下） |
| 1.2.1 | 管理介面 Permitted IP | 1 | ✅ PASS | 管理介面已限制來源 IP | L29 |
| 1.2.2 | 管理設定檔 Permitted IP | 1 | ❌ FAIL | 介面管理設定檔未設 Permitted IP | 補在 L25（<entry> 下） |
| 1.2.3 | 管理介面停用 HTTP/Telnet | 1 | 🔍 MANUAL | 確認 deviceconfig/system/service 的 disable-http/disable-telnet=yes（見 pan_audit 2.1） | — |
| 1.2.4 | 管理設定檔停用 HTTP/Telnet | 1 | 🔍 MANUAL | 需人工確認所有 interface-management-profile 的 http/telnet 未啟用 | — |
| 1.2.5 | 管理介面有效憑證 | 2 | ❌ FAIL | 管理介面未設有效憑證 profile（用預設自簽） | 補在 L20（<shared> 下） |
| 1.3.1 | 密碼複雜度已啟用 | 1 | ✅ PASS | = yes | L12 |
| 1.3.2 | 密碼最短長度 ≥12 | 1 | ✅ PASS | 12 ≥ 12 | L13 |
| 1.3.3 | 密碼最少大寫 ≥1 | 1 | ✅ PASS | 1 ≥ 1 | L14 |
| 1.3.4 | 密碼最少小寫 ≥1 | 1 | ✅ PASS | 1 ≥ 1 | L15 |
| 1.3.5 | 密碼最少數字 ≥1 | 1 | ✅ PASS | 1 ≥ 1 | L16 |
| 1.3.6 | 密碼最少特殊字元 ≥1 | 1 | ✅ PASS | 1 ≥ 1 | L17 |
| 1.3.7 | 密碼變更週期 ≤90 天 | 1 | ❌ FAIL | 未設定密碼變更週期 | 補在 L11（<password-complexity> 下） |
| 1.3.8 | 新密碼差異字元 ≥3 | 1 | ❌ FAIL | 未設定新密碼差異要求 | 補在 L11（<password-complexity> 下） |
| 1.3.9 | 密碼重用限制 ≥24 | 1 | ❌ FAIL | 未設定密碼重用限制 | 補在 L11（<password-complexity> 下） |
| 1.3.10 | Password Profiles 不存在 | 1 | ✅ PASS | 無 password-profile（不會繞過複雜度原則） | — |
| 1.4.1 | 管理閒置逾時 ≤10 分鐘 | 1 | ✅ PASS | 10 ≤ 10 | L35 |
| 1.4.2 | 帳號鎖定（失敗次數/鎖定時間） | 1 | ❌ FAIL | 未設定帳號鎖定（admin-lockout），無暴力破解防護 | 補在 L35（<management> 下） |
| 1.5.1 | SNMP 使用 V3 | 1 | ❌ FAIL | SNMP 未使用 v3（v1/v2c 為明文） | 補在 L27（<system> 下） |
| 1.6.1 | 驗證更新伺服器身分 | 1 | ❌ FAIL | 未設定驗證更新伺服器身分（TWGCB-03-005-0019） | 補在 L27（<system> 下） |
| 1.6.2 | NTP 冗餘（primary + secondary） | 1 | ✅ PASS | 已設 secondary NTP（冗餘） | L32 |
| 1.6.3 | 遠端存取 VPN 憑證有效 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 VPN 憑證有效非自簽過期 | — |
| 2.1 | IP 對應使用者名稱 | 2 | 🔍 MANUAL | 官方標 Investigate：User-ID 的 IP-user 對應需人工確認 | — |
| 2.2 | 停用 WMI probing | 2 | 🔍 MANUAL | 官方標 Investigate：確認 User-ID 未啟用 WMI probing（易被濫用） | — |
| 2.3 | User-ID 僅內部信任介面 | 2 | 🔍 MANUAL | 需人工確認 User-ID 只在內部信任 zone 啟用 | — |
| 2.4 | User-ID Include/Exclude Networks | 2 | 🔍 MANUAL | 官方標 Investigate：若啟用 User-ID，需人工確認有設 Include/Exclude Networks（避免掃描外部） | — |
| 2.5 | User-ID Agent 最小權限 | 2 | 🔍 MANUAL | 官方標 Investigate：User-ID service account 權限需人工檢視（不應有互動登入/遠端存取） | — |
| 2.6 | User-ID 服務帳號無互動登入 | 2 | 🔍 MANUAL | 官方標 Investigate：需查 AD 端 User-ID service account 權限（XML 無此資訊） | — |
| 2.7 | User-ID 帳號禁遠端存取 | 2 | 🔍 MANUAL | 官方標 Investigate：需查 User-ID service account 遠端存取權（AD 端） | — |
| 2.8 | 安全政策限制 User-ID Agent 流量 | 2 | 🔍 MANUAL | 需人工確認政策限制 User-ID Agent 不跨入不信任 zone | — |
| 3.1 | HA 對等節點已設定 | 2 | ❌ FAIL | 未設定 HA（單機無容錯；若為刻意單機部署可視為 N/A） | 補在 L26（<deviceconfig> 下） |
| 3.2 | HA Link/Path Monitoring | 2 | ❌ FAIL | HA 未設 Link/Path Monitoring（故障偵測不足） | 補在 L26（<deviceconfig> 下） |
| 3.3 | HA Passive Link State / Preemptive | 2 | 🔍 MANUAL | 需人工確認 HA passive-link-state=auto、preemptive 設定適當 | — |
| 4.1 | 防毒更新排程（每小時） | 1 | ❌ FAIL | 未設防毒更新排程（TWGCB-03-005-0030；病毒碼過期） | 補在 L27（<system> 下） |
| 4.2 | 應用程式與威脅更新排程 | 1 | ❌ FAIL | 未設應用程式與威脅更新排程（TWGCB-03-005-0031） | 補在 L27（<system> 下） |
| 5.1 | WildFire 檔案大小上限最大化 | 2 | 🔍 MANUAL | 官方標 Investigate：需比對 WildFire file-size 各類型是否設到建議上限 | — |
| 5.2 | WildFire 轉送所有應用/檔案類型 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 WildFire 分析設定檔涵蓋所有 app/file-type | — |
| 5.3 | 所有安全政策啟用 WildFire 分析 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認每條 allow 政策綁 WildFire 分析設定檔（TWGCB-03-005-0026） | — |
| 5.4 | 解密內容轉送 WildFire | 2 | ❌ FAIL | 未設定解密內容轉送 WildFire（需確認） | 補在 L35（<setting> 下） |
| 5.5 | WildFire session 資訊全啟用 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 WildFire session-information 各項啟用 | — |
| 5.6 | WildFire 惡意檔告警 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認惡意檔偵測告警已啟用 | — |
| 5.7 | WildFire 更新排程 | 1 | ❌ FAIL | 未設 WildFire 更新排程（TWGCB-03-005-0027） | 補在 L27（<system> 下） |
| 6.1 | 防毒設定檔解碼器動作 block/reset | 1 | 🔍 MANUAL | 官方標 Investigate：需人工確認 AV profile 各 decoder 動作為 block/reset-both（TWGCB-03-005-0028） | — |
| 6.2 | 所有政策套用安全防毒設定檔 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認每條相關政策綁安全 AV profile（TWGCB-03-005-0033） | — |
| 6.3 | 反間諜軟體設定檔阻擋 | 1 | 🔍 MANUAL | 官方標 Investigate：anti-spyware profile 特徵碼原則需人工檢視（TWGCB-03-005-0034） | — |
| 6.4 | 反間諜 DNS Sinkhole | 1 | 🔍 MANUAL | 需人工確認 anti-spyware profile 啟用 DNS sinkholing（TWGCB-03-005-0035） | — |
| 6.5 | 反間諜被動 DNS 監控 | 2 | 🔍 MANUAL | 需人工確認 anti-spyware profile 啟用 passive DNS | — |
| 6.6 | 對外政策套用反間諜設定檔 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認對網際網路政策綁安全 anti-spyware profile（TWGCB-03-005-0036） | — |
| 6.7 | 漏洞保護設定檔阻擋規則 | 1 | 🔍 MANUAL | 官方標 Investigate：vulnerability protection profile 阻擋 critical/high 需人工檢視（TWGCB-03-005-0037） | — |
| 6.8 | 所有政策套用漏洞保護設定檔 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認每條政策綁安全 vulnerability profile（TWGCB-03-005-0038） | — |
| 6.9 | 使用 PAN-DB URL Filtering | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 URL filtering 用 PAN-DB | — |
| 6.10 | URL 過濾 block/override 分類 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 URL 分類動作為 block/override | — |
| 6.11 | URL 過濾 HTTP 標頭記錄 | 2 | ❌ FAIL | URL 過濾未啟用 HTTP 標頭記錄（TWGCB-03-005-0041） | 補在 L25（<entry> 下） |
| 6.12 | URL 過濾內嵌分類 | 2 | ❌ FAIL | URL 過濾未啟用內嵌分類（TWGCB-03-005-0042） | 補在 L25（<entry> 下） |
| 6.13 | 對外政策啟用安全 URL 過濾 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認對網際網路政策綁 URL filtering（TWGCB-03-005-0043） | — |
| 6.14 | 信用卡/SSN 門檻告警 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 Data Filtering 信用卡/SSN 告警門檻 | — |
| 6.15 | 對外政策套用 Data Filtering | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認對網際網路政策綁 Data Filtering profile | — |
| 6.16 | Zone Protection Profile 存在（SYN Flood） | 2 | ❌ FAIL | 未定義任何 Zone Protection Profile（TWGCB-03-005-0021~0023；無 DoS/偵查防護） | 補在 L25（<entry> 下） |
| 6.17 | Zone Protection Flood 調校 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 zone protection 各 flood type 門檻已調校（TWGCB-03-005-0021） | — |
| 6.18 | Zone Protection 偵查保護 | 2 | 🔍 MANUAL | 需人工確認所有 zone 啟用 reconnaissance protection（TWGCB-03-005-0022） | — |
| 6.19 | Zone Protection 丟棄異常封包 | 2 | 🔍 MANUAL | 需人工確認所有 zone 啟用 packet-based attack protection（TWGCB-03-005-0023） | — |
| 6.20 | 使用者憑證提交 block/continue | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認 URL filtering 的 credential submission 動作 | — |
| 7.1 | 允許政策有 application 管制 | 2 | 🔍 MANUAL | 需人工/交叉 pan_audit：allow 政策應限定 application（非 any） | — |
| 7.2 | 政策 Service 非 ANY | 2 | 🔍 MANUAL | 官方標 Investigate：對外政策 service 不應為 any（TWGCB-03-005-0024；交叉 pan_audit 5.1） | — |
| 7.3 | 有拒絕惡意 IP 的政策 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認有 deny 已知惡意 IP 的政策 | — |
| 8.1 | SSL Forward Proxy 政策 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認對外流量有 SSL Forward Proxy 解密政策 | — |
| 8.2 | SSL Inbound Inspection | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認對內部伺服器有 SSL Inbound Inspection | — |
| 8.3 | 解密憑證有效 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認解密用憑證有效 | — |

**FAIL 19 · MANUAL 40 · PASS 12** — 共 71 項
