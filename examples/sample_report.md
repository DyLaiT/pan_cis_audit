# Palo Alto PAN-OS CIS Benchmark 稽核報告

> 來源：`sample_config.xml`（機敏值已遮罩）· 檢查項對照 CIS Palo Alto Firewall Benchmark

| 項次 | 檢查項 | Lv | 結果 | 說明 |
|---|---|:---:|:---:|---|
| 1.1.1.1 | Syslog logging 已設定 | 1 | ✅ PASS | system log 已設 syslog 轉送 |
| 1.1.2 | 登入警語 (Login Banner) | 1 | ✅ PASS | 已設定登入警語 |
| 1.1.3 | Log on High DP Load | 1 | ❌ FAIL | 未啟用 Log on High DP Load |
| 1.2.1 | 管理介面 Permitted IP | 1 | ✅ PASS | 管理介面已限制來源 IP |
| 1.2.3 | 管理介面停用 HTTP/Telnet | 1 | 🔍 MANUAL | 確認 deviceconfig/system/service 的 disable-http/disable-telnet=yes（見 pan_audit 2.1） |
| 1.2.5 | 管理介面有效憑證 | 2 | ❌ FAIL | 管理介面未設有效憑證 profile（用預設自簽） |
| 1.3.1 | 密碼複雜度已啟用 | 1 | ✅ PASS | = yes |
| 1.3.2 | 密碼最短長度 ≥12 | 1 | ✅ PASS | 12 ≥ 12 |
| 1.3.3 | 密碼最少大寫 ≥1 | 1 | ✅ PASS | 1 ≥ 1 |
| 1.3.4 | 密碼最少小寫 ≥1 | 1 | ✅ PASS | 1 ≥ 1 |
| 1.3.5 | 密碼最少數字 ≥1 | 1 | ✅ PASS | 1 ≥ 1 |
| 1.3.6 | 密碼最少特殊字元 ≥1 | 1 | ✅ PASS | 1 ≥ 1 |
| 1.3.7 | 密碼變更週期 ≤90 天 | 1 | ❌ FAIL | 未設定密碼變更週期 |
| 1.3.8 | 新密碼差異字元 ≥3 | 1 | ❌ FAIL | 未設定新密碼差異要求 |
| 1.3.9 | 密碼重用限制 ≥24 | 1 | ❌ FAIL | 未設定密碼重用限制 |
| 1.3.10 | Password Profiles 不存在 | 1 | ✅ PASS | 無 password-profile（不會繞過複雜度原則） |
| 1.4.1 | 管理閒置逾時 ≤10 分鐘 | 1 | ✅ PASS | 10 ≤ 10 |
| 1.4.2 | 帳號鎖定（失敗次數/鎖定時間） | 1 | ❌ FAIL | 未設定帳號鎖定（admin-lockout），無暴力破解防護 |
| 1.5.1 | SNMP 使用 V3 | 1 | ❌ FAIL | SNMP 未使用 v3（v1/v2c 為明文） |
| 1.6.2 | NTP 冗餘（primary + secondary） | 1 | ✅ PASS | 已設 secondary NTP（冗餘） |
| 2.4 | User-ID Include/Exclude Networks | 2 | 🔍 MANUAL | 官方標 Investigate：若啟用 User-ID，需人工確認有設 Include/Exclude Networks（避免掃描外部） |
| 2.5 | User-ID Agent 最小權限 | 2 | 🔍 MANUAL | 官方標 Investigate：User-ID service account 權限需人工檢視（不應有互動登入/遠端存取） |
| 3.1 | HA 對等節點已設定 | 2 | ❌ FAIL | 未設定 HA（單機無容錯；若為刻意單機部署可視為 N/A） |
| 3.2 | HA Link/Path Monitoring | 2 | ❌ FAIL | HA 未設 Link/Path Monitoring（故障偵測不足） |
| 4.1 | 防毒更新排程（每小時） | 1 | ❌ FAIL | 未設防毒更新排程（TWGCB-03-005-0030；病毒碼過期） |
| 4.2 | 應用程式與威脅更新排程 | 1 | ❌ FAIL | 未設應用程式與威脅更新排程（TWGCB-03-005-0031） |
| 5.3 | 所有安全政策啟用 WildFire 分析 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認每條 allow 政策綁 WildFire 分析設定檔（TWGCB-03-005-0026） |
| 5.7 | WildFire 更新排程 | 1 | ❌ FAIL | 未設 WildFire 更新排程（TWGCB-03-005-0027） |
| 6.1 | 防毒設定檔解碼器動作 block/reset | 1 | 🔍 MANUAL | 官方標 Investigate：需人工確認 AV profile 各 decoder 動作為 block/reset-both（TWGCB-03-005-0028） |
| 6.2 | 所有政策套用安全防毒設定檔 | 2 | 🔍 MANUAL | 官方標 Investigate：需人工確認每條相關政策綁安全 AV profile（TWGCB-03-005-0033） |
| 6.3 | 反間諜軟體設定檔阻擋 | 1 | 🔍 MANUAL | 官方標 Investigate：anti-spyware profile 特徵碼原則需人工檢視（TWGCB-03-005-0034） |
| 6.7 | 漏洞保護設定檔阻擋規則 | 1 | 🔍 MANUAL | 官方標 Investigate：vulnerability protection profile 阻擋 critical/high 需人工檢視（TWGCB-03-005-0037） |
| 6.11 | URL 過濾 HTTP 標頭記錄 | 2 | ❌ FAIL | URL 過濾未啟用 HTTP 標頭記錄（TWGCB-03-005-0041） |
| 6.16 | Zone Protection Profile 存在（SYN Flood） | 2 | ❌ FAIL | 未定義任何 Zone Protection Profile（TWGCB-03-005-0021~0023；無 DoS/偵查防護） |

**FAIL 14 · MANUAL 8 · PASS 12** — 共 34 項
