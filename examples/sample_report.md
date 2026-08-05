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

**FAIL 7 · MANUAL 1 · PASS 12** — 共 20 項
