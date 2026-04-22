# Cyber Security Detailed Analysis Report (Analyze_Result.md)

## 1. 執行摘要 (Executive Summary)
本報告詳列了 8 類異質日誌中偵測到的潛在安全威脅。我們嚴格遵循 `Analyze_Strategy.md` 的分析框架，針對初始入侵、持續執行、網路異常與目標達成四大維度，為每個子項目提供了至少 5 個具備**完整數據流 (Data Flow)** 與**精確時間**的真實案例。

---

## 一、 偵測初始入侵行為 (Detecting Initial Access)

### 1. 電子郵件威脅分析 (Email Threat Analysis)
篩選主旨含 `urgent` 之郵件，追蹤惡意附件的散佈：
1. `2025-03-02 01:30:00` | From: `eve` | To: `eve` | Subject: `urgent` | File: `budget.xlsx`
2. `2025-03-01 11:20:00` | From: `kate` | To: `irene` | Subject: `urgent` | File: `budget.xlsx`
3. `2025-03-02 02:01:00` | From: `charlie` | To: `david` | Subject: `urgent` | File: `notes.txt`
4. `2025-03-02 03:36:00` | From: `kate` | To: `david` | Subject: `urgent` | File: `notes.txt`
5. `2025-03-02 10:25:00` | From: `mike` | To: `mike` | Subject: `urgent` | File: `agenda.docx`

### 2. 登入失敗與暴力破解 (Login Failures & Brute Force)
偵測到高頻率登入失敗紀錄，顯示密集的帳號測試行為：
1. `2025-03-02 14:46:00` | User: `leo` | Action: `failed_login` | IP: `10.0.0.14` | Host: `WS02`
2. `2025-03-02 15:57:00` | User: `eve` | Action: `failed_login` | IP: `10.0.0.17` | Host: `WS02`
3. `2025-03-02 05:54:00` | User: `bob` | Action: `failed_login` | IP: `10.0.0.12` | Host: `FIN01`
4. `2025-03-01 10:12:00` | User: `jack` | Action: `failed_login` | IP: `10.0.0.13` | Host: `ENG01`
5. `2025-03-03 09:45:00` | User: `david` | Action: `failed_login` | IP: `10.0.0.21` | Host: `HR01`

---

## 二、 偵測執行與持續性行為 (Detecting Execution & Persistence)

### 3. 異常程序執行 (Suspicious Process Execution)
識別主機端調用偵測，特別是 PowerShell 載入非典型負載：
1. `2025-03-01 08:09:00` | Host: `ENG01` | User: `eve` | Event: `powershell` | Detail: `excel.exe`
2. `2025-03-03 04:36:00` | Host: `WS01` | User: `alice` | Event: `powershell` | Detail: `chrome.exe`
3. `2025-03-02 04:11:00` | Host: `FIN01` | User: `bob` | Event: `powershell` | Detail: `powershell -enc ...`
4. `2025-03-02 03:05:00` | Host: `WS02` | User: `eve` | Event: `powershell` | Detail: `backup.bat`
5. `2025-03-01 21:15:00` | Host: `HR01` | User: `mike` | Event: `powershell` | Detail: `svchost.exe`

### 4. 程序行為比對 (Process Behavior Mapping - Masquerading)
偵測到程序名稱與執行詳細內容不匹配的偽裝技術：
1. `2025-03-01 08:09:00` | Host: `ENG01` | User: `eve` | Event: `powershell` | Detail: `excel.exe` | Expected: `powershell*`
2. `2025-03-02 00:01:00` | Host: `HR01` | User: `nancy` | Event: `cmd` | Detail: `chrome.exe` | Expected: `cmd*`
3. `2025-03-02 16:20:00` | Host: `ENG01` | User: `mike` | Event: `cmd` | Detail: `svchost.exe` | Expected: `cmd*`
4. `2025-03-03 04:36:00` | Host: `WS01` | User: `alice` | Event: `powershell` | Detail: `chrome.exe` | Expected: `powershell*`
5. `2025-03-02 20:39:00` | Host: `WS01` | User: `nancy` | Event: `cmd` | Detail: `excel.exe` | Expected: `cmd*`

---

## 三、 偵測連線與流量異常 (Detecting C2 & Traffic Anomalies)

### 5. DNS 查詢頻率分析 (DNS Query Beaconing)
識別具規律性的域名查詢，具備高度自動化指令控制 (C2) 徵候：
1. Host: `10.0.0.17` | Query: `github.com` | Count: 182 | Time: `2025-03-01 08:15` to `03-03 09:57`
2. Host: `10.0.0.17` | Query: `sync-storage-transfer.co` | Count: 176 | Time: `2025-03-01 08:43` to `03-03 10:00`
3. Host: `10.0.0.22` | Query: `google.com` | Count: 175 | Time: `2025-03-01 08:14` to `03-03 09:56`
4. Host: `10.0.0.19` | Query: `cloud-sync.net` | Count: 174 | Time: `2025-03-01 08:11` to `03-03 09:51`
5. Host: `10.0.0.19` | Query: `github.com` | Count: 174 | Time: `2025-03-01 08:29` to `03-03 09:56`

### 6. 異常外連流量 (Suspicious Outbound Traffic)
監控非典型連接埠與目標 IP 的巨量連線：
1. `2025-03-02 04:05:00` | Src: `10.0.0.20` | Dst: `188.166.10.4` | Port: 22 (SSH) | Bytes: 1.49 MB
2. `2025-03-02 23:38:00` | Src: `10.0.0.22` | Dst: `45.33.12.8` | Port: 445 (SMB) | Bytes: 1.49 MB
3. `2025-03-02 04:58:00` | Src: `10.0.1.50` | Dst: `142.250.74.14` | Port: 80 (HTTP) | Bytes: 1.49 MB
4. `2025-03-02 08:33:00` | Src: `10.0.1.40` | Dst: `103.25.56.10` | Port: 445 (SMB) | Bytes: 1.49 MB
5. `2025-03-02 06:11:00` | Src: `10.0.0.18` | Dst: `142.250.74.14` | Port: 3389 (RDP) | Bytes: 1.49 MB

---

## 四、 偵測目標達成行為 (Detecting Actions on Objectives)

### 7. 敏感檔案存取監控 (Sensitive File Access Monitoring)
依據下班時間與行為風險得分篩選之關鍵事件：
1. `2025-03-03 00:02:00` | User: `henry` | File: `backup.zip` | Action: `compress` | Risk: 100
2. `2025-03-02 05:33:00` | User: `irene` | File: `finance.xlsx` | Action: `modify` | Risk: 100
3. `2025-03-01 22:58:00` | User: `henry` | File: `hr_records.csv` | Action: `compress` | Risk: 100
4. `2025-03-03 01:35:00` | User: `eve` | File: `vpn_creds.txt` | Action: `delete` | Risk: 100
5. `2025-03-02 00:31:00` | User: `mike` | File: `vpn_creds.txt` | Action: `modify` | Risk: 100

### 8. 資料外洩量化 (Quantifying Data Exfiltration)
識別主機總外傳流量最高之來源 (Data Flow 核心)：
1. Src: `10.0.0.10` | Connections: 748 | Total Outbound: **590,507,518 Bytes** (~590 MB)
2. Src: `10.0.0.20` | Connections: 781 | Total Outbound: **571,396,070 Bytes** (~571 MB)
3. Src: `10.0.0.18` | Connections: 746 | Total Outbound: **564,949,446 Bytes** (~564 MB)
4. Src: `10.0.0.22` | Connections: 755 | Total Outbound: **560,490,994 Bytes** (~560 MB)
5. Src: `10.0.1.30` | Connections: 730 | Total Outbound: **559,759,896 Bytes** (~559 MB)

---

## 5. 總結
本分析報告透過對 8 個子項目的詳盡數據提取，確立了環境中存在的**多階段複合式威脅**。從早期的認證暴力破解與釣魚郵件，到中期的隱蔽 C2 通訊與行程偽裝，最後導向深夜的敏感檔案打包與大規模數據外傳。所有案例均具備精確的時間戳記與資料欄位支持，可用於進一步的事件響應。

*報告產出時間: 2026-04-22*
*產出工具: Cyber Security Log Analyzer (Enhanced Flow)*
