# 網路安全日誌分析工具 (Cyber Security Log Analyzer)

本專案提供一套完整的 Python 工具鏈，用於將多來源系統日誌正規化，並進行深度的安全威脅偵測與異常行為分析。
This project provides a comprehensive Python toolkit to normalize multi-source system logs and perform in-depth security threat detection and anomaly analysis.

## 核心功能 / Core Features

### 1. 自動化整合執行 (Integrated Runner) - `main.py`
一鍵完成所有分析流程，包含日誌正規化與資安威脅偵測。

### 2. 日誌正規化 (Log Normalization) - `normalize_logs.py`
將分散的原始日誌整合，產出以下策略檔案於 `result/`：
- **時間軸策略 (Timeline Strategy)**: 統合所有事件至單一時間線。
- **使用者行為策略 (User Activity Strategy)**: 以使用者為中心，彙整其數位足跡。

### 3. 資安威脅分析 (Security Threat Analysis) - `analyze_logs.py`
自動化偵測腳本，結果存放於 `result/`：
- **初始入侵偵測**: 電子郵件惡意附件篩選、暴力破解統計。
- **執行與持續性監控**: 異常程序執行、程序偽裝行為辨識。
- **流量與連線異常**: DNS 心跳信號偵測、資料外洩量化。
- **目標行為分析**: 敏感檔案存取監控。

## 目錄結構 / Directory Structure
- `RAW_DATA/`: 存放原始 CSV 日誌檔案。
- `result/`: 所有分析結果與報表 (已加入 `.gitignore`)。
- `main.py`: **整合執行進入點**。
- `analyze_logs.py`: 核心資安分析邏輯。
- `normalize_logs.py`: 日誌格式統一與摘要邏輯。
- `Analyze_Strategy.md`: 詳細的分析清單與實作進度。

## 環境需求 / Requirements
- Python 3.x
- pandas (`pip install pandas`)

## 使用方法 / Usage
1. 將原始 CSV 日誌檔案放入 `RAW_DATA/` 目錄中。
2. 執行全量分析：
   ```bash
   python main.py
   ```
3. 前往 `result/` 資料夾查看產出的 10 項分析報表。

## 驗證資訊 / Validation
- **總日誌處理量**: 108,000+ 筆
- **偵測範圍**: 涵蓋 Email, Auth, DNS, Endpoint, Firewall, Netflow, File, USB 等 8 類日誌。
- **分析產出**: 包含威脅清單、行為統計與流量摘要等 10 項報表。
