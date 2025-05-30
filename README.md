# AI-SOC (AI Security Operations Center)
HackMD 筆記：https://hackmd.io/DCzKj59jTO-wrVg7Nu6fEg?both

AI-SOC 是一個基於人工智慧，能夠自動分析網絡日誌和系統日誌，識別潛在的安全威脅，並提供即時的防護建議。
## 核心功能
1. 即時 log 收集與分析
2. LLM 輔助威脅評估
3. 自動化響應機制
5. 可視化監控界面

## 系統畫面

<img width="1332" alt="image" src="https://github.com/user-attachments/assets/6e34245f-ce0a-4993-b951-d01ef2ae8477" />
<img width="924" alt="image" src="https://github.com/user-attachments/assets/b2cdc043-6612-4ad1-92d1-333ae92e5d4d" />
<img width="924" alt="image" src="https://github.com/user-attachments/assets/b0234205-2c5d-41aa-9efa-da70803fb9f6" />
<img width="920" alt="image" src="https://github.com/user-attachments/assets/ff23d179-2097-491e-ba2e-7e05d1697b05" />

## 流程圖
![image](https://github.com/user-attachments/assets/945f589d-ce51-4fe0-aa26-76edea1a914c)
### Step
1. 用三個工具（SQLMaps,dalfox,gobuster）送攻擊 request 去打特定主機A，獲得 web access log。
    -  查看攻擊的 log：`sudo vim /var/log/nginx/access.log`
        >  我們設定好的 Nginx 除了 GET 以外，還可以在 log 看到 POST 的 request body
2. 用 Vector 蒐集 raw log，再 Parse 這些 log
    > 用 [Regex](https://tw.alphacamp.co/blog/regex)（正規表達式）把字串中的欄位切分出來，ex:IP、status code

5. 用寫好的靜態分析規則（白名單＋黑名單）判斷 log 是否為攻擊，若為攻擊則把該 parse 過的 log 標記起來，放到 Prometheus。
7. 也會把一般的未標記的 raw log 放到 Prometheus，讓後端去拿資料並判斷行為模式
    > Prometheus 可用 Promql 查詢 metrics
9. **把靜態分析後判定為攻擊的log** 和 **後端分析 raw log 後判定行為模式異常的 log** ，都**給 LLM 判斷是否為為真正的攻擊行為（想避免 False positive）**。
12. 於 Dashboard 顯示 LLM 的判斷結果

### 靜態分析
核心的邏輯是採用白名單（whitelist）+ 黑名單（blacklist）來過濾，因為：
- 在正常情境下，正常 request 數量遠大於惡意攻擊 request
- 過多 False Positive 會讓系統管理員忽略掉真正有用的異常資訊
- LLM（大語言模型）的任務無法完全平行執行，且計算資源有限，因此需要先做初步過濾以減少處理量

#### 過濾規則設計
- **白名單**
    - 設定安全的 IP 位址
    - 不同時間點對應不同安全範圍（可隨時更新）

- **黑名單**
    - HTTP status code 屬於 4xx（Client Error）或 5xx（Server Error）
    - 使用未授權的 Query String（例如不應存在於 URL 的參數）
    - 基於行為模式：
        - 在過去一段時間內，單一 IP 或 User-Agent 存取次數異常過多（例如暴力破解行為）
    - 可根據客戶環境動態調整策略，例如某些時間段封包量異常本為正常現象，需設置例外處理

### 工具說明
1. **Vector**
在我們的專案中，我們用 Vector 來收集 server 的 web access log，並對這些 log 進行即時轉換與處理(ex:parsing)，使它們符合 Prometheus 的格式。也會提供 API 讓 Prometheus 查詢指標資料（metrics），讓後續的監控系統能正確理解和呈現資料。


2. **Prometheus**
將 Vector 收集和處理後的指標資料（metrics）輸出到 Prometheus，由它負責**儲存和監控這些指標**。
當系統中發生異常（例如：request 異常增加），Prometheus 可以及時發出警告，讓我們及早應對，保護系統的穩定性與安全。
    > 目前專案用到的指標有：`nginx_nginx_requests_total` 和 `nginx_nginx_requests_total_no_filter`

3. **Backend Server**
   - Express.js 框架
   - RESTful API 設計


4. **LLM 分析**
   - 基於 OpenAI API 做 log 分析
   - 威脅評估

5. **資料庫**
   - MySQL 儲存
   - 歷史數據查詢


### 後端技術（backend/server.js）
1. **Node.js & Express.js**
   ```javascript
   import express from 'express';
   import cors from 'cors';
   const app = express();
   ```


2. **資料庫操作**
   ```javascript
   const pool = mysql.createPool({
       host: '198.19.249.55',
       user: 'aiioc',
       password: 'aiioc',
       database: 'aiioc',
       waitForConnections: true,
       connectionLimit: 10,
       queueLimit: 0
   });
   ```


3. **LLM 整合**
   ```javascript
   const openai = new OpenAI({
       baseURL: "https://openrouter.ai/api/v1",
       apiKey: "YOUR_API_KEY"
   });
   ```

3. 行為模式分析：request 限流功能 
    ```javascript
    async function checkRequestFrequency(ip) {
        const query = `sum(sum_over_time(nginx_nginx_requests_total_no_filter{ip="${ip}"}[40s]))`;
        const response = await fetchWithTimeout(`${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(query)}`);
        const data = await response.json();
        // 分析請求頻率
    }
    ```

### 監控技術
1. **Vector.yml 配置**
   ```yaml
   sources:
     nginx_logs:
       type: "file"
       include: ["/var/log/nginx/access.log"]
   
   transforms:
     parse_nginx:
       type: "remap"
       inputs: ["nginx_logs"]
   
   sinks:
     prometheus:
       type: "prometheus"
       inputs: ["parse_nginx"]
   ```
   - log 作靜態分析
   - 數據轉換（parse）
   - 指標輸出
   - sink部分添加了 prometheus_exporter sink
    配置了兩種指標：
    http_response_time_seconds：HTTP 響應時間的分布
    http_requests_total：HTTP 請求總數，按方法、狀態碼和端點分類

2. **Prometheus.yml 查詢**
   ```javascript
   const query = `sum(sum_over_time(nginx_nginx_requests_total_no_filter{ip="${ip}"}[40s]))`;
   ```
   - PromQL Query 查詢
   - 可依設定好的時間定期抓取 Vector 的指標。
    ```yaml=
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      - job_name: 'vector'
        static_configs:
          - targets: ['vector:9090']
    ```    
### 儲存持久性資料技術
#### docker-compose.yml

1. Vector 添加 9090 對映
- Vector 是用來收集和轉換日誌（log）的工具。
- 我們在 Vector 容器裡開放 9090 這個 port，因為這是 Vector 的 Prometheus exporter（將內部指標數據輸出給 Prometheus 抓取）所使用的 port。這樣 Prometheus 就能從這個 port 上來收集 Vector 提供的指標數據。

2. Prometheus 服務（用 9091 port）
- Prometheus 是一個監控系統和時序數據庫，會定期從 Vector 收集指標數據。

3. 設置 volumes 持久化 Prometheus 數據
- Prometheus 收集到的數據需要長期儲存，不能只存在記憶體中。
- 我們透過 docker-compose 中的 volumes 把 Prometheus 的數據儲存在主機上，這樣就算容器重啟，數據也不會消失。
    ```yaml=
    version: "3.8"
    services:
      vector:
        image: timberio/vector:0.46.1-debian
        container_name: vector
        restart: always
        volumes:
          - ./vector.yaml:/etc/vector/vector.yaml:ro
          - /var/log/nginx:/var/log/nginx:ro
        ports:
          - "8686:8686"
          - "9090:9090"
        command: ["vector", "--config", "/etc/vector/vector.yaml"]

      prometheus:
        image: prom/prometheus:latest
        container_name: prometheus
        restart: always
        volumes:
          - ./prometheus.yml:/etc/prometheus/prometheus.yml
          - prometheus_data:/prometheus
        ports:
          - "9091:9090"
        command:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus'
          - '--web.console.libraries=/usr/share/prometheus/console_libraries'
          - '--web.console.templates=/usr/share/prometheus/consoles'

    volumes:
      prometheus_data: {}
    ```


## 詳細流程

### 1. Log 收集流程
1. Nginx 產生 log
2. Vector 監控 log 文件變化
3. 解析 log 內容為結構化數據
4. 轉換為 Prometheus 指標
5. 推送到 Prometheus service

### 2. 分析流程
1. 定期檢查請求頻率
   ```javascript
   setInterval(async () => {
       console.log('Checking request frequencies...');
       const activeIPs = await getActiveIPs();
       // 檢查每個 IP 的請求頻率
   }, 20000);
   ```

2. AI 分析可疑行為
   ```javascript
   const analysis = await sendToOpenAI(requestData);
   ```

3. 結果儲存＆通知
   ```javascript
   await saveAnalysisResult(analysisResult, request.logEntry);
   ```

### 前置需求

- Node.js (v14 或更高版本)
- MySQL 數據庫
- Prometheus 服務器

#### 配置步驟
1. 把專案 clone 下來：`git clone https://github.com/Anna0131/AI-SOC.git`
2. 安裝需要的套件：`npm intstall`
4. 初始化資料庫（建 DB 、建使用者帳號並給權限）
    > 記得 **sudo vi /etc/mysql/mysql.conf.d/mysqld.cnf**， 把bind-address 改成0.0.0.0，資料庫才能給外面連

6. 啟動服務`npm start`
![image](https://hackmd.io/_uploads/ByAxcIrfge.png)



## API 

- `GET /api/latest-analysis`: 獲取最新的分析結果
- `GET /api/analysis-history`: 獲取歷史分析記錄
- `POST /api/trigger-analysis`: 手動觸發日誌分析
- 
### 項目結構
```
AI-SOC/
├── backend/
│   ├── server.js          # 主服務器文件
│   ├── package.json       # 後端依賴配置
│   └── .env              # 環境變數配置
├── frontend/
│   └── index.html        # 前端界面
└── README.md             
```
