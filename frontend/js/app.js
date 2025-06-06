// 追蹤最後一次分析的時間戳記
let lastAnalysisTimestamp = null;

// 檢查新的分析結果並更新歷史記錄
async function checkNewResults() {
    try {
        // 獲取最新結果
        const response = await fetch('/api/latest-analysis');
        const data = await response.json();
        
        // 如果沒有結果，顯示等待訊息
        if (!data.results) {
            updateUI({
                timestamp: new Date(),
                results: {
                    is_attack: false,
                    need_test_command: false,
                    shell_script: "",
                    general_response: "等待第一次分析結果..."
                }
            });
            return;
        }

        // 檢查是否有新的結果
        const newTimestamp = new Date(data.timestamp).getTime();
        if (lastAnalysisTimestamp === null || newTimestamp > lastAnalysisTimestamp) {
            console.log('發現新的分析結果');
            lastAnalysisTimestamp = newTimestamp;
            updateUI(data);
            // 更新歷史記錄
            await updateHistory();
        }
    } catch (error) {
        console.error('檢查結果時發生錯誤:', error);
        updateUI({
            error: true,
            message: '無法連接到伺服器'
        });
    }
}

// 獲取並顯示歷史記錄
async function updateHistory() {
    try {
        const response = await fetch('/api/analysis-history?limit=10');
        const history = await response.json();
        
        const historyDiv = document.getElementById('analysis-history');
        if (!historyDiv) return;

        historyDiv.innerHTML = `
            <h2>歷史分析記錄</h2>
            <div class="history-container">
                ${history.map((record, index) => `
                    <div class="history-item ${record.is_attack ? 'attack-detected' : 'no-attack'}">
                        <div class="history-timestamp">
                            ${new Date(record.timestamp).toLocaleString()}
                        </div>
                        <div class="history-content">
                            <p><strong>是否檢測到攻擊:</strong> ${record.is_attack ? '是' : '否'}</p>
                            <p><strong>需要進一步測試:</strong> ${record.need_test_command ? '是' : '否'}</p>
                            ${record.shell_script ? `
                                <div class="shell-script">
                                    <strong>測試命令:</strong>
                                    <pre>${record.shell_script}</pre>
                                </div>
                            ` : ''}
                            <div class="response">
                                <strong>詳細說明:</strong>
                                <p>${record.general_response}</p>
                            </div>
                            <button onclick="showRawLogs(${index})" class="show-logs-btn">
                                顯示原始日誌
                            </button>
                            <div id="raw-logs-${index}" class="raw-logs" style="display: none;">
                                <pre>${record.raw_logs}</pre>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        console.error('獲取歷史記錄失敗:', error);
    }
}

// 顯示/隱藏原始日誌
function showRawLogs(index) {
    const logsDiv = document.getElementById(`raw-logs-${index}`);
    if (logsDiv) {
        const isVisible = logsDiv.style.display === 'block';
        logsDiv.style.display = isVisible ? 'none' : 'block';
    }
}

// 更新 UI 的函數
function updateUI(data) {
    const resultDiv = document.getElementById('analysis-result');
    if (!resultDiv) return;

    if (data.error) {
        resultDiv.innerHTML = `
            <div class="error-message">
                <h3>錯誤</h3>
                <p>${data.message}</p>
            </div>
        `;
        return;
    }

    const { timestamp, results } = data;
    const formattedTime = new Date(timestamp).toLocaleString();

    resultDiv.innerHTML = `
        <div class="analysis-container">
            <div class="timestamp">
                <strong>最後更新時間:</strong> ${formattedTime}
            </div>
            <div class="results ${results.is_attack ? 'attack-detected' : 'no-attack'}">
                <h3>分析結果</h3>
                <p><strong>是否檢測到攻擊:</strong> ${results.is_attack ? '是' : '否'}</p>
                <p><strong>需要進一步測試:</strong> ${results.need_test_command ? '是' : '否'}</p>
                ${results.shell_script ? `
                    <div class="shell-script">
                        <strong>測試命令:</strong>
                        <pre>${results.shell_script}</pre>
                    </div>
                ` : ''}
                <div class="response">
                    <strong>詳細說明:</strong>
                    <p>${results.general_response}</p>
                </div>
            </div>
        </div>
    `;
}

// 手動觸發分析
async function triggerAnalysis() {
    try {
        const response = await fetch('/api/trigger-analysis', {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.error) {
            console.error('手動觸發失敗:', data.message);
            return;
        }

        // 更新最後分析時間並更新UI
        lastAnalysisTimestamp = new Date(data.timestamp).getTime();
        updateUI(data);
        // 更新歷史記錄
        await updateHistory();
    } catch (error) {
        console.error('手動觸發請求失敗:', error);
    }
}

// 初始化函數
function initialize() {
    // 立即檢查一次結果並更新歷史記錄
    checkNewResults();
    updateHistory();

    // 每3秒檢查一次新結果
    setInterval(checkNewResults, 3000);

    // 添加手動觸發按鈕的事件監聽器
    const triggerButton = document.getElementById('trigger-analysis');
    if (triggerButton) {
        triggerButton.addEventListener('click', triggerAnalysis);
    }
}

// 當頁面載入完成時初始化
document.addEventListener('DOMContentLoaded', initialize); 