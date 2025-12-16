from flask import Flask, render_template, request, jsonify
import os
from modules.url_analyzer.basic_analyzer import BasicURLAnalyzer

app = Flask(__name__)

# Initialize analyzer
analyzer = BasicURLAnalyzer()

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishGuard Pro - Simple Version</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 40px auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            input[type="text"] {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
            }
            button {
                background: #4CAF50;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
            }
            button:hover {
                background: #45a049;
            }
            .result {
                margin-top: 20px;
                padding: 15px;
                border-radius: 5px;
                display: none;
            }
            .clean { background: #d4edda; color: #155724; }
            .suspicious { background: #fff3cd; color: #856404; }
            .malicious { background: #f8d7da; color: #721c24; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ PhishGuard Pro</h1>
            <p>Enter a URL to check for phishing indicators:</p>
            
            <input type="text" id="urlInput" placeholder="https://example.com">
            <button onclick="analyzeURL()">Analyze URL</button>
            
            <div id="loading" style="display:none;">
                <p>⏳ Analyzing...</p>
            </div>
            
            <div id="result" class="result"></div>
        </div>
        
        <script>
            function analyzeURL() {
                const url = document.getElementById('urlInput').value;
                if (!url) {
                    alert('Please enter a URL');
                    return;
                }
                
                document.getElementById('loading').style.display = 'block';
                document.getElementById('result').style.display = 'none';
                
                fetch('/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('loading').style.display = 'none';
                    const resultDiv = document.getElementById('result');
                    
                    // Set color based on verdict
                    resultDiv.className = 'result ';
                    if (data.verdict.includes('HIGH RISK')) {
                        resultDiv.classList.add('malicious');
                    } else if (data.verdict.includes('Suspicious')) {
                        resultDiv.classList.add('suspicious');
                    } else {
                        resultDiv.classList.add('clean');
                    }
                    
                    // Build result HTML
                    let html = `<h3>Analysis Result: ${data.verdict}</h3>`;
                    html += `<p><strong>Risk Score:</strong> ${data.risk_score}/100</p>`;
                    html += `<p><strong>URL:</strong> ${data.url}</p>`;
                    
                    if (data.findings.length > 0) {
                        html += '<h4>Findings:</h4><ul>';
                        data.findings.forEach(finding => {
                            html += `<li>${finding}</li>`;
                        });
                        html += '</ul>';
                    }
                    
                    resultDiv.innerHTML = html;
                    resultDiv.style.display = 'block';
                })
                .catch(error => {
                    document.getElementById('loading').style.display = 'none';
                    alert('Error: ' + error);
                });
            }
        </script>
    </body>
    </html>
    '''

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        results = analyzer.analyze(url)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'PhishGuard Pro'})

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs('data/reports', exist_ok=True)
    
    print("🚀 Starting PhishGuard Pro...")
    print("🌐 Open your browser and go to: http://localhost:5000")
    print("📡 API Health Check: http://localhost:5000/api/health")
    print("🛑 Press Ctrl+C to stop\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

# Add this at the very end, before the if __name__ block:
def main():
    # Create data directory if it doesn't exist
    os.makedirs('data/reports', exist_ok=True)
    
    print("🚀 Starting PhishGuard Pro...")
    print("🌐 Open your browser and go to: http://localhost:5000")
    print("📡 API Health Check: http://localhost:5000/api/health")
    print("🛑 Press Ctrl+C to stop\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)

if __name__ == '__main__':
    main()
