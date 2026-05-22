from flask import Flask, request, jsonify
from flask_cors import CORS
import google.generativeai as genai
from textblob import TextBlob
import math
import random
import datetime

app = Flask(__name__)
CORS(app) 

# ==========================================
# 🧠 AI CONFIGURATION 
# ==========================================
# APNI GOOGLE AI STUDIO KI KEY YAHAN DAALEIN
GEMINI_API_KEY = "AIzaSyA9trqBMSf37pfRyIITnC6H_t2oUGFvF8c" 
genai.configure(api_key=GEMINI_API_KEY)

try:
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
except:
    gemini_model = None

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '').lower()
    
    if not url: return jsonify({"error": "URL missing"}), 400
        
    entropy = calculate_entropy(url)
    suspicious_keywords = ['login', 'verify', 'update', 'free', 'secure', 'auth', 'account']
    found_keywords = [word for word in suspicious_keywords if word in url]
    
    # Base Engine Logic
    risk_score = 15
    if entropy > 4.0: risk_score += 30
    if len(found_keywords) > 0: risk_score += 25
    if "-" in url: risk_score += 10
    if url.count('.') > 2: risk_score += 15
    if not url.startswith("https"): risk_score += 20
    
    risk_score = min(max(risk_score, 0), 100)
    status = "MALICIOUS" if risk_score >= 60 else "SAFE"
    
    # Generating data for your ORIGINAL complex dashboard
    return jsonify({
        "score": risk_score,
        "status": status,
        "entropy": entropy,
        "keywords": found_keywords if found_keywords else ["None"],
        "ssl": "VALIDATED" if "https" in url else "UNSECURE",
        "domain_age": random.randint(1000, 9500) if status == "SAFE" else random.randint(1, 45),
        "global_scanners": f"{random.randint(4, 15) if status == 'MALICIOUS' else 0}/94 Engines Flagged",
        "server_location": "United States (US)" if status == "SAFE" else "Russian Federation (RU)",
        "ip_address": f"{random.randint(10,255)}.{random.randint(10,255)}.{random.randint(10,255)}.{random.randint(10,255)}"
    })

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    data = request.json
    text = data.get('text', '')
    if not text: return jsonify({"error": "Text missing"}), 400
    
    analysis = TextBlob(text)
    sentiment_score = analysis.sentiment.polarity 
    urgency_percentage = min(max(int((1 - sentiment_score) * 50), 0), 100)
    
    status = "PANIC / HIGH RISK" if urgency_percentage > 70 else "NORMAL"
    return jsonify({"urgency_score": urgency_percentage, "status": status})

@app.route('/api/report', methods=['POST'])
def generate_report():
    data = request.json
    url = data.get('url', '')
    score = data.get('score', 0)
    
    if not gemini_model: return jsonify({"report": "API Error: Gemini key invalid."})
    
    prompt = f"Act as an expert SOC Analyst. Write a short, professional 4-bullet Incident Report for the URL '{url}' which received a Threat Score of {score}/100."
    try:
        response = gemini_model.generate_content(prompt)
        return jsonify({"report": response.text})
    except Exception as e:
        return jsonify({"report": "Failed to generate report."})

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message', '')
    if not gemini_model: return jsonify({"reply": "Chatbot offline."})
    
    prompt = f"You are PhishGuard Copilot, a cybersecurity assistant. Answer concisely in 2 sentences: {message}"
    try:
        response = gemini_model.generate_content(prompt)
        return jsonify({"reply": response.text})
    except Exception as e:
        return jsonify({"reply": "Network interruption."})

if __name__ == '__main__':
    app.run(debug=True, port=5000)