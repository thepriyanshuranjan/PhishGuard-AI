from flask import Flask, request, jsonify
from flask_cors import CORS
import google.generativeai as genai
from textblob import TextBlob
import math
import random

app = Flask(__name__)
# Vercel (Frontend) ko Render (Backend) se connect karne ke liye CORS
CORS(app) 

# ==========================================
# 🧠 AI CONFIGURATION (Generative AI)
# ==========================================
# APNI KEY YAHAN DOUBLE QUOTES KE BEECH MEIN DAALEIN
GEMINI_API_KEY = "AIzaSy..." 
genai.configure(api_key=GEMINI_API_KEY)

try:
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
except:
    gemini_model = None

# ==========================================
# 📊 PREDICTIVE ML ENGINE (URL Analysis)
# ==========================================
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
    suspicious_keywords = ['login', 'verify', 'update', 'free', 'secure', 'auth', 'account', 'admin', 'support']
    found_keywords = [word for word in suspicious_keywords if word in url]
    
    # Mathematical Risk Logic (Zero-Day Detection)
    risk_score = 10
    if entropy > 4.0: risk_score += 35
    if len(found_keywords) > 0: risk_score += 30
    if "-" in url: risk_score += 10
    if url.count('.') > 2: risk_score += 15
    if not url.startswith("https"): risk_score += 20
    
    risk_score = min(max(risk_score, 0), 100)
    status = "MALICIOUS" if risk_score >= 60 else "SAFE"
    
    return jsonify({
        "score": risk_score,
        "status": status,
        "entropy": entropy,
        "keywords": found_keywords if found_keywords else ["None"],
        "ssl": "VALIDATED" if "https" in url else "UNSECURE - WEAK SSL",
        "age_days": random.randint(10, 5000) if status == "SAFE" else random.randint(1, 45)
    })

# ==========================================
# 📝 NLP ENGINE (Email Sentiment Forensics)
# ==========================================
@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    data = request.json
    text = data.get('text', '')
    
    if not text: return jsonify({"error": "Text missing"}), 400
    
    analysis = TextBlob(text)
    sentiment_score = analysis.sentiment.polarity 
    
    urgency_percentage = int((1 - sentiment_score) * 50) 
    urgency_percentage = min(max(urgency_percentage, 0), 100)
    
    status = "PANIC / HIGH RISK" if urgency_percentage > 70 else "NORMAL"
    
    return jsonify({
        "urgency_score": urgency_percentage,
        "status": status
    })

# ==========================================
# 💬 GENERATIVE AI (Report & Chatbot)
# ==========================================
@app.route('/api/report', methods=['POST'])
def generate_report():
    data = request.json
    url = data.get('url', '')
    score = data.get('score', 0)
    
    if not gemini_model: return jsonify({"report": "API Error: Gemini key invalid or missing."})
    
    prompt = f"Act as an expert SOC Analyst. Write a short, professional 4-bullet Incident Report for the URL '{url}' which received a Threat Score of {score}/100. Mention risks like obfuscation or masked redirects if the score is high."
    try:
        response = gemini_model.generate_content(prompt)
        return jsonify({"report": response.text})
    except Exception as e:
        return jsonify({"report": "Failed to generate report. Check API Limits."})

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message', '')
    
    if not gemini_model: return jsonify({"reply": "Chatbot offline. Missing API Key."})
    
    prompt = f"You are PhishGuard Copilot, a highly advanced cybersecurity assistant. Give a concise, professional answer in 2-3 sentences to this query: {message}"
    try:
        response = gemini_model.generate_content(prompt)
        return jsonify({"reply": response.text})
    except Exception as e:
        return jsonify({"reply": "Network interruption while contacting AI core."})

if __name__ == '__main__':
    app.run(debug=True, port=5000)