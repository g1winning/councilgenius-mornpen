#!/usr/bin/env python3
"""CouncilGenius Server — Mornington Peninsula Shire — V8 Production (Flask)"""
import os, json, re, csv, hashlib, time
from datetime import datetime, date
from flask import Flask, request, jsonify, send_file
from anthropic import Anthropic

app = Flask(__name__)

# ── Configuration ──────────────────────────────────────────
COUNCIL_NAME = "Mornington Peninsula Shire"
COUNCIL_DOMAIN = "www.mornpen.vic.gov.au"
COUNCIL_PHONE = "1300 850 600"
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
MODEL = os.environ.get('MODEL', 'claude-sonnet-4-6')
MAX_TOKENS = int(os.environ.get('MAX_TOKENS', '1024'))
PORT = int(os.environ.get('PORT', '5000'))
PROMPT_VERSION = "1.0"
SERVER_START_TIME = time.time()
TOTAL_QUERIES = 0

# ── Bin Day Configuration ──────────────────────────────────
BIN_LOOKUP_MODE = os.environ.get('BIN_LOOKUP_MODE', 'none')
# Values: 'api', 'geojson', 'calculation', 'static', 'none'

# ── Anthropic Client ───────────────────────────────────────
client = Anthropic(api_key=ANTHROPIC_API_KEY)

# ── Knowledge Base ─────────────────────────────────────────
KNOWLEDGE_FILE = "knowledge.txt"
KNOWLEDGE_BASE = ""
KNOWLEDGE_HASH = ""
KNOWLEDGE_LINES = 0
BIN_SCHEDULE = {}

def load_knowledge():
    global KNOWLEDGE_BASE, KNOWLEDGE_HASH, KNOWLEDGE_LINES, BIN_SCHEDULE
    if os.path.exists(KNOWLEDGE_FILE):
        with open(KNOWLEDGE_FILE, 'r') as f:
            KNOWLEDGE_BASE = f.read()
        KNOWLEDGE_HASH = hashlib.sha256(KNOWLEDGE_BASE.encode()).hexdigest()[:16]
        KNOWLEDGE_LINES = len(KNOWLEDGE_BASE.splitlines())
        if BIN_LOOKUP_MODE == 'static':
            BIN_SCHEDULE = parse_bin_schedule(KNOWLEDGE_BASE)
    print(f"[KNOWLEDGE] Loaded {len(KNOWLEDGE_BASE)} chars, {KNOWLEDGE_LINES} lines, hash: {KNOWLEDGE_HASH}")
    if BIN_SCHEDULE:
        print(f"[BIN] Loaded {len(BIN_SCHEDULE)} street entries")

load_knowledge()

# ── PII Filtering (V8 MANDATORY) ─────────────────────────
PII_PATTERNS = [
    (r'\b04\d{2}\s?\d{3}\s?\d{3}\b', '[REDACTED-PHONE]'),
    (r'\b\(0\d\)\s?\d{4}\s?\d{4}\b', '[REDACTED-PHONE]'),
    (r'\b13\s?\d{2}\s?\d{2}\b', '[REDACTED-PHONE]'),
    (r'\b[\w.-]+@[\w.-]+\.\w{2,}\b', '[REDACTED-EMAIL]'),
    (r'\b\d{1,5}\s+[A-Z][a-z]+\s+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Court|Ct|Place|Pl|Crescent|Cres|Lane|Ln|Way|Boulevard|Blvd|Terrace|Tce|Parade|Pde)\b', '[REDACTED-ADDRESS]'),
    (r'\b(?:my name is|I\'m|this is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b', '[REDACTED-NAME]'),
    (r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b', '[REDACTED-FINANCIAL]'),
    (r'\b\d{10,11}\b', '[REDACTED-ID]'),
]

def filter_pii(text):
    """Strip PII from text before logging."""
    for pattern, replacement in PII_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text

# ── Category Classification ───────────────────────────────
CATEGORIES = {
    'waste_bins': {
        'keywords': ['bin', 'collection', 'recycling', 'green waste', 'hard waste',
                     'rubbish', 'garbage', 'fogo', 'transfer station', 'tip', 'dump',
                     'landfill', 'waste', 'kerbside'],
    },
    'rates': {
        'keywords': ['rates', 'payment', 'concession', 'rebate', 'due date',
                     'valuation', 'rate notice', 'rate', 'assessment'],
    },
    'planning': {
        'keywords': ['planning', 'permit', 'development', 'application', 'zone',
                     'heritage', 'overlay', 'building', 'construction', 'shed',
                     'extension', 'subdivision', 'approved plan'],
    },
    'roads': {
        'keywords': ['pothole', 'road', 'maintenance', 'street', 'tree',
                     'street light', 'graffiti', 'footpath', 'pavement', 'verge'],
    },
    'parking': {
        'keywords': ['parking', 'fine', 'ticket', 'infringement', 'meter',
                     'on-street', 'permit', 'resident parking'],
    },
    'pets': {
        'keywords': ['pet', 'dog', 'cat', 'animal', 'registration', 'microchip',
                     'barking', 'off-lead', 'off lead', 'dangerous dog', 'animal control'],
    },
    'property': {
        'keywords': ['property', 'land', 'address', 'search', 'valuation',
                     'owner', 'title', 'lot'],
    },
    'family': {
        'keywords': ['kindergarten', 'kinder', 'childcare', 'maternal', 'immunisation',
                     'playgroup', 'family', 'children', 'early childhood'],
    },
    'community': {
        'keywords': ['library', 'pool', 'community', 'centre', 'program',
                     'recreation', 'swimming', 'sport', 'venue', 'hire', 'hall'],
    },
    'food_business': {
        'keywords': ['food', 'business', 'registration', 'supplier', 'tender',
                     'procurement', 'vendor', 'commercial kitchen'],
    },
    'contact': {
        'keywords': ['phone', 'email', 'address', 'hours', 'contact', 'office',
                     'council', 'location'],
    },
    'environment': {
        'keywords': ['stormwater', 'contaminated', 'environment', 'septic',
                     'wastewater', 'climate', 'bushfire', 'fire', 'emergency',
                     'sustainability'],
    },
    'legal': {
        'keywords': ['appeal', 'complaint', 'legal', 'ombudsman', 'foi',
                     'freedom of information', 'privacy', 'whistleblower'],
    },
    'grants': {
        'keywords': ['grant', 'funding', 'support', 'community fund', 'assistance'],
    },
    'local_laws': {
        'keywords': ['local law', 'bylaw', 'burning', 'burn off', 'camping',
                     'livestock', 'noise', 'domestic animal'],
    },
    'forms': {
        'keywords': ['form', 'application', 'download', 'online', 'portal',
                     'template', 'template'],
    },
    'potential_api_abuse': {
        'keywords': ['api', 'endpoint', 'json', 'curl', 'hack', 'inject',
                     'sql', 'script', 'exploit', 'sql injection'],
    },
    'off_topic': {
        'keywords': ['weather', 'football', 'recipe', 'joke', 'song', 'weather',
                     'celebrity', 'politics', 'unrelated'],
    },
}

def classify(text):
    """Classify query into service category."""
    text_lower = text.lower()
    scores = {}
    for cat, info in CATEGORIES.items():
        score = sum(1 for kw in info['keywords'] if kw in text_lower)
        scores[cat] = score
    top = max(scores, key=scores.get) if max(scores.values()) > 0 else 'general'
    return top

# ── Address Detection ──────────────────────────────────────
def detect_address(text):
    """Detect Australian street address including unit numbers."""
    pattern = r'\b(?:(?:Unit|Apt|Flat|Level|Suite)\s*\d+[A-Za-z]?\s*[/,]\s*)?(\d{1,5}\s+[A-Za-z][A-Za-z\s]{2,30}(?:Street|St|Road|Rd|Drive|Dr|Avenue|Ave|Boulevard|Blvd|Court|Ct|Crescent|Cres|Place|Pl|Way|Lane|Ln|Parade|Pde|Circuit|Cct|Close|Cl|Grove|Gr|Terrace|Tce|Rise|Highway|Hwy|Strip|Esplanade|Esp|East|West|North|South|E|W|N|S)[\s,]*[A-Za-z\s]*)\b'
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(0).strip().rstrip(',') if match else None

# ── Bin Day Logic (multi-turn aware) ───────────────────────
def check_bin_context(messages):
    """Scan conversation history for bin question + address across multiple turns."""
    has_bin_question = False
    address = None
    for msg in messages:
        if msg.get('role') == 'user':
            content = msg.get('content', '')
            cat = classify(content)
            if cat == 'waste_bins':
                has_bin_question = True
            addr = detect_address(content)
            if addr:
                address = addr
    return has_bin_question, address

# ── Bin Day Implementations ────────────────────────────────
def parse_bin_schedule(knowledge_text):
    """Parse static bin schedule from knowledge.txt."""
    schedule = {}
    return schedule

def lookup_bin_day(address, messages):
    """Route to appropriate bin lookup method."""
    if BIN_LOOKUP_MODE == 'api':
        return lookup_bin_api(address)
    elif BIN_LOOKUP_MODE == 'geojson':
        return lookup_bin_geojson(address)
    elif BIN_LOOKUP_MODE == 'calculation':
        return calculate_bin_day(address)
    elif BIN_LOOKUP_MODE == 'static':
        return lookup_bin_static(address)
    return None

def lookup_bin_api(address):
    """Lookup bin day via live API endpoint."""
    return None

def lookup_bin_geojson(address):
    """Lookup bin day via GeoJSON zone matching."""
    return None

def calculate_bin_day(address):
    """Calculate bin day using reference date calculation."""
    return None

def lookup_bin_static(address):
    """Lookup bin day via static schedule from knowledge.txt."""
    return BIN_SCHEDULE.get(address.lower(), None)

# ── System Prompt ──────────────────────────────────────────
def build_system_prompt(category, bin_context=""):
    """Build system prompt with current date and bin context."""
    today = date.today().strftime('%A %d %B %Y')
    prompt = KNOWLEDGE_BASE.replace('__CURRENT_DATE__', today)
    prompt = prompt.replace('__PROMPT_VERSION__', PROMPT_VERSION)
    if bin_context:
        prompt += f"\n\n--- LIVE BIN DATA ---\n{bin_context}"
    return prompt

# ── Dual JSONL Logging (V8 NEW) ────────────────────────────
def log_query_basic(ip, question, response_time_ms):
    """Write to basic log — lightweight operational tracking."""
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "ip": hashlib.sha256(ip.encode()).hexdigest()[:12],
        "q": filter_pii(question),
        "ms": response_time_ms,
        "cat": classify(question),
    }
    try:
        with open("query_log_basic.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def log_query_full(ip, question, answer, response_time_ms,
                   thumbs=None, sources=None, follow_up_of=None):
    """Write to full log — comprehensive analytics."""
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "ip": hashlib.sha256(ip.encode()).hexdigest()[:12],
        "q": filter_pii(question),
        "a": filter_pii(answer),
        "a_len": len(answer),
        "ms": response_time_ms,
        "cat": classify(question),
        "thumbs": thumbs,
        "sources": sources or [],
        "follow_up": follow_up_of,
        "prompt_v": PROMPT_VERSION,
        "kb_hash": KNOWLEDGE_HASH,
    }
    try:
        with open("query_log_full.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

# ── Legacy CSV Analytics (V7 compatibility) ────────────────
def log_analytics_csv(category, session_id, message_preview):
    """Log query to CSV for analytics."""
    try:
        with open('analytics.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().isoformat(), category, session_id,
                           message_preview[:80]])
    except Exception:
        pass

# ── Search Mode Handler (V8 ARCHITECTURE) ──────────────────
def handle_search_query(query):
    """Hidden search protocol — returns structured link results.
    Triggered by messages starting with 'search:'.
    Not user-facing yet — for operator testing and future product."""
    results = []
    query_lower = query.lower().strip()

    # Parse URL directory from knowledge base
    in_directory = False
    current_category = ""
    for line in KNOWLEDGE_BASE.splitlines():
        if '=== URL DIRECTORY' in line:
            in_directory = True
            continue
        if in_directory and line.startswith('==='):
            break
        if in_directory:
            if line.startswith('---'):
                current_category = line.strip('- \n')
            elif '[ENDPOINT]' in line and 'http' in line:
                # Extract URL and description
                parts = line.split('http')
                label = parts[0].replace('[ENDPOINT]', '').strip().rstrip(':')
                url = 'http' + parts[1].strip()
                desc = label  # fallback
                results.append({
                    'category': current_category,
                    'label': label,
                    'url': url,
                    'desc': desc,
                })

    # Score results against query
    scored = []
    for r in results:
        score = sum(1 for word in query_lower.split()
                   if word in r['label'].lower() or word in r['desc'].lower())
        if score > 0:
            scored.append((score, r))

    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:10]]

# ── Flask Routes ───────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main chat interface."""
    try:
        return send_file('page.html')
    except Exception as e:
        print(f"[ERROR] {e}")
        return "Error loading interface", 500

@app.route('/health', methods=['GET'])
def health():
    """Return server health and config status."""
    uptime = int(time.time() - SERVER_START_TIME)
    return jsonify({
        'status': 'ok',
        'council': COUNCIL_NAME,
        'knowledge_loaded': len(KNOWLEDGE_BASE) > 0,
        'knowledge_lines': KNOWLEDGE_LINES,
        'knowledge_hash': KNOWLEDGE_HASH,
        'bin_mode': BIN_LOOKUP_MODE,
        'model': MODEL,
        'prompt_version': PROMPT_VERSION,
        'uptime_seconds': uptime,
        'total_queries': TOTAL_QUERIES,
    })

@app.route('/knowledge.txt', methods=['GET'])
def serve_knowledge():
    """Serve the knowledge base file."""
    try:
        return send_file('knowledge.txt', mimetype='text/plain')
    except Exception:
        return "Knowledge base not found", 404

@app.route('/api/chat', methods=['POST', 'OPTIONS'])
def chat():
    """Main chat endpoint — process user message and return AI response."""
    global TOTAL_QUERIES

    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response, 200

    start_time = time.time()
    client_ip = request.remote_addr or 'unknown'

    try:
        data = request.json or {}
        messages = data.get('messages', [])
        user_message = messages[-1]['content'] if messages else ''

        if not user_message:
            response = jsonify({'error': 'No message provided'})
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response, 400

        # Check for search protocol (hidden — operator testing only)
        if user_message.lower().startswith('search:'):
            search_query = user_message[7:].strip()
            results = handle_search_query(search_query)
            response_ms = int((time.time() - start_time) * 1000)
            log_query_basic(client_ip, user_message, response_ms)

            response_obj = jsonify({
                'response': f"Search results for '{search_query}':\n" +
                    '\n'.join([f"- [{r['label']}]({r['url']})" for r in results]) if results else "No results found",
                'category': 'search',
                'search_results': results,
            })
            response_obj.headers['Access-Control-Allow-Origin'] = '*'
            return response_obj, 200

        # Classify query
        category = classify(user_message)

        # Handle abuse/off-topic
        if category == 'potential_api_abuse':
            response_ms = int((time.time() - start_time) * 1000)
            log_query_basic(client_ip, user_message, response_ms)

            response_obj = jsonify({
                'response': f"I'm the {COUNCIL_NAME} Community Assistant. I can help with council services like bins, rates, planning, and pets. What can I help you with?",
                'category': category
            })
            response_obj.headers['Access-Control-Allow-Origin'] = '*'
            return response_obj, 200

        if category == 'off_topic':
            # Log off-topic as informational only — query still reaches API
            response_ms = int((time.time() - start_time) * 1000)
            log_query_basic(client_ip, user_message, response_ms)
            print(f"[OFF_TOPIC] {user_message[:80]} — routing to API")

        # Check bin context across conversation history
        bin_context = ""
        has_bin_q, address = check_bin_context(messages)
        if has_bin_q and address and BIN_LOOKUP_MODE != 'none':
            bin_data = lookup_bin_day(address, messages)
            if bin_data:
                bin_context = f"[LIVE BIN COLLECTION DATA]\n{bin_data}"

        # Build system prompt
        system_prompt = build_system_prompt(category, bin_context)

        # Call Anthropic API
        api_response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=messages
        )

        assistant_text = api_response.content[0].text
        response_ms = int((time.time() - start_time) * 1000)
        TOTAL_QUERIES += 1

        # Log to all three systems
        log_analytics_csv(category, data.get('session_id', 'unknown'), user_message)
        log_query_basic(client_ip, user_message, response_ms)
        log_query_full(client_ip, user_message, assistant_text, response_ms)

        response_obj = jsonify({
            'response': assistant_text,
            'category': category,
            'bin_info': bin_context if bin_context else None
        })
        response_obj.headers['Access-Control-Allow-Origin'] = '*'
        return response_obj, 200

    except Exception as e:
        print(f"[ERROR] {e}")
        response_ms = int((time.time() - start_time) * 1000)
        log_query_basic(client_ip, str(e), response_ms)

        response_obj = jsonify({
            'response': f"Sorry, I couldn't process your question right now. Please try again, or call {COUNCIL_NAME} on {COUNCIL_PHONE} for help.",
            'error': True,
            'category': 'general'
        })
        response_obj.headers['Access-Control-Allow-Origin'] = '*'
        return response_obj, 200

@app.route('/feedback', methods=['POST', 'OPTIONS'])
def feedback():
    """Handle user feedback (thumbs up/down and optional message)."""

    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response, 200

    try:
        data = request.json or {}

        # Log to feedback.csv
        try:
            with open('feedback.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    data.get('rating', ''),
                    filter_pii(data.get('message_preview', ''))[:80]
                ])
        except Exception:
            pass

        # Also log thumbs to full JSONL if query hash provided
        if data.get('query_hash'):
            # Implementation: read last N lines, find match, update
            # For now, we'll skip updating existing entries
            pass

        response_obj = jsonify({'status': 'ok'})
        response_obj.headers['Access-Control-Allow-Origin'] = '*'
        return response_obj, 200

    except Exception as e:
        print(f"[FEEDBACK ERROR] {e}")
        response_obj = jsonify({'error': str(e)})
        response_obj.headers['Access-Control-Allow-Origin'] = '*'
        return response_obj, 500

# ── Error Handlers ─────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    response = jsonify({'error': 'Not found'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response, 404

@app.errorhandler(500)
def server_error(error):
    response = jsonify({'error': f"Sorry, something went wrong. Please call {COUNCIL_NAME} on {COUNCIL_PHONE} for help."})
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response, 500

# ── Main ───────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"[SERVER] {COUNCIL_NAME} CouncilGenius V8 — {MODEL}")
    print(f"[SERVER] Knowledge: {KNOWLEDGE_LINES} lines, hash: {KNOWLEDGE_HASH}")
    print(f"[SERVER] Prompt version: {PROMPT_VERSION}")
    print(f"[SERVER] Bin mode: {BIN_LOOKUP_MODE}")
    print(f"[SERVER] Listening on port {PORT}")

    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=False,
        use_reloader=False
    )
