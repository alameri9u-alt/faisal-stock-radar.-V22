import os, sqlite3, secrets, hashlib, base64
from datetime import datetime, timedelta, timezone
from functools import wraps
import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
DB = os.getenv("DATABASE_PATH", "radar.db")
BASE = "https://api.massive.com"

def connect():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

with connect() as c:
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS watchlist (ticker TEXT,category TEXT,note TEXT,added_at TEXT,PRIMARY KEY(ticker,category))")
    c.execute("CREATE TABLE IF NOT EXISTS evaluations (id INTEGER PRIMARY KEY,ticker TEXT,at TEXT,data TEXT)")

def cipher():
    secret = os.getenv("RADAR_ENCRYPTION_KEY") or os.getenv("FLASK_SECRET_KEY")
    if not secret: raise RuntimeError("اضبط RADAR_ENCRYPTION_KEY في Render أولًا.")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))

def saved_key():
    with connect() as c: row = c.execute("SELECT value FROM settings WHERE key='massive_api_key'").fetchone()
    if not row: return None
    try: return cipher().decrypt(row["value"].encode()).decode()
    except (InvalidToken, RuntimeError): return None

def api_key(): return saved_key() or os.getenv("MASSIVE_API_KEY")

def admin(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not session.get("admin_ok"):
            return (jsonify(ok=False,error="يلزم دخول المسؤول"),401) if request.path.startswith("/api/") else redirect(url_for("login"))
        return fn(*a, **kw)
    return inner

class Massive:
    def __init__(self,key):
        self.s=requests.Session(); self.s.headers["Authorization"]="Bearer "+key
    def get(self,path,params=None):
        r=self.s.get(BASE+path,params=params or {},timeout=25)
        if r.status_code==401: raise RuntimeError("مفتاح API غير صالح.")
        if r.status_code==403: raise RuntimeError("اشتراك Massive لا يسمح بهذا المسار.")
        if r.status_code==429: raise RuntimeError("تم بلوغ حد الطلبات؛ حاول لاحقًا.")
        r.raise_for_status(); return r.json()
    def details(self,t): return self.get("/v3/reference/tickers/"+t).get("results",{})
    def bars(self,t,days=90):
        end=datetime.now(timezone.utc).date(); start=end-timedelta(days=days)
        return self.get(f"/v2/aggs/ticker/{t}/range/1/day/{start}/{end}",{"adjusted":"true","sort":"asc","limit":5000}).get("results",[])
    def symbols(self,n): return self.get("/v3/reference/tickers",{"market":"stocks","active":"true","limit":min(1000,max(1,n)),"sort":"ticker","order":"asc"}).get("results",[])

def metrics(t,d,b):
    b=sorted(b,key=lambda x:x.get("t",0))
    if not b: return {"ticker":t,"name":d.get("name",""),"price":None,"market_cap":d.get("market_cap"),"float":None,"avg_vol20":None,"rel_vol":None,"monthly_performance":None,"status":"UNKNOWN","source":"Massive API"}
    vols=[x["v"] for x in b if isinstance(x.get("v"),(int,float))]
    closes=[x["c"] for x in b if isinstance(x.get("c"),(int,float))]
    avg=sum(vols[-21:-1])/len(vols[-21:-1]) if len(vols)>1 and vols[-21:-1] else None
    rv=b[-1].get("v")/avg if avg and b[-1].get("v") is not None else None
    month=(closes[-1]/closes[-22]-1)*100 if len(closes)>=22 and closes[-22] else None
    return {"ticker":t,"name":d.get("name",""),"price":b[-1].get("c"),"market_cap":d.get("market_cap"),"float":None,"avg_vol20":avg,"rel_vol":rv,"monthly_performance":month,"day_volume":b[-1].get("v"),"support":min(x["l"] for x in b[-20:] if x.get("l") is not None),"resistance":max(x["h"] for x in b[-20:] if x.get("h") is not None),"data_time":datetime.fromtimestamp(b[-1]["t"]/1000,tz=timezone.utc).isoformat() if b[-1].get("t") else None,"source":"Massive API","status":"OK","note":"Float غير متاح من المسارات الحالية، لذلك يبقى UNKNOWN."}

def checks(m, price=5, cap=300_000_000, avg=100000, rv=1):
    items=[]
    for label,val,ok,evidence in [
        ("السعر",m.get("price"),lambda x:x<price,f"أقل من ${price}"),
        ("القيمة السوقية",m.get("market_cap"),lambda x:x<cap,f"أقل من ${cap:,.0f}"),
        ("Float",m.get("float"),lambda x:x<50_000_000,"يلزم مصدر Float موثوق"),
        ("متوسط حجم 20 يومًا",m.get("avg_vol20"),lambda x:x>=avg,f"على الأقل {avg:,.0f}"),
        ("Relative Volume",m.get("rel_vol"),lambda x:x>=rv,f"على الأقل {rv}x"),
        ("الأداء الشهري",m.get("monthly_performance"),lambda x:x<0,"سلبي")
    ]:
        items.append({"label":label,"value":val,"state":"UNKNOWN" if val is None else ("PASS" if ok(val) else "FAIL"),"evidence":evidence})
    return items

def test():
    key=api_key()
    if not key:return {"ok":False,"message":"أدخل مفتاح Massive API من الإعدادات أو Render."}
    try: Massive(key).get("/v3/reference/tickers",{"ticker":"AAPL","market":"stocks","limit":1}); return {"ok":True,"message":"نجح الاتصال بمسار البيانات المرجعية."}
    except Exception as e:return {"ok":False,"message":str(e)}

@app.get("/")
def home(): return render_template("index.html",connection=test(),logged_in=bool(session.get("admin_ok")))
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        pwd=os.getenv("RADAR_ADMIN_PASSWORD","")
        if pwd and secrets.compare_digest(request.form.get("password",""),pwd): session["admin_ok"]=True; return redirect("/settings")
        flash("كلمة المرور غير صحيحة أو RADAR_ADMIN_PASSWORD غير مضبوط.")
    return render_template("login.html")
@app.post("/logout")
def logout(): session.clear(); return redirect("/")
@app.get("/settings")
@admin
def settings():
    return render_template("settings.html",has_saved=bool(saved_key()),has_env=bool(os.getenv("MASSIVE_API_KEY")),connection=test())
@app.post("/settings/api-key")
@admin
def set_key():
    action=request.form.get("action")
    if action=="delete":
        with connect() as c:c.execute("DELETE FROM settings WHERE key='massive_api_key'")
        flash("حُذف مفتاح الموقع؛ سيُستخدم مفتاح Render إن وجد."); return redirect("/settings")
    key=request.form.get("api_key","").strip()
    if not key: flash("أدخل المفتاح."); return redirect("/settings")
    try:
        enc=cipher().encrypt(key.encode()).decode()
        with connect() as c:c.execute("INSERT INTO settings VALUES('massive_api_key',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(enc,))
        flash("تم حفظ المفتاح مشفرًا على الخادم.")
    except Exception as e: flash(str(e))
    return redirect("/settings")
@app.post("/api/connection")
@admin
def connection(): return jsonify(test())
@app.post("/api/scan")
def scan():
    if not api_key(): return jsonify(ok=False,error="لا يوجد مفتاح API.",results=[]),400
    q=request.get_json(silent=True) or {}; limit=min(100,max(1,int(q.get("scan_limit",20))))
    try:
        client=Massive(api_key()); symbols=client.symbols(limit); out=[]; errors=[]
        for item in symbols:
            t=item.get("ticker")
            if not t: continue
            try:
                d=client.details(t); ex=d.get("primary_exchange")
                exchange=q.get("exchange","Any")
                if exchange=="NASDAQ" and ex!="XNAS": continue
                if exchange=="NYSE" and ex!="XNYS": continue
                m=metrics(t,d,client.bars(t))
                m["checklist"]=checks(m,float(q.get("max_price",5)),float(q.get("max_market_cap_m",300))*1e6,float(q.get("min_avg_volume",100000)),float(q.get("min_relative_volume",1)))
                if m["price"] is not None and m["price"]>=float(q.get("max_price",5)): continue
                if m["market_cap"] is not None and m["market_cap"]>=float(q.get("max_market_cap_m",300))*1e6: continue
                if m["avg_vol20"] is not None and m["avg_vol20"]<float(q.get("min_avg_volume",100000)): continue
                if m["rel_vol"] is not None and m["rel_vol"]<float(q.get("min_relative_volume",1)): continue
                if m["monthly_performance"] is not None and m["monthly_performance"]>=0: continue
                states=[x["state"] for x in m["checklist"]]; m["quality"]=round(100*states.count("PASS")/len(states))
                m["classification"]="يحتاج تحققًا إضافيًا" if "UNKNOWN" in states or "FAIL" in states else "مناسب للمراجعة"
                out.append(m)
            except Exception as e: errors.append({"ticker":t,"error":str(e)})
        import json
        with connect() as c:
            for m in out:c.execute("INSERT INTO evaluations(ticker,at,data) VALUES(?,?,?)",(m["ticker"],datetime.now(timezone.utc).isoformat(),json.dumps(m,ensure_ascii=False)))
        return jsonify(ok=True,scanned=len(symbols),count=len(out),note="المسح محدود بعدد الرموز المختار وليس مسحًا شاملًا. Float يبقى UNKNOWN.",results=out,errors=errors[:8])
    except Exception as e:return jsonify(ok=False,error=str(e),results=[]),502
@app.get("/api/ticker/<ticker>")
def ticker(ticker):
    if not api_key(): return jsonify(ok=False,error="لا يوجد مفتاح API."),400
    try:
        c=Massive(api_key()); m=metrics(ticker.upper(),c.details(ticker.upper()),c.bars(ticker.upper())); m["checklist"]=checks(m)
        import json
        with connect() as con:con.execute("INSERT INTO evaluations(ticker,at,data) VALUES(?,?,?)",(ticker.upper(),datetime.now(timezone.utc).isoformat(),json.dumps(m,ensure_ascii=False)))
        return jsonify(ok=True,result=m)
    except Exception as e:return jsonify(ok=False,error=str(e)),502
@app.get("/api/watchlist/<category>")
@admin
def get_watch(category):
    if category not in ("watchlist","ready"):return jsonify(ok=False,error="قائمة غير معروفة"),400
    with connect() as c: rows=c.execute("SELECT * FROM watchlist WHERE category=? ORDER BY added_at DESC",(category,)).fetchall()
    return jsonify(ok=True,items=[dict(x) for x in rows])
@app.post("/api/watchlist")
@admin
def save_watch():
    d=request.get_json(silent=True) or {}; t=str(d.get("ticker","")).strip().upper(); cat=d.get("category","watchlist")
    if not t or cat not in ("watchlist","ready"):return jsonify(ok=False,error="رمز أو قائمة غير صحيحة"),400
    with connect() as c:c.execute("INSERT INTO watchlist VALUES(?,?,?,?) ON CONFLICT(ticker,category) DO UPDATE SET note=excluded.note",(t,cat,str(d.get("note",""))[:500],datetime.now(timezone.utc).isoformat()))
    return jsonify(ok=True)
@app.delete("/api/watchlist")
@admin
def del_watch():
    d=request.get_json(silent=True) or {}
    with connect() as c:c.execute("DELETE FROM watchlist WHERE ticker=? AND category=?",(str(d.get("ticker","")).upper(),d.get("category","watchlist")))
    return jsonify(ok=True)
@app.get("/api/history")
@admin
def history():
    import json
    with connect() as c: rows=c.execute("SELECT ticker,at,data FROM evaluations ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify(ok=True,items=[{"ticker":x["ticker"],"at":x["at"],"result":json.loads(x["data"])} for x in rows])
@app.get("/health")
def health(): return jsonify(ok=True,service="faisal-stock-radar")
if __name__=="__main__":app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")))
