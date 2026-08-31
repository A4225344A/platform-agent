"""W3 v6 判讀 Agent:Alertmanager webhook -> 佇列 -> 脫敏 -> Hybrid RAG -> LiteLLM -> 修復 -> 寫回。

所有外部位址走環境變數,所有狀態存 Postgres —— 換雲時只換環境變數,程式碼不動。

v6 相對 v5 的七處變更:
  1. 追蹤改用 OTel GenAI 標準屬性 + OTLP,不綁任何廠商 SDK
  2. 告警進 Postgres 佇列(FOR UPDATE SKIP LOCKED),不再用記憶體背景執行緒
  3. 全域斷路器 + 動手前重新確認告警仍在 firing
  4. 服務目錄:擁有權路由、tier 政策、runbook 與部署時間進 prompt
  5. Hybrid Search 的關鍵字從日誌抽取,不再誤傳服務名
  6. 知識庫寫回帶 outcome 分級,失敗與 notify_only 不進 RAG
  7. Structured Outputs:模型在解碼階段就受 enum 約束
"""
import os
import re
import json
import time
import logging
import threading
from contextlib import closing
from typing import Literal

import boto3
import psycopg2
import requests
from flask import Flask, request, jsonify
from pgvector.psycopg2 import register_vector
from pydantic import BaseModel, Field, ValidationError
from kubernetes import client as k8s, config as k8s_config
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException

from opentelemetry import trace as otel_trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

import genai_semconv as sc

LITELLM_URL = os.environ["LITELLM_URL"]
LITELLM_KEY = os.environ["LITELLM_MASTER_KEY"]
PRESIDIO_URL = os.environ["PRESIDIO_URL"]
PROM_URL = os.environ["PROM_URL"]
PGHOST = os.environ.get("PGHOST", "postgres")
PGPASSWORD = os.environ["PGPASSWORD"]
ALERT_EMAIL = os.environ["ALERT_EMAIL"]          # 寄件人 + 目錄查不到時的後備收件人
AWS_REGION = os.environ.get("AWS_REGION", "ap-northeast-1")
NAMESPACE = os.environ.get("TARGET_NAMESPACE", "default")
AGENT_VERSION = os.environ.get("AGENT_VERSION", "v6.1.3")

COOLDOWN_MIN = int(os.environ.get("COOLDOWN_MIN", "10"))
VERIFY_WAIT = int(os.environ.get("VERIFY_WAIT_SEC", "60"))
MAX_REMEDIATIONS = int(os.environ.get("MAX_REMEDIATIONS", "3"))
CIRCUIT_WINDOW_MIN = int(os.environ.get("CIRCUIT_WINDOW_MIN", "15"))
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "3"))
STALE_LOCK_MIN = int(os.environ.get("STALE_LOCK_MIN", "10"))
USE_STRUCTURED = os.environ.get("USE_STRUCTURED_OUTPUT", "true").lower() == "true"
EMBED_MODEL_VERSION = os.environ.get("EMBED_MODEL_VERSION", "titan-embed-text-v2")

app = Flask(__name__)


def configure_kubernetes():
    if os.environ.get("SKIP_K8S_CONFIG", "false").lower() == "true":
        return
    try:
        k8s_config.load_incluster_config()
    except ConfigException:
        k8s_config.load_kube_config()


configure_kubernetes()
apps_v1 = k8s.AppsV1Api()
core_v1 = k8s.CoreV1Api()
autoscaling_v2 = k8s.AutoscalingV2Api()
ses = boto3.client("ses", region_name=AWS_REGION)

# ---------- 綁定點十:AI 可觀測性(OTel 標準,後端由環境變數決定) ----------
otel_resource = Resource.create({
    "service.name": "w3-ai-agent",
    "service.version": AGENT_VERSION,
})

trace_provider = TracerProvider(resource=otel_resource)
trace_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter())        # 讀 OTEL_EXPORTER_OTLP_ENDPOINT
)
otel_trace.set_tracer_provider(trace_provider)
tracer = otel_trace.get_tracer("w3.agent")

# Python logging 不會因為設了 OTEL_EXPORTER_OTLP_LOGS_ENDPOINT 就自己變成 OTLP。
# 需要明確建立 Logs SDK bridge:logging -> LoggingHandler -> OTLPLogExporter。
log_provider = LoggerProvider(resource=otel_resource)
set_logger_provider(log_provider)
log_handlers = [logging.StreamHandler()]         # 保留 kubectl logs
if os.environ.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"):
    log_provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter())   # 讀 OTEL_EXPORTER_OTLP_LOGS_ENDPOINT
    )
    log_handlers.append(
        LoggingHandler(level=logging.INFO, logger_provider=log_provider)
    )
logging.basicConfig(
    level=logging.INFO,
    handlers=log_handlers,
)
log = logging.getLogger("agent")


# ---------- Schema(綁定點四:不依賴模型盲從) ----------
class RemediationAction(BaseModel):
    action: Literal["restart", "rollback", "notify_only"]
    service: str = Field(min_length=1, max_length=63)
    reason: str = Field(min_length=1, max_length=500)


def _strip_bedrock_unsupported_schema_keywords(value):
    if isinstance(value, dict):
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            value.pop(key, None)
        for child in value.values():
            _strip_bedrock_unsupported_schema_keywords(child)
    elif isinstance(value, list):
        for child in value:
            _strip_bedrock_unsupported_schema_keywords(child)


def response_format():
    """把同一份 Pydantic Schema 轉成模型的解碼約束。

    v6:Schema 現在有兩個用途 ——
      (1) 送給模型當解碼約束(Bedrock 2026-02 起以文法強制)
      (2) 回來後仍用 Pydantic 驗證一次
    v5 只有 (2)。有了 (1),(2) 才從唯一防線變成第二道防線。
    """
    schema = RemediationAction.model_json_schema()
    schema["additionalProperties"] = False
    _strip_bedrock_unsupported_schema_keywords(schema)
    return {"type": "json_schema",
            "json_schema": {"name": "remediation_action",
                            "strict": True, "schema": schema}}


# ---------- Postgres(所有狀態) ----------
def db():
    """注意用法:with closing(db()) as conn。

    psycopg2 的 `with conn:` 只管交易(commit/rollback),**不會關閉連線**。
    只寫 `with db() as conn` 會造成連線洩漏,最終耗盡 max_connections。
    """
    conn = psycopg2.connect(
        host=PGHOST, user="postgres", password=PGPASSWORD, dbname="postgres",
        connect_timeout=10,
    )
    register_vector(conn)
    # RAG 查詢有 outcome 過濾。不開 iterative scan 的話,HNSW 會先取
    # ef_search 筆再過濾,可能靜默回傳過少甚至 0 筆。
    with conn.cursor() as cur:
        cur.execute("SET hnsw.iterative_scan = 'relaxed_order'")
        cur.execute("SET hnsw.max_scan_tuples = 20000")
        cur.execute("SET hnsw.ef_search = 60")
    conn.commit()
    return conn


# ---------- 服務目錄:擁有權與政策 ----------
DEFAULT_META = {"owner_email": ALERT_EMAIL, "escalation_email": None, "tier": 0,
                "auto_remediate": False, "runbook_url": None, "last_deploy_at": None,
                "log_query_url_template": None, "depends_on": []}


def lookup_service(service):
    """查擁有權與政策。查不到時回傳保守預設 ——
    不在目錄裡的服務一律不自動修復,因為我們對它一無所知。

    v6.1:多讀 log_query_url_template(供 notify_owner() 附上深連結)
    與 depends_on(供 query_dependency_health() 判斷相依服務健康度)。
    """
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "SELECT owner_email, escalation_email, tier, auto_remediate, "
            "       runbook_url, last_deploy_at, log_query_url_template, depends_on "
            "FROM service_catalog WHERE service = %s", (service,))
        row = cur.fetchone()
    if not row:
        log.warning("service %s not in catalog; defaulting to notify_only", service)
        return dict(DEFAULT_META)
    keys = ("owner_email", "escalation_email", "tier", "auto_remediate",
            "runbook_url", "last_deploy_at", "log_query_url_template", "depends_on")
    return dict(zip(keys, row))


# ---------- 冷卻與斷路器 ----------
def in_cooldown(alertname, service):
    """同一告警 + 同一服務,COOLDOWN_MIN 分鐘內只修一次。"""
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM remediation_log "
            "WHERE alertname = %s AND service = %s "
            "AND created_at > now() - (%s || ' minutes')::interval LIMIT 1",
            (alertname, service, COOLDOWN_MIN),
        )
        return cur.fetchone() is not None


def circuit_open():
    """全叢集範圍的修復速率上限。

    v5 只有 per-(alertname, service) 冷卻,擋不住「共用相依掛掉導致
    10 個服務同時告警」→ 10 個修復同時執行 → 連鎖降級。
    這是業界有實際案例的失效模式,不是假想風險。
    """
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM remediation_log "
            "WHERE action <> 'notify_only' "
            "AND created_at > now() - (%s || ' minutes')::interval",
            (CIRCUIT_WINDOW_MIN,),
        )
        n = cur.fetchone()[0]
    if n >= MAX_REMEDIATIONS:
        log.warning("circuit breaker OPEN: %d remediations in %d min",
                    n, CIRCUIT_WINDOW_MIN)
        return True
    return False


def log_remediation(alertname, act, verified, trace_id, incident_id=None):
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO remediation_log "
            "(alertname, service, action, reason, verified, trace_id, incident_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (alertname, act.service, act.action, act.reason, verified,
             trace_id, incident_id),
        )


def classify_outcome(acted, ok):
    if not acted:
        return "notify_only"
    return "verified" if ok else "failed"


# ---------- v7:事故生命週期 ----------
# 到 v6 為止,一次判讀只在結案時寫兩列(write_back() + log_remediation())。
# 中間發生的一切 —— 看了哪幾行日誌、遮蔽了幾個實體、檢索到什麼、五道降級
# 檢查怎麼判定、花了多少 token —— 全是區域變數,函式返回就消失。
# v7 把這件事拆成三支函式,讓事故列在流程「開始」時就存在,
# 過程逐步寫進 incident_steps,結案時才補完。

def open_incident(alertname, service, trace_id, started_at):
    """在 diagnose() 一開始就建列,而不是結案時。

    v6 的 write_back() 是 verify()(內含 sleep(VERIFY_WAIT))跑完才 INSERT——
    也就是說事故進行中的那一到三分鐘,資料庫裡根本沒有這一列。W4 控制平面
    的「判讀中」狀態、5 秒輪詢、以及進行中的時間軸全部依賴這一列存在。
    """
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO incidents "
            "(service, summary, resolution, alertname, trace_id, "
            " started_at, status, outcome) "
            "VALUES (%s, '', '', %s, %s, %s, 'running', 'unverified') "
            "RETURNING id",
            (service, alertname, trace_id, started_at))
        return cur.fetchone()[0]


def step(incident_id, name, detail):
    """時間軸的一格。

    刻意不批次、不緩衝 —— 進行中的事故要能即時看到進度,緩衝會讓
    「判讀中」這個狀態失去意義。代價是每次判讀多約 30–50 ms 的資料庫
    往返,相對於一次 LLM 呼叫可以忽略。

    刻意把例外吞掉,只寫 log —— 時間軸的某一格寫失敗,判讀應該繼續跑完
    (少一格總比整次判讀掛掉好)。這與 open_incident()/close_incident()
    不吞例外是刻意的不對稱:事故列本身建不起來或補不完,代表資料庫有
    更嚴重的問題,應該讓例外往上拋、進到 diagnose() 既有的 except 分支。
    """
    if incident_id is None:
        return
    try:
        with closing(db()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO incident_steps (incident_id, step, detail) "
                "VALUES (%s, %s, %s)",
                (incident_id, name,
                 json.dumps(detail, ensure_ascii=False, default=str)))
    except Exception:
        log.exception("step write failed: %s/%s", incident_id, name)


def close_incident(incident_id, status="closed", outcome=None,
                   summary=None, resolution=None, vec=None):
    """補完事故列。取代 v6 的 write_back()——INSERT 移到 open_incident(),
    這裡只做 UPDATE。嵌入向量仍在這裡才寫,因為它需要脫敏後的日誌,
    而那要等流程跑到第 2 步才有。
    """
    sets = ["status = %s", "ended_at = now()"]
    args = [status]
    if outcome is not None:
        sets.append("outcome = %s");    args.append(outcome)
    if summary is not None:
        sets.append("summary = %s");    args.append(summary)
    if resolution is not None:
        sets.append("resolution = %s"); args.append(resolution)
    if vec is not None:
        sets.append("embedding = %s");   args.append(vec)
        sets.append("embed_model = %s"); args.append(EMBED_MODEL_VERSION)
    args.append(incident_id)
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id = %s", args)


# ---------- 工作佇列(取代 v5 的 threading.Thread) ----------
def enqueue(group):
    """排入佇列。唯一索引保證同一個 groupKey 不會重複排入,
    這同時解決 Alertmanager 逾時重送造成的重複判讀。"""
    key = group.get("groupKey") or json.dumps(
        group.get("commonLabels", {}), sort_keys=True)
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO alert_queue (group_key, payload) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (key, json.dumps(group)),
        )


def claim_one():
    """取出一件工作。SKIP LOCKED 讓多個 replica 可以安全並行 ——
    v5 的執行緒方案綁死單一 replica,這個方案沒有這個限制。"""
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE alert_queue SET status='running', locked_at=now(),
                                   attempts = attempts + 1
            WHERE id = (
              SELECT id FROM alert_queue
              WHERE status='pending'
                 OR (status='running'
                     AND locked_at < now() - (%s || ' minutes')::interval)
              ORDER BY created_at
              FOR UPDATE SKIP LOCKED
              LIMIT 1
            )
            RETURNING id, payload, attempts
            """,
            (STALE_LOCK_MIN,),
        )
        return cur.fetchone()


def finish(job_id, ok):
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute("UPDATE alert_queue SET status=%s WHERE id=%s",
                    ("done" if ok else "failed", job_id))


def queue_depth():
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM alert_queue WHERE status='pending'")
        return cur.fetchone()[0]


# ---------- 綁定點九:應用層脫敏(保護落地儲存與外送) ----------
# gateway 的 guardrail 保護送進模型的內容;這一層保護寫進 Postgres、
# 寄出的郵件、以及 OTel span 屬性 —— 那些不經過 gateway。
TW_ID_RECOGNIZER = {
    "name": "TW_ID_RECOGNIZER",
    "supported_language": "en",
    "supported_entity": "TW_ID",
    "patterns": [{"name": "tw_id", "regex": r"\b[A-Z][12]\d{8}\b", "score": 0.8}],
}
INJECTION_KEYWORDS = [
    "ignore previous", "ignore all previous", "disregard the above",
    "system prompt", "you are now", "new instructions",
    "忽略前面", "忽略以上", "你現在是",
]


def sanitize(text):
    """回傳 (清乾淨的文字, 遮蔽區間, 實體數)。v7 變更(原僅回傳文字)。

    偏移量刻意在替換的同時累計,而不是事後用 regex 找 [XXX] —— 日誌裡
    本來就充滿方括號([Warning]、[main]、[http-nio-8080-exec-3]),事後
    比對會把它們一起框成「遮蔽處」。

    由後往前替換是為了讓尚未處理的 entity 偏移量保持有效;因此收集到
    的區間是倒序的,回傳前反轉成閱讀順序。span 與實體數是 W4 控制平面
    事故詳情頁用琥珀底標出遮蔽處的唯一資料來源 —— 沒有它,「脫敏有沒有
    真的生效」在畫面上就是看不到的。
    """
    r = requests.post(
        f"{PRESIDIO_URL}/analyze",
        json={"text": text, "language": "en",
              "ad_hoc_recognizers": [TW_ID_RECOGNIZER]},
        timeout=15,
    )
    r.raise_for_status()
    ents = sorted(r.json(), key=lambda x: -x["start"])
    spans = []
    for e in ents:
        token = f"[{e['entity_type']}]"
        text = text[: e["start"]] + token + text[e["end"]:]
        spans.append({"start": e["start"], "end": e["start"] + len(token),
                      "type": e["entity_type"]})
    return text, list(reversed(spans)), len(ents)


def looks_like_injection(text):
    """關鍵字黑名單。這是最低限度的攔截,不是完整防護 —— 見任務 4.2。"""
    low = text.lower()
    return any(k in low for k in INJECTION_KEYWORDS)


# ---------- K8s:把告警 label 解析成真正的 Deployment ----------
def _deployment_from_pod(pod):
    for ref in pod.metadata.owner_references or []:
        if ref.kind == "ReplicaSet":
            rs = apps_v1.read_namespaced_replica_set(ref.name, NAMESPACE)
            for owner in rs.metadata.owner_references or []:
                if owner.kind == "Deployment":
                    return owner.name
    return None


def _deployment_from_pod_name(name):
    match = re.match(r"^(.+)-[a-f0-9]{9,10}-[a-z0-9]{5}$", name or "")
    if not match:
        return None
    candidate = match.group(1)
    try:
        apps_v1.read_namespaced_deployment(candidate, NAMESPACE)
        return candidate
    except Exception:
        return None


def resolve_deployment(name):
    """把 Alertmanager 的 service identity 收斂成 Deployment 名。

    三種輸入都接得住：
      1. HighErrorRate 常帶 Kubernetes Service 名；若 Service/Deployment 同名直接命中。
      2. PodNotReady / PodCrashLooping 帶 Pod 名，沿 Pod → ReplicaSet → Deployment。
      3. 若 Service 名與 Deployment 不同，讀 Service selector 找任一 Pod，再沿 ownerReference 回推。

    找不到時原樣回傳，後面的 service_catalog 保守預設會把未知服務降成 notify_only。
    """
    try:
        apps_v1.read_namespaced_deployment(name, NAMESPACE)
        return name
    except Exception:
        pass

    try:
        pod = core_v1.read_namespaced_pod(name, NAMESPACE)
        dep = _deployment_from_pod(pod)
        if dep:
            return dep
    except Exception:
        pass

    dep = _deployment_from_pod_name(name)
    if dep:
        return dep

    try:
        svc = core_v1.read_namespaced_service(name, NAMESPACE)
        selector = svc.spec.selector or {}
        if selector:
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
            pods = core_v1.list_namespaced_pod(
                NAMESPACE, label_selector=label_selector).items
            for pod in pods:
                dep = _deployment_from_pod(pod)
                if dep:
                    return dep
    except Exception as exc:
        log.warning("resolve_deployment(%s) failed: %s", name, exc)
    return name


def fetch_logs(deployment, tail_lines=100, previous=False):
    """用 Deployment 自己的 selector 找 Pod,不猜 label。

    v6.1:tail_lines 從 100 提高到 500,並新增 previous 參數 ——
    previous=True 時讀取上一個容器實例的日誌,對『探針已經重啟過
    一次』的情況特別有用,因為原本較短的窗口讀不到重啟前的最後狀態。

    這是判讀當下的即時讀取,不是日誌儲存系統。歷史查詢由
    build_log_query_url() 提供的深連結交給專門的日誌系統負責,
    見任務 5.0 / 3.2 的說明。
    """
    try:
        dep = apps_v1.read_namespaced_deployment(deployment, NAMESPACE)
        sel = ",".join(f"{k}={v}"
                       for k, v in (dep.spec.selector.match_labels or {}).items())
        pods = core_v1.list_namespaced_pod(NAMESPACE, label_selector=sel).items
        if not pods:
            return f"no pods found for deployment {deployment}"
        return core_v1.read_namespaced_pod_log(
            pods[0].metadata.name, NAMESPACE,
            tail_lines=tail_lines, previous=previous)
    except Exception as exc:
        return f"log read failed for {deployment}: {exc}"


def fetch_events(deployment):
    """讀取與該 Deployment 相關的 Kubernetes Events(v6.1 新增)。

    為什麼這是投報率最高的一個補充:RBAC 從一開始就允許讀 events
    (任務 7.2 的 Role 已含 "events"),但 v5/v6 從未讀取過。Events
    直接寫明「為什麼」—— OOMKilling、FailedScheduling、探針失敗訊息、
    ImagePullBackOff —— 這些是日誌裡通常看不到的(容器被 OOM 殺掉時,
    日誌就是被截斷,不會有一行寫「我被 OOM 了」)。

    對照 ADR 5.0b:Events 是結構化記錄(reason/type/message/timestamp),
    來自 K8s API 本身而非應用程式的自由輸出,屬於「應該同步查詢」的
    那一類資料,與日誌的「只留連結」策略不衝突。
    """
    try:
        dep = apps_v1.read_namespaced_deployment(deployment, NAMESPACE)
        sel = ",".join(f"{k}={v}"
                       for k, v in (dep.spec.selector.match_labels or {}).items())
        pods = core_v1.list_namespaced_pod(NAMESPACE, label_selector=sel).items
        names = {p.metadata.name for p in pods} | {deployment}

        evts = core_v1.list_namespaced_event(NAMESPACE).items
        rows = []
        for e in evts:
            obj = e.involved_object
            if obj.name in names or (obj.name or "").startswith(deployment + "-"):
                rows.append((e.last_timestamp or e.event_time, e.type,
                             e.reason, (e.message or "")[:160]))
        rows.sort(key=lambda r: (r[0] is not None, r[0]), reverse=True)
        if not rows:
            return "(無相關 Kubernetes Events)"
        return "\n".join(
            f"[{at}] {event_type}/{reason}: {msg}"
            for at, event_type, reason, msg in rows[:15]
        )
    except Exception as exc:
        return f"event read failed: {exc}"


NODE_QUERIES = {
    "cpu_pct":       '100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
    "steal_pct":     'avg(rate(node_cpu_seconds_total{mode="steal"}[5m])) * 100',
    "mem_avail_pct": '100 * avg(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)',
    "load5":         'avg(node_load5)',
}


def promql_scalar(q):
    """單一純量 PromQL 查詢,失敗回 None 而非拋例外 ——
    節點/相依健康度是補充證據,查不到不該讓整次判讀失敗。"""
    try:
        r = requests.get(f"{PROM_URL}/api/v1/query",
                         params={"query": q}, timeout=8)
        r.raise_for_status()
        res = r.json().get("data", {}).get("result", [])
        return round(float(res[0]["value"][1]), 1) if res else None
    except Exception:
        return None


def query_node_health():
    """節點層狀態(v6.1 新增)。steal_pct 特別重要 ——
    它是 T 系列 EC2 CPU credit 耗盡的唯一內部徵兆(credit 餘額
    本身只在 CloudWatch,從 OS 裡面讀不到,見上一輪稽核 §4.1)。
    """
    vals = {k: promql_scalar(q) for k, q in NODE_QUERIES.items()}
    lines = [f"{k}={v}" for k, v in vals.items() if v is not None]
    if vals.get("steal_pct") and vals["steal_pct"] > 10:
        lines.append("警告:steal time 偏高,節點可能被 hypervisor 節流,"
                     "此時加機器或重啟通常無效")
    return " | ".join(lines) or "(節點指標讀取失敗)"


def query_dependency_health(deps):
    """相依服務健康度(v6.1 新增)。

    這是「DB 被鎖時誤判為 restart」的直接對策 —— 先讓模型看到
    上游的狀態,再讓它決定要不要動下游。deps 來自
    service_catalog.depends_on(見任務 3.2b)。

    v6.1.2:deps 為空時回傳明確的「無已知相依」而不是預設去查
    postgres —— 本階段五支示範服務並不連任何資料庫,硬查 postgres
    會把一份與該服務無關的證據餵進 prompt,反而誤導判讀。
    """
    if not deps:
        return "(此服務在目錄中沒有登記外部相依)"
    out = []
    for d in deps:
        # 一般 K8s 相依用 Pod Ready；Postgres 若已切到任務 11.2 RDS，
        # 叢集裡不再有 postgres-* Pod，不能把「查不到 Pod」誤當上游故障。
        if d == "postgres" and PGHOST != "postgres":
            ready = "managed-rds(n/a)"
        else:
            ready = promql_scalar(
                f'count(kube_pod_status_ready{{namespace="{NAMESPACE}",'
                f'condition="true",pod=~"{d}-.*"}} == 1)')
        extra = ""
        if d == "postgres":
            # 自架/RDS 都由 postgres_exporter 暴露 DB 內部狀態。
            # pg_locks_count 沒有 granted 維度，因此用 wait_event_type=Lock。
            lock_waiters = promql_scalar('sum(pg_stat_activity_count{wait_event_type="Lock"})')
            conns = promql_scalar('sum(pg_stat_activity_count)')
            longtx = promql_scalar('max(pg_stat_activity_max_tx_duration)')
            extra = f" lock_waiters={lock_waiters} conns={conns} longest_tx_sec={longtx}"
        out.append(f"{d}: ready={ready}{extra}")
    return " | ".join(out) or "(無相依資訊)"


def query_hpa_status(service):
    try:
        hpa = autoscaling_v2.read_namespaced_horizontal_pod_autoscaler(
            service, NAMESPACE)
    except ApiException as exc:
        if exc.status == 404:
            return f"{service}: hpa=none"
        return f"{service}: hpa_error={exc.status}"
    except Exception as exc:
        log.warning("HPA status query failed for %s: %s", service, exc)
        return f"{service}: hpa_error={type(exc).__name__}"

    status = hpa.status
    spec = hpa.spec
    conditions = []
    for cond in status.conditions or []:
        conditions.append(
            f"{cond.type}={cond.status}"
            + (f"({cond.reason})" if cond.reason else "")
        )

    metrics = []
    for metric in status.current_metrics or []:
        if metric.type == "Resource" and metric.resource:
            current = metric.resource.current
            value = current.average_utilization
            if value is None and current.average_value:
                value = current.average_value
            metrics.append(f"{metric.resource.name}={value}")

    return (
        f"{service}: hpa=current={status.current_replicas} "
        f"desired={status.desired_replicas} min={spec.min_replicas} "
        f"max={spec.max_replicas} metrics={','.join(map(str, metrics)) or 'none'} "
        f"conditions={','.join(conditions) or 'none'}"
    )


def build_log_query_url(template, service):
    """組出日誌查詢深連結,供通知信件與(未來)W4 UI 使用。

    v6.1 新增。刻意用 urllib.parse.quote() 而非手刻字串插值 ——
    服務名或查詢語法裡的特殊字元(空白、冒號、花括號)未編碼會
    破壞 URL 結構,在組 CloudWatch/Grafana 深連結時尤其常見。
    """
    if not template:
        return None
    from urllib.parse import quote
    return template % quote(service)


# ---------- 綁定點四:LiteLLM + Hybrid RAG ----------
def embed(text):
    r = requests.post(
        f"{LITELLM_URL}/v1/embeddings",
        headers={"Authorization": f"Bearer {LITELLM_KEY}"},
        json={"model": "embed", "input": text},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["data"][0]["embedding"]


_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{3,23}")
_STOPWORDS = {
    "info", "warn", "warning", "error", "debug", "trace", "level", "time",
    "true", "false", "null", "none", "http", "https", "request", "response",
    "message", "logger", "thread", "class", "java", "python", "main", "with",
    "from", "this", "that", "have", "been", "will", "when", "then", "your",
}


def keyword_query(text, alertname, limit=10):
    """從日誌抽出檢索關鍵詞,以 OR 串成 websearch_to_tsquery 可吃的字串。

    v6 修正:v5 傳的是服務名,導致稀疏那一路搜錯目標,RRF 實質退化成
    純向量檢索且不報錯。而直接傳整段日誌會更糟 —— plainto_tsquery 會把
    所有詞 AND 起來,結果恆為空集合。必須抽少量高訊息量的詞並以 OR 串接。
    """
    seen, out = set(), []
    for tok in _TOKEN_RE.findall(text or ""):
        low = tok.lower()
        if low in _STOPWORDS or low in seen:
            continue
        seen.add(low)
        out.append(low)
        if len(out) >= limit:
            break
    alert_low = (alertname or "").lower()
    if alert_low and alert_low not in seen:
        out.append(alert_low)
    return " OR ".join(out) if out else (alertname or "")


HYBRID_SQL = """
WITH vec AS (
  SELECT id, ROW_NUMBER() OVER (ORDER BY embedding <=> CAST(%(v)s AS vector)) AS rnk
  FROM incidents
  WHERE embedding IS NOT NULL AND outcome IN ('verified','human')
  ORDER BY embedding <=> CAST(%(v)s AS vector) LIMIT 20
),
kw AS (
  SELECT id, ROW_NUMBER() OVER (
           ORDER BY ts_rank(summary_tsv,
                            websearch_to_tsquery('english', %(q)s)) DESC) AS rnk
  FROM incidents
  WHERE summary_tsv @@ websearch_to_tsquery('english', %(q)s)
    AND outcome IN ('verified','human')
  LIMIT 20
)
SELECT i.service, i.summary, i.resolution,
       (COALESCE(1.0/(60+vec.rnk),0) + COALESCE(1.0/(60+kw.rnk),0))
       * POWER(0.5, EXTRACT(EPOCH FROM (now() - i.created_at)) / (30 * 86400))
       * i.trust_weight AS score                       -- v7 新增,見下方說明
FROM incidents i
LEFT JOIN vec ON vec.id = i.id
LEFT JOIN kw  ON kw.id  = i.id
WHERE vec.id IS NOT NULL OR kw.id IS NOT NULL
ORDER BY score DESC LIMIT 3;
"""


def hybrid_search(keywords, vec):
    """v7 修正:`HYBRID_SQL` 的 score 到 v6 為止從未讀取 `trust_weight`——

    任務 3.2 種子資料把它設成預設值,任務 10.4 的人工補寫刻意把它調高到
    2.0,並稱人工補寫是「知識庫自我增長的真正來源」。但那個 2.0 從來
    沒有影響過任何檢索結果:`trust_weight` 是一個寫進去、從來沒被讀出來
    的欄位。上面的 `* i.trust_weight` 是這個落差的修法——一行,但少了
    它,任務 10.4 那句話裡的「真正來源」四個字就是不成立的。
    """
    vector_literal = "[" + ",".join(str(x) for x in vec) + "]"
    with closing(db()) as conn, conn, conn.cursor() as cur:
        cur.execute(HYBRID_SQL, {"v": vector_literal, "q": keywords})
        return cur.fetchall()


def call_llm(prompt, schema=None):
    """走 LiteLLM,並以 OTel GenAI semconv 記錄。

    v6 兩處變更:
      1. 追蹤改用 OTel 標準屬性,不綁任何廠商 SDK
      2. span 用 context manager —— v5 需要手動在例外路徑補 gen.end(),
         那是靠紀律維持的正確性;with 區塊讓它變成結構上必然

    v7 變更:回傳值從純文字改成 dict,多帶 token 用量、模型名與成本 ——
    這些 v6 只寫進 OTel span 屬性,而 span 是暫態的(任務 10 刻意不備份
    trace),隔天就查不到了。取不到成本時回 None,絕不回 0 —— $0.0000
    會讓人以為判讀不用錢,None 對應「成本未知」,兩者傳達的意思完全相反。
    """
    with tracer.start_as_current_span(f"{sc.OP_CHAT} judge") as span:
        span.set_attribute(sc.ATTR_OPERATION, sc.OP_CHAT)
        span.set_attribute(sc.ATTR_PROVIDER, "aws.bedrock")
        span.set_attribute(sc.ATTR_REQ_MODEL, "judge")

        body = {"model": "judge",
                "messages": [{"role": "user", "content": prompt}]}
        if schema is not None:
            body["response_format"] = schema

        r = requests.post(
            f"{LITELLM_URL}/v1/chat/completions",
            headers={"Authorization": f"Bearer {LITELLM_KEY}"},
            json=body, timeout=60,
        )
        if not r.ok:
            log.error("LiteLLM chat failed: status=%s body=%s",
                      r.status_code, r.text[:1000])
        r.raise_for_status()
        data = r.json()
        usage = data.get("usage", {}) or {}
        hidden = data.get("_hidden_params", {}) or {}   # LiteLLM 的成本欄位
        cost = hidden.get("response_cost")               # 未驗證,見文末〈仍未驗證的部分〉

        span.set_attribute(sc.ATTR_IN_TOKENS, usage.get("prompt_tokens", 0))
        span.set_attribute(sc.ATTR_OUT_TOKENS, usage.get("completion_tokens", 0))
        span.set_attribute(sc.ATTR_RESP_MODEL, data.get("model", "unknown"))
        if cost is not None:
            span.set_attribute("w3.gen_ai.cost_usd", cost)   # 自訂屬性,w3. 前綴

        return {
            "content": data["choices"][0]["message"]["content"],
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "model": data.get("model", "unknown"),
            "cost_usd": cost,
        }


JSON_RE = re.compile(r"\{.*\}", re.S)
STRICTER = (
    "\n\n嚴格要求:只輸出一個 JSON 物件,不要任何說明文字或 markdown 圍欄。"
    "欄位為 action(只能是 restart/rollback/notify_only)、service、reason。"
    "不要輸出 scale 或 replicas；replicas 由 Kubernetes HPA 管理。"
)


def extract_json(raw):
    m = JSON_RE.search(raw or "")
    if not m:
        raise json.JSONDecodeError("no json object found", raw or "", 0)
    return m.group(0)


def decide(prompt, retries=2):
    """取得一個經過驗證的 RemediationAction,以及這次判讀的用量資訊。

    可攜性設計:USE_STRUCTURED=false 時完全走 prompt + 解析路徑。
    換到不支援 json_schema 的底層(例如某些 Ollama 模型)只需改環境變數,
    程式碼不動 —— 這正是綁定點四要示範的東西。

    v7 變更:call_llm() 回傳形狀從純文字改成 dict,這裡同步接住;
    函式回傳 (act, llm) 兩個值,llm 帶著最後一次成功呼叫的用量與成本,
    供 diagnose() 寫進 incident_steps 的 judged 步驟。
    """
    fmt = response_format() if USE_STRUCTURED else None
    llm = call_llm(prompt, schema=fmt)
    raw = llm["content"]
    for attempt in range(retries + 1):
        try:
            payload = raw if USE_STRUCTURED else extract_json(raw)
            act = RemediationAction(**json.loads(payload))
            return act, llm
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            log.warning("parse failed (attempt %d): %s", attempt, exc)
            if attempt >= retries:
                break
            try:
                # 結構化都失敗了,代表 gateway/模型端有問題,退回非結構化路徑
                llm = call_llm(prompt + STRICTER, schema=None)
                raw = llm["content"]
            except Exception:
                break
    act = RemediationAction(action="notify_only", service="unknown",
                            reason="schema validation failed after retries")
    return act, llm


# ---------- 修復與驗證 ----------
def still_firing(alertname, alert_service):
    """動手前重新查一次 Prometheus,確認「同一件服務」的問題還在。

    不能只用 alertname。HighErrorRate / PodNotReady 可能同時有多支服務
    firing；若只查 alertname，A 已恢復但 B 還在 firing 時，A 會被誤判成
    「仍在告警」而繼續修復。這裡使用 Alertmanager 原始 `service` label，
    不使用 resolve_deployment() 後的名稱——PodNotReady 的 service label
    本來就是 Pod 名，改成 Deployment 名反而會匹配不到原告警。
    """
    q = (
        'ALERTS{alertname=' + json.dumps(alertname) +
        ',alertstate="firing",service=' + json.dumps(alert_service) + '}'
    )
    try:
        r = requests.get(f"{PROM_URL}/api/v1/query",
                         params={"query": q}, timeout=10)
        r.raise_for_status()
        return bool(r.json().get("data", {}).get("result", []))
    except Exception as exc:
        log.warning("still_firing check failed: %s", exc)
        return False          # 查不到就不動手 —— fail closed


def remediate(act):
    if act.action == "notify_only":
        return False
    if act.action == "restart":
        apps_v1.patch_namespaced_deployment(
            act.service, NAMESPACE,
            {"spec": {"template": {"metadata": {"annotations": {
                "kubectl.kubernetes.io/restartedAt":
                    time.strftime("%Y-%m-%dT%H:%M:%SZ")}}}}})
        return True
    if act.action == "rollback":
        # 防禦性保底：正常流程在 guarded 階段就已把 rollback 改成 notify_only。
        # 若未來某條新路徑繞過 guard，這裡仍拒絕直接執行高風險動作。
        log.warning("rollback reached remediate() unexpectedly; refusing")
        return False
    return False


def verify(deployment, wait=None, incident_id=None):
    """修復後驗證:等 wait 秒,確認 Deployment 新版 rollout 已完成。

    只看「至少有 Pod Ready」會把舊 ReplicaSet 的健康 Pod 誤判成修復成功。
    任務 8.2 這類 GitOps spec 仍然故障的場景,舊 Pod 可能繼續服務,
    但新版 ReplicaSet 正在 CrashLoop;這必須判定為 failed。

    v7 新增 incident_id:由這個函式自己寫時間軸的 verified 步驟,而不是
    在 diagnose() 裡重組同一份 PromQL 再存一次 —— 那會讓查詢字串在兩個
    地方各存一份,改了一邊忘了另一邊時,畫面顯示的查詢會與實際跑的不同,
    而那種錯誤沒有任何方式能被自動偵測到。
    """
    waited = VERIFY_WAIT if wait is None else wait
    time.sleep(waited)
    detail = {"waited_seconds": waited}
    try:
        dep = apps_v1.read_namespaced_deployment(deployment, NAMESPACE)
        desired = dep.spec.replicas or 1
        status = dep.status
        conditions = {c.type: c for c in (status.conditions or [])}
        progressing = conditions.get("Progressing")
        available_cond = conditions.get("Available")
        observed = status.observed_generation or 0
        generation = dep.metadata.generation or 0
        updated = status.updated_replicas or 0
        ready = status.ready_replicas or 0
        available = status.available_replicas or 0
        unavailable = status.unavailable_replicas or 0

        detail.update({
            "desired_replicas": desired,
            "generation": generation,
            "observed_generation": observed,
            "updated_replicas": updated,
            "ready_replicas": ready,
            "available_replicas": available,
            "unavailable_replicas": unavailable,
            "progressing_status": getattr(progressing, "status", None),
            "progressing_reason": getattr(progressing, "reason", None),
            "available_status": getattr(available_cond, "status", None),
        })
        ok = (
            observed >= generation and
            updated >= desired and
            ready >= desired and
            available >= desired and
            unavailable == 0 and
            getattr(progressing, "status", None) != "False"
        )
    except Exception as exc:
        log.warning("verify failed: %s", exc)
        detail["error"] = str(exc)
        ok = False
    detail["passed"] = ok
    step(incident_id, "verified", detail)
    return ok


def notify_owner(meta, service, subject, body, escalate=False):
    """依服務目錄路由通知。v5 永遠寄給同一個寫死的地址。

    v6.1:若服務目錄有 log_query_url_template,信件附上『查完整日誌』
    的深連結 —— 這是本文件對日誌採取的策略(不儲存,只留連結)
    在通知路徑上的落地,見任務 3.2 / 5.0 的說明。
    """
    to = [meta.get("owner_email") or ALERT_EMAIL]
    if escalate and meta.get("escalation_email"):
        to.append(meta["escalation_email"])
    log_url = build_log_query_url(meta.get("log_query_url_template"), service)
    if log_url:
        body = f"{body}\n\n完整日誌:{log_url}"
    try:
        ses.send_email(
            Source=ALERT_EMAIL,
            Destination={"ToAddresses": to},
            Message={"Subject": {"Data": subject},
                     "Body": {"Text": {"Data": body}}},
        )
    except Exception as exc:
        log.error("SES send failed: %s", exc)


def build_prompt(service, alertname, logs, similar, meta,
                 events="", node="", deps="", hpa=""):
    """組出送給模型的 prompt。

    v6.1:新增 events / node / deps 三個參數(皆選填,預設空字串以維持
    向後相容 —— 任務 9 evaluated 沿用舊呼叫方式仍可運作)。這三項是
    固定的證據包(方案 A),不是讓模型自己決定查什麼(方案 B) ——
    延續本文件一貫的可預測 token 成本、可完整脫敏、無迴圈失控風險
    的設計立場。

    v10.5:新增 hpa 證據,replicas 由 Kubernetes HPA 管理,AI 不再做 scale。
    """
    hist = "\n".join(f"- {s}: {sm} -> {r}"
                     for s, sm, r, _ in similar) or "(無相似歷史事故)"
    deploy_hint = ""
    if meta.get("last_deploy_at"):
        deploy_hint = (f"\n最近一次部署:{meta['last_deploy_at']:%Y-%m-%d %H:%M UTC}。"
                       f"若告警發生在部署後不久,rollback 的可能性提高。")
    runbook = (f"\n該服務既有 runbook:{meta['runbook_url']}"
               if meta.get("runbook_url") else "")
    evidence = ""
    if node or deps or events or hpa:
        evidence = f"""
節點狀態:
{node or '(未查詢)'}

相依服務狀態:
{deps or '(未查詢)'}

HPA 狀態:
{hpa or '(未查詢)'}

Kubernetes Events(最近 15 筆,通常寫明了「為什麼」):
{events or '(未查詢)'}
"""
    return f"""你是 SRE 判讀助手。根據以下資訊決定修復動作。

告警:{alertname}
服務(Deployment 名):{service}{deploy_hint}{runbook}
{evidence}
最近日誌(已脫敏):
{logs[:2500]}

相似歷史事故與當時解法(僅列出已驗證有效的):
{hist}

重要判斷原則:
- replicas 由 Kubernetes HPA 管理。不要建議 scale,不要輸出 replicas。
- HPAMaxedOut、HPAScalingInactive 或 Pending/Unschedulable 屬容量或排程問題,
  應保留證據並 notify_only,交由平台/節點容量流程處理。
- 若相依服務(如 postgres)本身不健康(locks 高、長交易存在),
  重啟或擴容本服務通常無效,甚至會因為重建連線而加重上游負擔 ——
  這種情況應選 notify_only。
- 若節點 steal time 偏高,問題可能在基礎設施層而非應用層,
  加機器無效 —— 應選 notify_only。

只輸出一個 JSON 物件,不要任何其他文字:
{{"action": "restart|rollback|notify_only", "service": "{service}",
  "reason": "簡短理由"}}
不確定或風險高時,一律用 notify_only。"""


# ---------- 主流程 ----------
def diagnose(alert):
    """v7 變更:diagnose() 從「只寫結論」改成「寫下過程」。

    每一步都呼叫 step() 把中介結果存進 incident_steps —— 這些資料
    在 v6 全是區域變數,函式返回就消失,W4 控制平面的事故詳情頁
    完全沒有資料可顯示。事故列也從「結案時才 INSERT」改成「一開始
    就 INSERT、結案時 UPDATE」,讓「判讀中」第一次成為可查詢的狀態。
    """
    labels = alert.get("labels", {})
    alertname = labels.get("alertname", "unknown")
    # 保留 Alertmanager 原始 service label 給 still_firing() 精確回查。
    # PodNotReady 的 service label 是 Pod 名；resolve_deployment() 之後才是 Deployment 名。
    alert_service = labels.get("service") or labels.get("pod") or "unknown"
    raw_name = alert_service
    service = resolve_deployment(raw_name)
    meta = lookup_service(service)
    started_at = labels.get("startsAt") or alert.get("startsAt")

    if in_cooldown(alertname, service):
        # v7:被冷卻擋下也要留痕跡。v6 這裡是 log.info() 後直接 return——
        # 連 OTel span 都不開,這條決定在整套系統裡不留任何痕跡,唯一的
        # 紀錄是 Pod stdout,明天重建叢集就消失。建一列只有一格「queued」
        # 的事故,不呼叫模型,讓這條路徑第一次變得看得見。
        iid = open_incident(alertname, service, None, started_at)
        step(iid, "queued", {
            "cooldown": True, "cooldown_min": COOLDOWN_MIN,
            "note": "同告警同服務在冷卻窗內,未進入判讀"})
        close_incident(iid, status="skipped_cooldown", outcome="notify_only",
                       summary=f"[{alertname}] 冷卻窗內,未判讀",
                       resolution="skipped: cooldown")
        log.info("skip %s/%s: cooldown", alertname, service)
        return

    with tracer.start_as_current_span(f"{sc.OP_INVOKE_AGENT} diagnose") as root:
        root.set_attribute(sc.ATTR_OPERATION, sc.OP_INVOKE_AGENT)
        root.set_attribute(sc.ATTR_ALERTNAME, alertname)
        root.set_attribute(sc.ATTR_SERVICE, service)
        trace_id = format(root.get_span_context().trace_id, "032x")

        iid = open_incident(alertname, service, trace_id, started_at)
        step(iid, "queued", {"cooldown": False, "group_dedup": True,
                             "tier": meta["tier"],
                             "auto_remediate": meta["auto_remediate"]})
        try:
            # CrashLoop 最有價值的通常是「上一個已終止 container」的最後幾行。
            # previous log 不存在時 Kubernetes API 會報錯，這時再退回 current log。
            if alertname == "PodCrashLooping":
                raw_logs = fetch_logs(service, previous=True)
                if raw_logs.startswith("log read failed"):
                    raw_logs = fetch_logs(service)
            else:
                raw_logs = fetch_logs(service)
            raw_events = fetch_events(service)          # v6.1

            # 1. 應用層脫敏 + 注入檢查(綁九)
            # v6.1:Events 的 message 欄位可能包含探針回應內容,
            # 同樣是攻擊者可影響的文字,必須跟日誌走一樣的脫敏與檢查 ——
            # 不能因為 Events 是「結構化資料」就跳過這一步。
            clean, log_spans, log_ents = sanitize(raw_logs)
            clean_events, evt_spans, evt_ents = sanitize(raw_events)
            step(iid, "sanitized", {
                "entities_masked": log_ents + evt_ents,
                "masked_spans": log_spans,
                "excerpt": clean[:500],
                "log_query_url": build_log_query_url(
                    meta.get("log_query_url_template"), service)})
            step(iid, "events_collected", {"excerpt": clean_events[:800],
                                           "entities_masked": evt_ents})

            if looks_like_injection(clean) or looks_like_injection(clean_events):
                raise ValueError("suspected prompt injection, refused")

            # 1b. 固定證據包:節點狀態 + 相依服務健康度(v6.1,方案 A)
            node_ev = query_node_health()
            deps_ev = query_dependency_health(meta.get("depends_on"))
            hpa_ev = query_hpa_status(service)
            step(iid, "evidence_gathered", {
                "node": node_ev, "deps": deps_ev, "hpa": hpa_ev})

            # 2. Hybrid Search 檢索歷史(綁四)
            vec = embed(f"{alertname} {service}: {clean[:2000]}")
            kw = keyword_query(clean, alertname)
            log.info("hybrid keywords: %s", kw)
            similar = hybrid_search(kw, vec)
            # hybrid_search 回的是 tuple 串列(psycopg2 預設 cursor,沒有
            # 指定 cursor_factory),欄位順序來自 HYBRID_SQL 的 SELECT:
            # service, summary, resolution, score —— 沒有 id/outcome。
            step(iid, "retrieved", {
                "keyword_query": kw,
                "hit_count": len(similar),
                "hits": [{"service": r[0], "summary": (r[1] or "")[:120],
                          "resolution": (r[2] or "")[:120],
                          "score": round(float(r[3]), 4)} for r in similar]})

            # 3. 走 LiteLLM 判讀 + 結構化輸出約束(綁四)
            prompt = build_prompt(service, alertname, clean, similar, meta,
                                  events=clean_events, node=node_ev,
                                  deps=deps_ev, hpa=hpa_ev)
            act, llm = decide(prompt)
            step(iid, "judged", {
                "model": llm["model"], "input_tokens": llm["input_tokens"],
                "output_tokens": llm["output_tokens"],
                "cost_usd": llm["cost_usd"], "action": act.action,
                "reason": act.reason})

            # 4. 五道降級檢查。rollback 在核心 W3 尚未實作，必須在真正
            # 呼叫 remediate() 前就降成 notify_only；不能只讓 remediate()
            # return False 卻仍把 action="rollback" 寫進 remediation_log，否則
            # Overview/每週統計會把「根本沒執行」的 rollback 算成自動修復。
            guard = {"target_match": True, "l2_policy": None, "tier_policy": None,
                     "circuit_open": False, "still_firing": None,
                     "downgraded_to": None, "downgraded_by": None}

            if act.action != "notify_only" and act.service != service:
                guard["target_match"] = False
                guard["downgraded_to"], guard["downgraded_by"] = \
                    "notify_only", "target_mismatch"
                log.warning("model targeted %s but alert was %s; downgrading",
                            act.service, service)
                act = RemediationAction(action="notify_only", service=service,
                                        reason="model targeted a different service")
            elif act.action == "rollback":
                guard["l2_policy"] = "核心 W3 尚未實作 rollback；需走延伸 GitOps 核准"
                guard["downgraded_to"], guard["downgraded_by"] = \
                    "notify_only", "l2_not_implemented"
                act = RemediationAction(
                    action="notify_only", service=service,
                    reason="rollback 屬 L2；核心 W3 尚未實作，降級為通知")
            elif not meta["auto_remediate"] or meta["tier"] == 0:
                guard["tier_policy"] = f"tier-{meta['tier']},政策上不自動修復"
                guard["downgraded_to"], guard["downgraded_by"] = \
                    "notify_only", "tier_policy"
                act = RemediationAction(
                    action="notify_only", service=service,
                    reason=f"服務分級 tier-{meta['tier']},政策上不自動修復")
            elif circuit_open():
                guard["circuit_open"] = True
                guard["downgraded_to"], guard["downgraded_by"] = \
                    "notify_only", "circuit_breaker"
                act = RemediationAction(
                    action="notify_only", service=service,
                    reason=f"斷路器開啟:{CIRCUIT_WINDOW_MIN} 分鐘內已達修復上限")
            elif act.action != "notify_only":
                # 只有真的準備動手時才查 still_firing；模型原本就選 notify_only
                # 時這個檢查是「未執行」，必須保留 None，不能偽造成 True。
                if not still_firing(alertname, alert_service):
                    guard["still_firing"] = False
                    guard["downgraded_to"], guard["downgraded_by"] = \
                        "notify_only", "alert_resolved"
                    act = RemediationAction(action="notify_only", service=service,
                                            reason="告警已自行恢復,不需修復")
                else:
                    guard["tier_policy"] = f"tier {meta['tier']} + 自動修復已啟用"
                    guard["still_firing"] = True
            # act.action 本來就是 notify_only：五道 guard 沒有需要再做 still_firing。
            # tier_policy / still_firing 維持 None，表示「未執行」，不是通過。
            # 但不論模型把 service 寫成 unknown、Pod 名或其他字串，這筆事故的
            # 稽核 service 都必須回到前面已 resolve 的 Deployment，否則 incidents
            # 與 remediation_log 會對同一件事故記成兩個服務名稱。
            if act.action == "notify_only" and act.service != service:
                act = RemediationAction(action="notify_only", service=service,
                                        reason=act.reason)

            step(iid, "guarded", guard)

            # 5. 分級修復 + 驗證
            acted = remediate(act)
            if acted:
                step(iid, "remediated", {"action": act.action,
                                         "target": f"deploy/{service}"})
            ok = verify(service, incident_id=iid) if acted else None
            outcome = classify_outcome(acted, ok)

            root.set_attribute(sc.ATTR_ACTION, act.action)
            root.set_attribute(sc.ATTR_VERIFIED, bool(ok))

            # 6. 稽核與知識庫寫回(全部進 Postgres)
            log_remediation(alertname, act, ok, trace_id, incident_id=iid)
            close_incident(iid, status="closed", outcome=outcome,
                           summary=f"[{alertname}] {clean[:500]}",
                           resolution=f"{act.action}: {act.reason}", vec=vec)
            step(iid, "written_back", {"outcome": outcome,
                                       "in_rag": outcome in ("verified", "human")})

            if not acted or ok is False:
                notify_owner(
                    meta, service, f"[AIOps] {service} 需要人工介入",
                    f"alert={alertname}\naction={act.action}\n"
                    f"reason={act.reason}\nverified={ok}\ntrace={trace_id}",
                    escalate=(meta["tier"] <= 1))
            log.info("done %s/%s action=%s verified=%s outcome=%s",
                     alertname, service, act.action, ok, outcome)
        except Exception as exc:
            # v7:例外路徑刻意把事故留在 status='running',不改成 'failed'。
            # agent.py 可能在 step(iid, "failed", ...) 執行之前就被 K8s
            # 殺掉(OOM、節點驅逐),那種情況下這裡的 step() 根本沒機會跑。
            # W4 控制平面用「status='running' 且距上一步超過 5 分鐘」判定
            # 中斷(timeline_stale),同時涵蓋這兩種情況;'failed' 只涵蓋一種。
            step(iid, "failed", {"error": str(exc)[:300]})
            log.exception("diagnose failed for %s", service)
            notify_owner(meta, service, f"[AIOps] {service} 判讀流程異常",
                         f"alert={alertname},請查 ai-agent 日誌\ntrace={trace_id}")


def diagnose_group(payload):
    """v6:保留 Alertmanager 的分群結果,逐一判讀但共用一個 span 樹。

    Alertmanager 已用 group_by 做了關聯,v5 在 webhook handler 裡把它拆掉,
    等於丟掉整個 AIOps 流程裡最成熟的那一段能力。
    """
    alerts = payload.get("alerts", [])
    with tracer.start_as_current_span("alert_group") as span:
        span.set_attribute("w3.group.key", payload.get("groupKey", ""))
        span.set_attribute("w3.group.size", len(alerts))
        for alert in alerts:
            diagnose(alert)


def worker_loop():
    """單一常駐 worker。與 v5 的差別:
       - 工作在 Postgres 裡,Pod 重啟後會被重新取出(locked_at 逾時)
       - 同一時間只處理一件,天然限制並行修復數量
       - 可水平擴充到多 replica 而不會重複處理
    """
    while True:
        try:
            job = claim_one()
            if not job:
                time.sleep(5)
                continue
            job_id, payload, attempts = job
            if attempts > MAX_ATTEMPTS:
                log.error("job %s exceeded max attempts, marking failed", job_id)
                finish(job_id, False)
                continue
            diagnose_group(payload)
            finish(job_id, True)
        except Exception:
            log.exception("worker loop error")
            time.sleep(5)


@app.route("/alert", methods=["POST"])
def on_alert():
    """立刻回 200,工作排進 Postgres 佇列。"""
    payload = request.get_json(force=True, silent=True) or {}
    alerts = [a for a in payload.get("alerts", [])
              if a.get("status", "firing") == "firing"]
    if not alerts:
        return jsonify({"accepted": 0}), 200
    enqueue({"groupKey": payload.get("groupKey", ""),
             "commonLabels": payload.get("commonLabels", {}),
             "alerts": alerts})
    return jsonify({"accepted": len(alerts)}), 200


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/metrics")
def metrics():
    """最小化的 Prometheus 端點,只暴露佇列深度(任務 1.4 的告警規則用)。"""
    try:
        depth = queue_depth()
    except Exception:
        depth = -1
    return (f"# HELP ai_agent_queue_pending 待處理的告警群組數\n"
            f"# TYPE ai_agent_queue_pending gauge\n"
            f"ai_agent_queue_pending {depth}\n"), 200, \
           {"Content-Type": "text/plain; version=0.0.4"}


if __name__ == "__main__":
    threading.Thread(target=worker_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, threaded=True)
