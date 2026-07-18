"""SQLite 数据库模型 — peewee ORM"""

import os
import hashlib
from datetime import datetime
from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    TextField,
    DateTimeField,
    IntegerField,
    BooleanField,
    ForeignKeyField,
)

db_path = os.environ.get("DATABASE_PATH", "xinru.db")
os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
db = SqliteDatabase(db_path, pragmas={"journal_mode": "wal", "foreign_keys": 1})


class BaseModel(Model):
    class Meta:
        database = db


class Task(BaseModel):
    """一次扫描任务"""
    STATUS_CHOICES = [
        ("pending", "等待开始"),
        ("collecting", "收集源码中"),
        ("authenticating", "获取认证中"),
        ("auditing", "审计中"),
        ("verifying_chain", "攻击链验证中"),
        ("generating_report", "生成报告中"),
        ("paused", "已暂停(可恢复)"),
        ("completed", "已完成"),
        ("failed", "失败"),
        ("cancelled", "已取消"),
    ]

    target = CharField(max_length=2048)  # 目标 URL/域名（JSON 数组字符串）
    status = CharField(max_length=32, default="pending")

    # 粗粒度阶段：collecting/authenticating/auditing/verifying_chain/reporting/done
    phase = CharField(max_length=32, default="pending")
    pause_reason = TextField(null=True)

    # 启动配置 — 用户一次性填好，执行中不留交互
    config = TextField(null=True)  # JSON: {credentials, allow_register, allow_brute, subdomain, path_brute, ...}

    # 收集结果
    yakit_export_path = CharField(max_length=512, null=True)  # Yakit 导出数据路径
    yakit_flows_imported = IntegerField(default=0)
    total_files_collected = IntegerField(default=0)
    total_lines_audited = IntegerField(default=0)
    total_findings = IntegerField(default=0)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    completed_at = DateTimeField(null=True)

    def get_config(self) -> dict:
        """解析 config JSON"""
        import json
        try:
            return json.loads(self.config) if self.config else {}
        except json.JSONDecodeError:
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "status_label": dict(self.STATUS_CHOICES).get(self.status, self.status),
            "phase": self.phase,
            "pause_reason": self.pause_reason,
            "config": self.get_config(),
            "total_files_collected": self.total_files_collected,
            "total_lines_audited": self.total_lines_audited,
            "total_findings": self.total_findings,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class CollectedFile(BaseModel):
    """收集到的源码文件"""
    task = ForeignKeyField(Task, backref="files", on_delete="CASCADE")
    source_type = CharField(max_length=64)  # js_bundle / sourcemap / git_leak / backup / framework_ref / spider
    url = CharField(max_length=2048)  # 来源 URL
    local_path = CharField(max_length=1024)  # 本地存储路径
    file_name = CharField(max_length=512)
    file_size = IntegerField(default=0)
    line_count = IntegerField(default=0)
    content_hash = CharField(max_length=64, null=True, index=True)
    is_audited = BooleanField(default=False)
    audit_start_line = IntegerField(default=0)  # 审计到的行号（断点续扫）
    created_at = DateTimeField(default=datetime.now)


class Finding(BaseModel):
    """发现的漏洞"""
    SEVERITY_CHOICES = [
        ("critical", "🔴 严重"),
        ("high", "🔴 高危"),
        ("medium", "🟡 中危"),
        ("low", "🟢 低危"),
        ("info", "ℹ️ 信息"),
    ]

    task = ForeignKeyField(Task, backref="findings", on_delete="CASCADE")
    finding_number = IntegerField()  # 线索编号
    fingerprint = CharField(max_length=64, null=True, index=True)
    name = CharField(max_length=512)
    severity = CharField(max_length=32)
    file_path = CharField(max_length=1024)
    line_number = IntegerField()
    call_chain = TextField()  # JSON: 调用链
    api_endpoint = TextField()  # JSON: 接口信息
    parameters = TextField()  # JSON: 参数
    verdict = CharField(max_length=32)  # confirmed / excluded / uncertain
    yakit_evidence = TextField()  # JSON: Yakit 验证数据包列表
    attack_impact = TextField()
    fix_suggestion = TextField()
    created_at = DateTimeField(default=datetime.now)


class AttackChain(BaseModel):
    """攻击链端到端验证"""
    task = ForeignKeyField(Task, backref="attack_chains", on_delete="CASCADE")
    chain_number = IntegerField()
    name = CharField(max_length=512)
    involved_findings = TextField()  # JSON: 涉及的漏洞编号列表
    steps = TextField()  # JSON: 每步的请求+响应数据包
    final_verification = TextField()
    created_at = DateTimeField(default=datetime.now)


class ProgressLog(BaseModel):
    """进度日志"""
    task = ForeignKeyField(Task, backref="progress_logs", on_delete="CASCADE")
    message = TextField()
    log_type = CharField(max_length=32, default="info")  # info / warning / error / discovery / action_required
    created_at = DateTimeField(default=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "task_id": self.task_id,
            "message": self.message,
            "log_type": self.log_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class HumanLoopRequest(BaseModel):
    """Human-in-the-loop 请求"""
    STATUS_CHOICES = [
        ("pending", "等待回复"),
        ("approved", "已批准"),
        ("rejected", "已拒绝"),
        ("answered", "已回答"),
    ]

    task = ForeignKeyField(Task, backref="human_loops", on_delete="CASCADE")
    request_type = CharField(max_length=64)  # danger_confirm / captcha / ask_credentials / ask_cookie
    message = TextField()  # Agent 的问题
    options = TextField(null=True)  # JSON: 可选选项
    image_path = CharField(max_length=512, null=True)  # 验证码截图等
    status = CharField(max_length=32, default="pending")
    response = TextField(null=True)  # 用户回复
    created_at = DateTimeField(default=datetime.now)
    resolved_at = DateTimeField(null=True)

    def to_dict(self):
        return {
            "id": self.id,
            "task_id": self.task_id,
            "request_type": self.request_type,
            "message": self.message,
            "options": self.options,
            "image_path": self.image_path,
            "status": self.status,
            "response": self.response,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditLead(BaseModel):
    """审计中发现并需要补充收集/验证的 URL 线索。"""

    task = ForeignKeyField(Task, backref="audit_leads", on_delete="CASCADE")
    normalized_url = CharField(max_length=2048)
    original_url = CharField(max_length=2048)
    reason = TextField(default="")
    source_file = CharField(max_length=1024, default="")
    source_line = IntegerField(default=0)
    status = CharField(max_length=32, default="pending")
    created_at = DateTimeField(default=datetime.now)
    processed_at = DateTimeField(null=True)

    class Meta:
        indexes = (
            (("task", "normalized_url"), True),
        )


class WorkItem(BaseModel):
    """可恢复工作单元 — 崩溃重启后只重做未完成单元。"""

    STATUS_CHOICES = [
        ("pending", "待领取"),
        ("running", "执行中"),
        ("done", "已完成"),
        ("failed", "失败"),
        ("skipped", "跳过"),
    ]

    task = ForeignKeyField(Task, backref="work_items", on_delete="CASCADE")
    item_type = CharField(max_length=64)  # audit_file / collect_target / verify_endpoint / ...
    dedupe_key = CharField(max_length=255)
    status = CharField(max_length=32, default="pending", index=True)
    attempts = IntegerField(default=0)
    max_attempts = IntegerField(default=5)
    priority = IntegerField(default=100)  # 越小越优先
    locked_by = CharField(max_length=128, null=True)
    locked_until = DateTimeField(null=True)
    heartbeat_at = DateTimeField(null=True)
    payload_json = TextField(default="{}")
    result_json = TextField(null=True)
    error = TextField(null=True)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    started_at = DateTimeField(null=True)
    completed_at = DateTimeField(null=True)

    class Meta:
        indexes = (
            (("task", "dedupe_key"), True),
            (("task", "status", "priority"), False),
        )

    def get_payload(self) -> dict:
        import json
        try:
            return json.loads(self.payload_json) if self.payload_json else {}
        except json.JSONDecodeError:
            return {}

    def set_payload(self, payload: dict):
        import json
        self.payload_json = json.dumps(payload or {}, ensure_ascii=False)

    def get_result(self) -> dict:
        import json
        try:
            return json.loads(self.result_json) if self.result_json else {}
        except json.JSONDecodeError:
            return {}


def finding_fingerprint(
    file_path: str,
    line_number: int,
    name: str,
    api_endpoint: str = "",
) -> str:
    """生成稳定发现指纹，防止补收和恢复执行重复落库。"""
    payload = "\x00".join((
        os.path.normpath(file_path or ""),
        str(line_number),
        (name or "").strip().lower(),
        (api_endpoint or "").strip(),
    ))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _ensure_column(table: str, column: str, declaration: str):
    try:
        columns = {col.name for col in db.get_columns(table)}
    except Exception:
        return
    if column not in columns:
        db.execute_sql(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {declaration}')


def init_db():
    """初始化数据库，创建所有表"""
    opened_here = db.is_closed()
    db.connect(reuse_if_open=True)
    db.create_tables([
        Task,
        CollectedFile,
        Finding,
        AttackChain,
        ProgressLog,
        HumanLoopRequest,
        AuditLead,
        WorkItem,
    ])

    # Peewee create_tables 不会给旧表补字段，显式做轻量兼容迁移。
    _ensure_column("collectedfile", "content_hash", "VARCHAR(64)")
    _ensure_column("finding", "fingerprint", "VARCHAR(64)")
    _ensure_column("task", "phase", "VARCHAR(32) DEFAULT 'pending'")
    _ensure_column("task", "pause_reason", "TEXT")
    db.execute_sql(
        'CREATE INDEX IF NOT EXISTS "collectedfile_content_hash" '
        'ON "collectedfile" ("content_hash")'
    )
    db.execute_sql(
        'CREATE INDEX IF NOT EXISTS "finding_fingerprint" '
        'ON "finding" ("fingerprint")'
    )
    db.execute_sql(
        'CREATE INDEX IF NOT EXISTS "workitem_task_status_priority" '
        'ON "workitem" ("task_id", "status", "priority")'
    )

    if opened_here:
        db.close()
