import express from "express";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { seed } from "./seed.js";
import {
  states,
  matches,
  parseSbom,
  publicState,
  visibleProjects,
} from "./domain.js";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = process.env.DATA_DIR || path.join(root, "data");
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, "db.json");
let db = fs.existsSync(dbPath)
  ? JSON.parse(fs.readFileSync(dbPath, "utf8"))
  : seed();
function save() {
  const tmp = dbPath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, dbPath);
}
save();
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "3mb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  if (req.path.startsWith("/api/")) res.setHeader("Cache-Control", "no-store");
  next();
});
const roles = {
  security: "安全负责人",
  developer: "研发工程师",
  director: "IT 总监",
  sre: "运维工程师",
  pm: "产品经理",
};
const sessions = new Map();
app.get("/api/health", (_, res) => res.json({ ok: true, mode: "demo" }));
app.post("/api/session", (req, res) => {
  const role = req.body.role;
  if (!roles[role]) return res.status(400).json({ error: "无效角色" });
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { role, expires: Date.now() + 86400000 });
  res.cookie("vh_session", token, {
    httpOnly: true,
    sameSite: "strict",
    maxAge: 86400000,
    path: "/",
  });
  res.json({ role, name: roles[role], demo: true });
});
app.use("/api", (req, res, next) => {
  if (
    !["GET", "HEAD"].includes(req.method) &&
    req.headers.origin &&
    req.headers.origin !== `${req.protocol}://${req.get("host")}` &&
    !/^http:\/\/(127\.0\.0\.1|localhost):5173$/.test(req.headers.origin)
  )
    return res.status(403).json({ error: "请求来源不受信任" });
  const token = (req.headers.cookie || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("vh_session="))
    ?.slice(11);
  const session = sessions.get(token);
  if (!session || session.expires < Date.now())
    return res.status(401).json({ error: "演示会话已过期，请重新选择角色" });
  req.role = session.role;
  next();
});
const allow =
  (...permitted) =>
  (req, res, next) =>
    permitted.includes(req.role)
      ? next()
      : res.status(403).json({ error: "当前角色无权执行此操作" });
function audit(req, action) {
  db.audit.unshift({
    id: crypto.randomUUID(),
    action,
    actor: roles[req.role],
    at: new Date().toISOString(),
  });
  db.audit = db.audit.slice(0, 300);
  save();
}
app.get("/api/state", (req, res) =>
  res.json({
    ...publicState(db, req.role),
    user: { role: req.role, name: roles[req.role] },
  }),
);
app.post("/api/notify", allow("security"), (req, res) => {
  const v = db.vulnerabilities.find((v) => v.id === req.body.cveId);
  if (!v) return res.status(404).json({ error: "漏洞不存在" });
  let count = 0;
  db.projects.forEach((p) => {
    if (
      !p.components.some((c) => !c.managed && matches(c, v)) ||
      db.tasks.some((t) => t.cveId === v.id && t.projectId === p.id)
    )
      return;
    const now = new Date();
    db.tasks.push({
      id: "VH-" + crypto.randomUUID().slice(0, 8),
      cveId: v.id,
      projectId: p.id,
      status: "已通报",
      createdAt: now.toISOString(),
      dueAt: new Date(+now + 86400000).toISOString(),
      history: [
        { status: "已通报", at: now.toISOString(), actor: roles[req.role] },
      ],
    });
    count++;
  });
  audit(req, `为 ${v.id} 创建 ${count} 条站内通报（演示，不发送外部消息）`);
  res.json({ count });
});
app.patch("/api/tasks/:id", (req, res) => {
  if (!["security", "developer", "sre", "director"].includes(req.role))
    return res.status(403).json({ error: "无操作权限" });
  const t = db.tasks.find(
    (t) =>
      t.id === req.params.id &&
      visibleProjects(db, req.role).some((p) => p.id === t.projectId),
  );
  if (!t) return res.status(404).json({ error: "任务不存在" });
  const target = req.body.status;
  const next = states[states.indexOf(t.status) + 1];
  if (
    target !== next &&
    !(t.status === "已关闭" && target === "已确认" && req.body.reason?.trim())
  )
    return res
      .status(400)
      .json({ error: "请按流程推进；重新打开必须填写原因" });
  t.status = target;
  t.history.push({
    status: target,
    at: new Date().toISOString(),
    actor: roles[req.role],
    reason: req.body.reason || "",
  });
  if (target === "已关闭") t.closedAt = new Date().toISOString();
  else delete t.closedAt;
  audit(req, `${t.id} → ${target}`);
  res.json(t);
});
app.post("/api/feedback", (req, res) => {
  const { rating, text, tag, cveId } = req.body;
  if (
    !Number.isInteger(rating) ||
    rating < 1 ||
    rating > 5 ||
    typeof text !== "string" ||
    text.length > 2000 ||
    !["准确", "无效", "缺少信息"].includes(tag) ||
    !db.vulnerabilities.some((v) => v.id === cveId)
  )
    return res
      .status(400)
      .json({ error: "请填写有效评分和标签，评论不超过 2000 字" });
  db.feedback.unshift({
    id: crypto.randomUUID(),
    rating,
    text,
    tag,
    cveId,
    role: roles[req.role],
    createdAt: new Date().toISOString(),
  });
  audit(req, "提交报告反馈");
  res.json({ ok: true });
});
app.post("/api/projects/:id/sbom", allow("security", "sre"), (req, res) => {
  const p = visibleProjects(db, req.role).find(
    (p) => p.id === Number(req.params.id),
  );
  if (!p) return res.status(404).json({ error: "项目不存在" });
  try {
    const components = parseSbom(req.body.text, req.body.filename);
    p.components = components;
    p.updated = new Date().toLocaleString("zh-CN", {
      timeZone: "Asia/Shanghai",
    });
    audit(req, `导入 ${p.name} SBOM，${components.length} 个组件`);
    res.json({ count: components.length });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.post("/api/personas", allow("pm"), (req, res) => {
  const { role, pain, value } = req.body;
  if (!role?.trim() || !pain?.trim() || !value?.trim())
    return res.status(400).json({ error: "请完整填写角色、痛点和期望价值" });
  db.personas.push({
    id: crypto.randomUUID(),
    role: String(role).slice(0, 100),
    pain: String(pain).slice(0, 1000),
    value: String(value).slice(0, 1000),
    validated: false,
  });
  audit(req, "创建用户画像");
  res.json({ ok: true });
});
app.post("/api/factory", allow("pm"), (req, res) => {
  const themes = [
    [
      "跨项目差异化分析",
      "D-4",
      "研发工程师",
      "在报告中并列展示各项目组件版本、暴露面和升级路径。",
    ],
    [
      "托管组件责任边界",
      "O-3",
      "运维工程师",
      "显示服务提供商、责任方和人工核验入口。",
    ],
    [
      "分析报告可信度",
      "D-1",
      "安全负责人",
      "补充证据来源、人工复核状态和用户反馈。",
    ],
  ];
  const meaningful = db.feedback.filter((f) => f.text.trim().length >= 4);
  if (!meaningful.length)
    return res.status(400).json({ error: "暂无足够的有效反馈" });
  const rows = themes.map(([title, pain, role, suggestion], i) => ({
    id: `VOC-${i + 1}`,
    title,
    pain,
    role,
    suggestion,
    priority: i ? "P1" : "P0",
    status: "待评审",
    evidence: meaningful
      .filter((f) => f.role === role || i === 2)
      .map((f) => f.id),
    mode: "规则归类示例",
  }));
  db.requirements = rows;
  audit(req, "运行需求工厂：规则演示归类，未调用 LLM");
  res.json(rows);
});
app.patch("/api/requirements/:id", allow("pm"), (req, res) => {
  const r = db.requirements.find((r) => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "需求不存在" });
  r.status = "已纳入 Sprint";
  audit(req, `${r.id} 纳入 Sprint`);
  res.json(r);
});
app.post("/api/sources", allow("security"), (req, res) => {
  try {
    const url = new URL(req.body.url);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error();
    if (!req.body.name?.trim()) throw new Error();
    db.sources.push({
      id: crypto.randomUUID(),
      name: req.body.name.slice(0, 80),
      url: url.href,
      type: req.body.type === "RSS" ? "RSS" : "API",
      enabled: false,
    });
    audit(req, "保存自定义情报源配置（未连接）");
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "请填写名称和有效的 HTTP/HTTPS 地址" });
  }
});
app.post("/api/sync", allow("security"), (req, res) => {
  db.meta.lastSync = new Date().toISOString();
  audit(req, "演示情报刷新：重新计算本地 SBOM 关联，未请求外部源");
  res.json({ ok: true, mode: "demo" });
});
app.post("/api/agent", (req, res) => {
  const q = String(req.body.question || "").trim();
  if (!q || q.length > 1000)
    return res.status(400).json({ error: "请输入 1–1000 字问题" });
  const projects = visibleProjects(db, req.role);
  const cve = q.match(/CVE-\d{4}-\d+/i)?.[0].toUpperCase();
  const candidates = db.vulnerabilities.filter(
    (v) =>
      (!cve || v.id === cve) &&
      (!q.includes("超高危") || v.severity === "超高危"),
  );
  const rows = projects
    .filter(
      (p) =>
        (!q.includes("公网") || p.zone === "Public DMZ") &&
        candidates.some((v) =>
          p.components.some((c) => !c.managed && matches(c, v)),
        ),
    )
    .map((p) => ({
      name: p.name,
      zone: p.zone,
      servers: db.servers.filter((s) => s.projectId === p.id).length,
      cves: candidates
        .filter((v) => p.components.some((c) => !c.managed && matches(c, v)))
        .map((v) => v.id),
    }));
  res.json({
    mode: "结构化规则查询 · 未连接 LLM",
    answer: rows.length
      ? `在当前角色可见的资产中找到 ${rows.length} 个相关项目。服务器数量为项目部署规模，具体可利用性仍需人工核验。`
      : "未找到匹配结果。可以尝试查询完整 CVE 编号，或“哪些项目有公网暴露的超高危 CVE”。",
    rows,
  });
});
app.use("/api", (_, res) => res.status(404).json({ error: "接口不存在" }));
if (fs.existsSync(path.join(root, "dist"))) {
  app.use(express.static(path.join(root, "dist")));
  app.get("*", (_, res) => res.sendFile(path.join(root, "dist/index.html")));
}
app.use((err, req, res, next) => {
  console.error(err.message);
  res
    .status(err.status || 500)
    .json({
      error:
        err.status === 413
          ? "文件超过 3MB 限制"
          : "请求处理失败，请检查输入或服务器日志",
    });
});
const port = Number(process.env.PORT || 3001);
app.listen(port, "127.0.0.1", () =>
  console.log(`VunHunter server http://127.0.0.1:${port} · demo mode`),
);
