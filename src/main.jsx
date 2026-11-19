import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  LayoutDashboard,
  Radio,
  ScanLine,
  GitBranch,
  Network,
  FolderKanban,
  MessageSquare,
  Settings,
  ChevronDown,
  ChevronRight,
  Plus,
  Search,
  Bell,
  ArrowUpRight,
  ArrowDownRight,
  Download,
  RefreshCw,
  MoreHorizontal,
  Check,
  Clock,
  TriangleAlert,
  Activity,
  Server,
  Box,
  Globe,
  Layers,
  Sparkles,
  X,
  Send,
  ExternalLink,
  FileText,
  Upload,
  Star,
  CheckCheck,
  Maximize2,
  PanelRightClose,
  Filter,
  Target,
  Users,
  SlidersHorizontal,
  Command,
  Info,
  ShieldCheck,
  Workflow,
  Menu,
  CheckCircle2,
} from "lucide-react";
import "./styles.css";
import semver from "semver";
const icons = {
  dashboard: LayoutDashboard,
  intelligence: Radio,
  analysis: ScanLine,
  tracking: GitBranch,
  graph: Network,
  projects: FolderKanban,
  pm: MessageSquare,
  settings: Settings,
};
const titles = {
  dashboard: "安全态势总览",
  intelligence: "威胁情报中心",
  analysis: "漏洞智能分析",
  tracking: "修复跟踪",
  graph: "安全知识图谱",
  projects: "项目与资产",
  pm: "PM Toolkit",
  settings: "系统设置",
};
const roles = {
  security: "安全负责人",
  developer: "研发工程师",
  director: "IT 总监",
  sre: "运维工程师",
  pm: "产品经理",
};
const steps = ["已通报", "已确认", "修复中", "验证中", "已关闭"];
async function api(url, body, method) {
  const r = await fetch("/api" + url, {
    method: method || (body ? "POST" : "GET"),
    headers: { "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "请求失败");
  return d;
}
const hit = (p, v) =>
  p.components.some(
    (c) =>
      !c.managed &&
      c.name.toLowerCase() === v.component.toLowerCase() &&
      semver.coerce(c.version) &&
      semver.satisfies(semver.coerce(c.version), v.range),
  );
const fmt = (d) =>
  new Date(d).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
function riskGradient(vs) {
  if (!vs.length) return "#eef1f6";
  const a =
      (vs.filter((v) => v.severity === "超高危").length / vs.length) * 100,
    b = a + (vs.filter((v) => v.severity === "高危").length / vs.length) * 100;
  return `conic-gradient(#e76372 0 ${a}%, #f4a35b ${a}% ${b}%, #e5bd55 ${b}% 100%)`;
}
function Icon({ name, ...props }) {
  const C = icons[name] || Shield;
  return <C size={19} strokeWidth={1.8} {...props} />;
}
function Badge({ children, type }) {
  return (
    <span
      className={`badge ${type || { 超高危: "critical", 高危: "high", 中危: "medium", 低危: "low", 已关闭: "success", 修复中: "blue", 验证中: "purple", 已确认: "medium", 已通报: "muted" }[children] || "muted"}`}
    >
      {children}
    </span>
  );
}
function Empty({ text = "暂无数据" }) {
  return (
    <div className="empty">
      <ShieldCheck size={32} />
      <p>{text}</p>
    </div>
  );
}
function App() {
  const [db, setDb] = useState(null),
    [role, setRole] = useState(sessionStorage.getItem("vh-role") || "security"),
    [page, setPage] = useState(location.hash.slice(1) || "dashboard"),
    [error, setError] = useState(""),
    [toast, setToast] = useState(""),
    [search, setSearch] = useState(""),
    [project, setProject] = useState("all"),
    [period, setPeriod] = useState("7"),
    [agent, setAgent] = useState(false),
    [modal, setModal] = useState(null),
    [busy, setBusy] = useState(false),
    [mobile, setMobile] = useState(false);
  const notify = (s) => {
    setToast(s);
    setTimeout(() => setToast(""), 4500);
  };
  async function refresh() {
    setDb(await api("/state"));
  }
  useEffect(() => {
    (async () => {
      try {
        await api("/session", { role });
        await refresh();
        sessionStorage.setItem("vh-role", role);
        setError("");
      } catch (e) {
        setError(e.message);
      }
    })();
  }, [role]);
  useEffect(() => {
    const f = () => setPage(location.hash.slice(1) || "dashboard");
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  useEffect(() => {
    const f = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        document.getElementById("global-search")?.focus();
      }
      if (e.key === "Escape") {
        setModal(null);
        setSearch("");
      }
    };
    addEventListener("keydown", f);
    return () => removeEventListener("keydown", f);
  }, []);
  function nav(p) {
    location.hash = p;
    setPage(p);
    setSearch("");
    setMobile(false);
  }
  async function action(fn, msg) {
    setBusy(true);
    try {
      await fn();
      await refresh();
      if (msg) notify(msg);
    } catch (e) {
      notify(e.message);
    } finally {
      setBusy(false);
    }
  }
  const exportReport = () => {
    const rows = [
      ["项目", "业务级别", "组件数", "未关闭任务", "网络区域"],
      ...db.projects.map((p) => [
        p.name,
        `P${3 - p.criticality}`,
        p.components.length,
        db.tasks.filter((t) => t.projectId === p.id && t.status !== "已关闭")
          .length,
        p.zone,
      ]),
    ];
    const blob = new Blob(
      [
        "\uFEFF" +
          rows
            .map((r) =>
              r
                .map((c) => '"' + String(c).replaceAll('"', '""') + '"')
                .join(","),
            )
            .join("\r\n"),
      ],
      { type: "text/csv;charset=utf-8;" },
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "VunHunter-安全态势报告.csv";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    notify("安全态势报告已导出");
  };
  if (!db)
    return (
      <div className="loading">
        <div className="brand-mark">
          <Shield />
        </div>
        <h2>VunHunter</h2>
        <p>{error || "正在构建您的安全工作空间…"}</p>
        {error && <button onClick={() => location.reload()}>重新加载</button>}
      </div>
    );
  const projects = db.projects.filter(
    (p) => project === "all" || p.id === Number(project),
  );
  const tasks = db.tasks.filter((t) =>
    projects.some((p) => p.id === t.projectId),
  );
  const filtered = { ...db, projects, tasks };
  const visibleNav = [
    "dashboard",
    "intelligence",
    "analysis",
    "tracking",
    "graph",
    "projects",
    ...(role === "pm" ? ["pm"] : []),
  ];
  const activePage =
    page === "pm" && role !== "pm"
      ? "dashboard"
      : titles[page]
        ? page
        : "dashboard";
  const results = search.trim()
    ? db.vulnerabilities.filter((v) =>
        (v.id + " " + v.title + " " + v.component)
          .toLowerCase()
          .includes(search.toLowerCase()),
      )
    : [];
  return (
    <div className={`app ${agent ? "agent-open" : ""}`}>
      <aside className={`sidebar ${mobile ? "mobile-show" : ""}`}>
        <a className="brand" href="#dashboard">
          <span className="brand-mark">
            <Shield size={24} />
          </span>
          <span>
            Vun<span className="brand-light">Hunter</span>
            <small>SECURITY INTELLIGENCE</small>
          </span>
        </a>
        <button
          className="workspace"
          onClick={() => setModal({ type: "workspace" })}
        >
          <span className="workspace-icon">
            <Layers size={18} />
          </span>
          <span>
            星云科技<small>企业安全工作空间</small>
          </span>
          <ChevronDown size={15} />
        </button>
        <div className="nav-label">
          工作空间 <span>WORKSPACE</span>
        </div>
        <nav>
          {visibleNav.map((n) => (
            <button
              key={n}
              className={activePage === n ? "active" : ""}
              onClick={() => nav(n)}
            >
              <Icon name={n} />
              <span>{titles[n]}</span>
              {n === "intelligence" && <b className="nav-count">12</b>}
              {n === "tracking" && <span className="nav-dot" />}
              {n === "pm" && <span className="tiny">INTERNAL</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="engine-status">
            <span className="pulse" />
            <span>
              演示工作空间<small>本地数据 · 外部服务未连接</small>
            </span>
            <Activity size={17} />
          </div>
          <button
            className={
              activePage === "settings"
                ? "settings-link active"
                : "settings-link"
            }
            onClick={() => nav("settings")}
          >
            <Settings size={18} />
            系统设置
          </button>
          <div className="profile">
            <div className="avatar purple">林</div>
            <div>
              <b>林安</b>
              <select
                aria-label="切换演示角色"
                value={role}
                onChange={(e) => {
                  setRole(e.target.value);
                  setProject("all");
                  setModal(null);
                }}
              >
                {Object.entries(roles).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </div>
            <Chevrons />
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-toggle"
              onClick={() => setMobile(!mobile)}
              aria-label="展开导航"
            >
              <Menu size={20} />
            </button>
            <span>工作空间</span>
            <ChevronRight size={14} />
            <b>{titles[activePage]}</b>
          </div>
          <div className="top-actions">
            <div className="global-search">
              <Search size={16} />
              <input
                id="global-search"
                placeholder="搜索漏洞、组件…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <kbd>⌘ K</kbd>
              {search && (
                <div className="search-results">
                  <small>漏洞与组件</small>
                  {results.length ? (
                    results.slice(0, 6).map((v) => (
                      <button
                        key={v.id}
                        onClick={() => {
                          setModal({ type: "report", v });
                          setSearch("");
                        }}
                      >
                        <Shield size={16} />
                        <span>
                          {v.id}
                          <small>{v.title}</small>
                        </span>
                        <Badge>{v.severity}</Badge>
                      </button>
                    ))
                  ) : (
                    <p>没有找到匹配结果</p>
                  )}
                </div>
              )}
            </div>
            <span className="header-divider" />
            <button
              className="icon-button notification"
              aria-label="查看通知"
              onClick={() => setModal({ type: "notifications" })}
            >
              <Bell size={19} />
              <i />
            </button>
            <button
              className={`agent-toggle ${agent ? "selected" : ""}`}
              onClick={() => setAgent(!agent)}
            >
              <Sparkles size={16} />
              安全 Agent
            </button>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                {activePage === "dashboard"
                  ? "YOUR SECURITY, AT A GLANCE"
                  : "VUNHUNTER SECURITY OPERATIONS"}
              </div>
              <h1>
                {titles[activePage]}
                {activePage === "dashboard" && (
                  <span className="live-tag">
                    <span />
                    实时概览
                  </span>
                )}
              </h1>
              <p>
                {
                  {
                    dashboard:
                      "洞察威胁，聚焦风险。让每一个漏洞都有迹可循、有序闭环。",
                    intelligence:
                      "聚合多源威胁情报，基于企业 SBOM 识别真正相关的风险。",
                    analysis:
                      "把复杂漏洞转化为清晰、可信、可执行的项目级修复方案。",
                    tracking: "从通报到验证关闭，每一步都清晰可见。",
                    graph: "连接项目、组件、漏洞与基础设施，看清风险如何传递。",
                    projects:
                      "统一管理软件供应链与基础设施，建立完整的安全资产视图。",
                    pm: "让真实用户反馈推动产品持续进化。",
                    settings: "管理情报接入、工作空间权限与平台运行配置。",
                  }[activePage]
                }
              </p>
            </div>
            <div className="heading-actions">
              <button className="button" onClick={exportReport}>
                <Download size={16} />
                导出报告
              </button>
              {role === "security" && (
                <button
                  className="button primary"
                  disabled={busy}
                  onClick={() =>
                    action(
                      () => api("/sync", {}),
                      "本地关联已刷新。演示模式未连接外部情报源。",
                    )
                  }
                >
                  <RefreshCw size={16} className={busy ? "spin" : ""} />
                  刷新情报
                </button>
              )}
            </div>
          </div>
          <div className="filterbar">
            <div>
              <span className="filter-label">
                <FolderKanban size={15} />
                项目范围
              </span>
              <select
                aria-label="项目范围"
                value={project}
                onChange={(e) => setProject(e.target.value)}
              >
                <option value="all">全部项目</option>
                {db.projects.map((p) => (
                  <option value={p.id} key={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <span className="filter-divider" />
              <button
                className="date-picker"
                onClick={() => setPeriod(period === "7" ? "30" : "7")}
              >
                <Clock size={14} />
                最近 {period} 天<ChevronDown size={14} />
              </button>
            </div>
            <span className="last-update">
              数据集：演示环境 <span>·</span>{" "}
              {db.meta.lastSync
                ? `刷新于 ${fmt(db.meta.lastSync)}`
                : "快照 2026-11-19"}
              <Info size={14} />
            </span>
          </div>
          {activePage === "dashboard" && (
            <Dashboard
              db={filtered}
              period={period}
              nav={nav}
              open={setModal}
            />
          )}
          {activePage === "intelligence" && (
            <Intelligence db={filtered} open={setModal} />
          )}
          {activePage === "analysis" && (
            <Analysis db={filtered} open={setModal} />
          )}
          {activePage === "tracking" && (
            <Tracking
              db={filtered}
              open={setModal}
              action={action}
              role={role}
            />
          )}
          {activePage === "graph" && (
            <Graph db={filtered} open={setModal} ask={() => setAgent(true)} />
          )}
          {activePage === "projects" && (
            <Projects db={filtered} open={setModal} role={role} />
          )}
          {activePage === "pm" && (
            <PM db={db} open={setModal} action={action} />
          )}
          {activePage === "settings" && (
            <SettingsPage db={db} role={role} open={setModal} />
          )}
          <footer>
            <span>
              <Shield size={13} /> VunHunter · 让安全响应形成闭环
            </span>
            <span>
              演示环境 <i /> v1.0.0
            </span>
          </footer>
        </main>
      </div>
      {agent && (
        <Agent onClose={() => setAgent(false)} open={setModal} db={db} />
      )}
      {modal && (
        <Modal
          modal={modal}
          close={() => setModal(null)}
          db={db}
          role={role}
          action={action}
          notify={notify}
          refresh={refresh}
          busy={busy}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          <CheckCircle2 size={18} />
          {toast}
          <button onClick={() => setToast("")} aria-label="关闭提示">
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}
function Chevrons() {
  return <ChevronDown size={15} />;
}
function SectionHeader({ title, sub, action, children }) {
  return (
    <div className="section-head">
      <div>
        <h2>
          {title}
          {sub && <span>{sub}</span>}
        </h2>
      </div>
      {children || action}
    </div>
  );
}
function Sparkline({ color = "#5267ed", down = false }) {
  return (
    <svg className="sparkline" viewBox="0 0 110 38">
      <path
        d={
          down
            ? "M0 4 L10 8 L21 6 L32 17 L43 13 L54 21 L65 19 L76 30 L87 25 L99 31 L110 32"
            : "M0 33 L10 28 L21 31 L32 20 L43 24 L54 15 L65 19 L76 8 L87 13 L99 4 L110 6"
        }
        fill="none"
        stroke={color}
        strokeWidth="2.2"
      />
      <path
        d={
          down
            ? "M0 4 L10 8 L21 6 L32 17 L43 13 L54 21 L65 19 L76 30 L87 25 L99 31 L110 32 V38 H0Z"
            : "M0 33 L10 28 L21 31 L32 20 L43 24 L54 15 L65 19 L76 8 L87 13 L99 4 L110 6 V38 H0Z"
        }
        fill={color}
        opacity=".07"
      />
    </svg>
  );
}
function Dashboard({ db, period, nav, open }) {
  const active = db.tasks.filter((t) => t.status !== "已关闭"),
    closed = db.tasks.filter((t) => t.status === "已关闭");
  const overdue = active.filter((t) => new Date(t.dueAt) < Date.now());
  const applicable = db.vulnerabilities.filter((v) =>
    db.projects.some((p) => hit(p, v)),
  );
  const metrics = [
    {
      title: "待处置漏洞",
      value: applicable.length,
      unit: "个",
      detail: "已匹配当前项目 SBOM",
      icon: Shield,
      color: "indigo",
      trend: "聚焦真实风险",
    },
    {
      title: "超高危 / 高危",
      value: applicable.filter((v) => v.severity !== "中危").length,
      unit: "个",
      detail: `${applicable.filter((v) => v.severity === "超高危").length} 个超高危需优先处理`,
      icon: TriangleAlert,
      color: "red",
      trend: "优先处置",
    },
    {
      title: "平均修复时间",
      value: closed.length
        ? closed.filter((t) => t.closedAt).length
          ? Math.round(
              (closed
                .filter((t) => t.closedAt)
                .reduce(
                  (s, t) =>
                    s +
                    (new Date(t.closedAt) - new Date(t.createdAt)) / 3600000,
                  0,
                ) /
                closed.filter((t) => t.closedAt).length) *
                10,
            ) / 10
          : "18.6"
        : "—",
      unit: "小时",
      detail: "目标 < 24 小时",
      icon: Clock,
      color: "green",
      trend: "演示基线 18.6h",
    },
    {
      title: "修复闭环率",
      value: db.tasks.length
        ? Math.round((closed.length / db.tasks.length) * 100)
        : 0,
      unit: "%",
      detail: `${closed.length} / ${db.tasks.length} 项任务已完成`,
      icon: CheckCheck,
      color: "blue",
      trend: "完整流程追踪",
    },
  ];
  return (
    <>
      <div className="stats-grid">
        {metrics.map((m, i) => (
          <div className="stat-card" key={m.title}>
            <div className="stat-top">
              <span>{m.title}</span>
              <span className={`stat-icon ${m.color}`}>
                <m.icon size={18} />
              </span>
            </div>
            <div className="stat-value">
              {m.value}
              <small>{m.unit}</small>
            </div>
            <div className="stat-bottom">
              <div>
                <span className={`stat-trend ${i === 1 ? "danger-text" : ""}`}>
                  {i === 1 ? (
                    <TriangleAlert size={12} />
                  ) : (
                    <ArrowDownRight size={13} />
                  )}{" "}
                  {m.trend}
                </span>
                <p>{m.detail}</p>
              </div>
              <Sparkline
                color={i === 1 ? "#ed6a72" : i === 2 ? "#28a68b" : "#6878ec"}
                down={i !== 3}
              />
            </div>
          </div>
        ))}
      </div>
      {overdue.length > 0 && (
        <div className="alert-banner">
          <span className="alert-icon">
            <TriangleAlert size={19} />
          </span>
          <div>
            <b>有 {overdue.length} 项修复任务已超出 SLA</b>
            <span>请关注超期项目，及时协调负责人推进修复。</span>
          </div>
          <button onClick={() => nav("tracking")}>
            查看修复任务
            <ChevronRight size={15} />
          </button>
        </div>
      )}
      <div className="dashboard-grid">
        <section className="panel trend-panel">
          <SectionHeader title="漏洞态势趋势" sub="Vulnerability trend">
            <div className="legend">
              <span>
                <i className="legend-dot indigo-bg" />
                新增漏洞
              </span>
              <span>
                <i className="legend-dot green-bg" />
                已修复
              </span>
              <span className="chart-period">近{period}天</span>
            </div>
          </SectionHeader>
          <Trend period={period} />
          <div className="chart-foot">
            <span>
              <span className="tiny-dot" />
              演示趋势数据
            </span>
            <span>持续缩短风险暴露窗口，让修复快于威胁。</span>
          </div>
        </section>
        <section className="panel distribution">
          <SectionHeader title="漏洞风险分布" />
          <div className="donut-wrap">
            <div
              className="donut"
              style={{ background: riskGradient(applicable) }}
            >
              <div>
                <b>{applicable.length}</b>
                <span>关联漏洞总数</span>
              </div>
            </div>
            <div className="donut-key">
              {["超高危", "高危", "中危"].map((s, i) => (
                <div key={s}>
                  <span>
                    <i
                      style={{
                        background: ["#e76372", "#f4a35b", "#e5bd55"][i],
                      }}
                    />
                    {s}
                  </span>
                  <b>
                    {applicable.filter((v) => v.severity === s).length}
                    <small>个</small>
                  </b>
                </div>
              ))}
            </div>
          </div>
          <div className="risk-note">
            <ShieldCheck size={16} />
            <span>基于 SBOM 精准匹配，已排除托管组件</span>
          </div>
        </section>
        <section className="panel project-risk">
          <SectionHeader
            title="项目风险概览"
            sub={`${db.projects.length} 个项目`}
          >
            <button className="text-button" onClick={() => nav("projects")}>
              查看全部
              <ChevronRight size={14} />
            </button>
          </SectionHeader>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>项目名称</th>
                  <th>风险等级</th>
                  <th>
                    漏洞分布{" "}
                    <span className="risk-bars-label">
                      超高危 / 高危 / 中危
                    </span>
                  </th>
                  <th>修复进度</th>
                  <th>负责人</th>
                </tr>
              </thead>
              <tbody>
                {db.projects.map((p) => {
                  const vs = db.vulnerabilities.filter((v) => hit(p, v));
                  const ts = db.tasks.filter((t) => t.projectId === p.id);
                  const pct = Math.round(
                    (ts.filter((t) => t.status === "已关闭").length /
                      (ts.length || 1)) *
                      100,
                  );
                  return (
                    <tr key={p.id} onClick={() => open({ type: "project", p })}>
                      <td>
                        <div className="project-name">
                          <span
                            className="project-square"
                            style={{
                              background: p.color + "15",
                              color: p.color,
                            }}
                          >
                            <Box size={17} />
                          </span>
                          <span>
                            <b>{p.name}</b>
                            <small>{p.code}</small>
                          </span>
                        </div>
                      </td>
                      <td>
                        <Badge>
                          {vs.some((v) => v.severity === "超高危")
                            ? "超高危"
                            : "高危"}
                        </Badge>
                      </td>
                      <td>
                        <div className="severity-bars">
                          {["超高危", "高危", "中危"].map((s, i) => (
                            <span
                              key={s}
                              style={{
                                width:
                                  25 +
                                  vs.filter((v) => v.severity === s).length * 8,
                                background: ["#f8d5dc", "#fce3cf", "#f7edca"][
                                  i
                                ],
                                color: ["#c75969", "#c4864f", "#af963c"][i],
                              }}
                            >
                              {vs.filter((v) => v.severity === s).length}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <div className="progress-cell">
                          <div className="progress-track">
                            <i style={{ width: pct + "%" }} />
                          </div>
                          <span>{pct}%</span>
                        </div>
                      </td>
                      <td>
                        <span className="owner">
                          <span
                            className="avatar mini"
                            style={{
                              background: p.color + "18",
                              color: p.color,
                            }}
                          >
                            {p.initial}
                          </span>
                          {p.owner}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
        <section className="panel workflow-panel">
          <SectionHeader title="修复流程概览">
            <button className="text-button" onClick={() => nav("tracking")}>
              进入看板
              <ChevronRight size={14} />
            </button>
          </SectionHeader>
          <div className="workflow-total">
            <b>{db.tasks.length}</b>
            <span>项修复任务</span>
            <Badge type="success">端到端闭环</Badge>
          </div>
          <div className="workflow-stacked">
            {steps.map((s, i) => (
              <span
                key={s}
                style={{
                  flex: db.tasks.filter((t) => t.status === s).length || 0.1,
                  background: [
                    "#a8b4eb",
                    "#7e97e6",
                    "#657be2",
                    "#a18bdf",
                    "#52b59b",
                  ][i],
                }}
              />
            ))}
          </div>
          <div className="workflow-list">
            {steps.map((s, i) => (
              <button key={s} onClick={() => nav("tracking")}>
                <span>
                  <i
                    style={{
                      background: [
                        "#a8b4eb",
                        "#7e97e6",
                        "#657be2",
                        "#a18bdf",
                        "#52b59b",
                      ][i],
                    }}
                  />
                  {s}
                </span>
                <b>
                  {db.tasks.filter((t) => t.status === s).length}
                  <ChevronRight size={14} />
                </b>
              </button>
            ))}
          </div>
        </section>
        <section className="panel priority-panel">
          <SectionHeader title="优先关注情报" sub="按 VunHunter Score 排序">
            <button className="text-button" onClick={() => nav("intelligence")}>
              全部情报
              <ChevronRight size={14} />
            </button>
          </SectionHeader>
          {[...applicable]
            .sort((a, b) => b.score - a.score)
            .slice(0, 3)
            .map((v) => (
              <button
                className="priority-item"
                key={v.id}
                onClick={() => open({ type: "report", v })}
              >
                <span
                  className={`vuln-icon ${v.severity === "超高危" ? "red" : "orange"}`}
                >
                  <Shield size={19} />
                </span>
                <span className="priority-info">
                  <b>{v.title}</b>
                  <small>
                    <span className="mono">{v.id}</span>
                    <span>·</span>
                    {v.component}
                    <span>·</span>
                    {db.projects.filter((p) => hit(p, v)).length} 个受影响项目
                  </small>
                </span>
                <Badge>{v.severity}</Badge>
                <span className="score-pill">
                  {v.score}
                  <small>分</small>
                </span>
                <ChevronRight size={15} />
              </button>
            ))}
        </section>
        <section className="agent-card">
          <div className="agent-card-top">
            <span className="agent-symbol">
              <Sparkles size={22} />
            </span>
            <Badge type="purple">KNOWLEDGE GRAPH</Badge>
          </div>
          <h2>让风险关系，一目了然</h2>
          <p>
            关联项目、组件与基础设施，
            <br />
            沿着攻击路径找到真正的风险。
          </p>
          <div className="mini-network">
            <svg viewBox="0 0 240 55">
              <g stroke="#d9d2ee" fill="none">
                <path d="M20 30L80 10L139 32L208 12M20 30L84 48L139 32L216 47M80 10L84 48" />
              </g>
              {[
                [20, 30],
                [80, 10],
                [84, 48],
                [139, 32],
                [208, 12],
                [216, 47],
              ].map(([x, y], i) => (
                <circle
                  key={i}
                  cx={x}
                  cy={y}
                  r={i === 3 ? 8 : 5}
                  fill={i === 3 ? "#9a7bda" : "#ded5f1"}
                />
              ))}
            </svg>
          </div>
          <button className="button" onClick={() => nav("graph")}>
            <Network size={16} />
            探索安全知识图谱
            <ChevronRight size={15} />
          </button>
        </section>
      </div>
    </>
  );
}
function Trend({ period }) {
  const [hover, setHover] = useState(null);
  const a =
      period === "7"
        ? [18, 29, 23, 38, 32, 44, 35]
        : [38, 31, 42, 28, 35, 22, 18],
    b =
      period === "7"
        ? [10, 14, 12, 22, 25, 30, 34]
        : [12, 18, 26, 22, 29, 32, 36];
  const points = (arr) =>
    arr.map((v, i) => `${48 + i * 76},${180 - v * 3}`).join(" ");
  return (
    <div className="trend-chart">
      <svg
        viewBox="0 0 550 218"
        role="img"
        aria-label="演示漏洞新增与修复趋势折线图"
      >
        <defs>
          <linearGradient id="area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#6c7bea" stopOpacity=".16" />
            <stop offset="100%" stopColor="#6c7bea" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 15, 30, 45].map((n) => (
          <g key={n}>
            <text x="15" y={184 - n * 3}>
              {n}
            </text>
            <line
              x1="46"
              y1={180 - n * 3}
              x2="521"
              y2={180 - n * 3}
              stroke="#edf0f5"
              strokeDasharray="3 4"
            />
          </g>
        ))}
        <polygon points={`48,180 ${points(a)} 504,180`} fill="url(#area)" />
        <polyline
          points={points(a)}
          fill="none"
          stroke="#6979e9"
          strokeWidth="2.6"
          strokeLinejoin="round"
        />
        <polyline
          points={points(b)}
          fill="none"
          stroke="#41b59c"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />
        {a.map((v, i) => (
          <g
            key={i}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
          >
            <rect
              x={i * 76 + 25}
              y="20"
              width="60"
              height="168"
              fill="transparent"
            />
            <circle
              cx={48 + i * 76}
              cy={180 - v * 3}
              r="3.5"
              fill="white"
              stroke="#6979e9"
              strokeWidth="2"
            />
            <circle
              cx={48 + i * 76}
              cy={180 - b[i] * 3}
              r="3"
              fill="white"
              stroke="#41b59c"
              strokeWidth="2"
            />
            <text x={48 + i * 76} y="207" textAnchor="middle">
              {period === "7"
                ? `11/${13 + i}`
                : `${10 + Math.floor((20 + i * 4) / 30)}/${((20 + i * 4) % 30) + 1}`}
            </text>
            {hover === i && (
              <g>
                <rect
                  x={Math.min(390, 48 + i * 76)}
                  y="15"
                  width="128"
                  height="43"
                  rx="6"
                  fill="#17243a"
                />
                <text x={Math.min(400, 58 + i * 76)} y="32" fill="white">
                  新增 {v} · 修复 {b[i]}
                </text>
                <text x={Math.min(400, 58 + i * 76)} y="47" fill="#b2bfd4">
                  演示历史数据
                </text>
              </g>
            )}
          </g>
        ))}
      </svg>
    </div>
  );
}
function Intelligence({ db, open }) {
  const [severity, setSeverity] = useState("all"),
    [query, setQuery] = useState(""),
    [matched, setMatched] = useState(true),
    [sort, setSort] = useState("score");
  const rows = db.vulnerabilities
    .filter(
      (v) =>
        (severity === "all" || v.severity === severity) &&
        (!matched || db.projects.some((p) => hit(p, v))) &&
        (v.id + v.title + v.component)
          .toLowerCase()
          .includes(query.toLowerCase()),
    )
    .sort((a, b) =>
      sort === "score"
        ? b.score - a.score
        : new Date(b.published) - new Date(a.published),
    );
  return (
    <>
      <div className="source-strip">
        {db.sources.map((s, i) => (
          <div key={s.id}>
            <span
              className="source-logo"
              style={{
                color: ["#4d69ad", "#cc7761", "#354056", "#9d79c5"][i % 4],
              }}
            >
              {s.name === "GitHub Advisory" ? (
                <GitBranch size={19} />
              ) : (
                <Radio size={19} />
              )}
            </span>
            <div>
              <b>{s.name}</b>
              <small>
                {s.url ? "未连接 · 自定义配置" : "演示源 · 样例数据"}
              </small>
            </div>
            <Badge type={s.url ? "muted" : "success"}>
              {s.url ? "待配置" : "已载入"}
            </Badge>
          </div>
        ))}
      </div>
      <section className="panel">
        <div className="list-toolbar">
          <div className="tabs">
            <button
              className={matched ? "selected" : ""}
              onClick={() => setMatched(true)}
            >
              与我相关{" "}
              <b>
                {
                  db.vulnerabilities.filter((v) =>
                    db.projects.some((p) => hit(p, v)),
                  ).length
                }
              </b>
            </button>
            <button
              className={!matched ? "selected" : ""}
              onClick={() => setMatched(false)}
            >
              全部情报 <b>{db.vulnerabilities.length}</b>
            </button>
          </div>
          <div className="toolbar-controls">
            <label className="input-search">
              <Search size={16} />
              <input
                placeholder="搜索 CVE / 组件"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </label>
            <select
              aria-label="风险等级"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="all">全部风险等级</option>
              {["超高危", "高危", "中危"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <select
              aria-label="排序"
              value={sort}
              onChange={(e) => setSort(e.target.value)}
            >
              <option value="score">评分优先</option>
              <option value="time">发布时间</option>
            </select>
          </div>
        </div>
        <div className="table-scroll">
          <table className="intel-table">
            <thead>
              <tr>
                <th>漏洞 / 威胁情报</th>
                <th>风险等级</th>
                <th>VH Score</th>
                <th>受影响项目</th>
                <th>情报来源</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.id}>
                  <td>
                    <button
                      className="table-title"
                      onClick={() => open({ type: "report", v })}
                    >
                      <b>{v.title}</b>
                      <small>
                        <span className="mono">{v.id}</span>
                        <span> · </span>
                        {v.component} {v.range}
                      </small>
                    </button>
                  </td>
                  <td>
                    <Badge>{v.severity}</Badge>
                  </td>
                  <td>
                    <span
                      className={`score-number ${v.score > 85 ? "danger-text" : ""}`}
                    >
                      {v.score}
                      <small>/100</small>
                    </span>
                  </td>
                  <td>
                    <span className="project-chips">
                      {db.projects
                        .filter((p) => hit(p, v))
                        .slice(0, 2)
                        .map((p) => (
                          <span key={p.id}>{p.name}</span>
                        ))}
                      {!db.projects.some((p) => hit(p, v)) && (
                        <small>无匹配项目</small>
                      )}
                    </span>
                  </td>
                  <td>
                    <span className="source-cell">
                      {v.source}
                      <small>{fmt(v.published)}</small>
                    </span>
                  </td>
                  <td>
                    <button
                      className="text-button"
                      onClick={() => open({ type: "report", v })}
                    >
                      <Sparkles size={14} />
                      智能分析
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty text="当前筛选条件下没有相关情报" />}
        </div>
        <div className="table-footer">
          共 {rows.length} 条情报
          <span>
            样例漏洞描述与版本范围仅用于功能演示，生产使用前需核验公告。
          </span>
        </div>
      </section>
    </>
  );
}
function Analysis({ db, open }) {
  return (
    <>
      <div className="feature-banner">
        <span className="feature-icon">
          <Sparkles size={28} />
        </span>
        <div>
          <h2>从漏洞情报，到可执行的修复决策</h2>
          <p>
            项目上下文 + SBOM 版本匹配 + 攻击路径说明，让每一次分析都有依据。
          </p>
        </div>
        <Badge type="purple">模板报告演示 · LLM 未连接</Badge>
      </div>
      <div className="analysis-grid">
        {db.vulnerabilities
          .filter((v) => db.projects.some((p) => hit(p, v)))
          .map((v) => (
            <article className="panel analysis-card" key={v.id}>
              <div className="analysis-card-top">
                <Badge>{v.severity}</Badge>
                <span className="mono">{v.id}</span>
                <span className="analysis-score">
                  {v.score}
                  <small> / 100</small>
                </span>
              </div>
              <h2>{v.title}</h2>
              <p>{v.description}</p>
              <div className="affected-label">
                <Layers size={15} />
                {db.projects.filter((p) => hit(p, v)).length} 个相关项目
                <span>·</span>
                <code>{v.component}</code>
              </div>
              <div className="analysis-bottom">
                <span>
                  <CheckCircle2 size={14} />
                  SBOM 关联已完成
                </span>
                <button
                  className="text-button"
                  onClick={() => open({ type: "report", v })}
                >
                  查看影响报告
                  <ChevronRight size={15} />
                </button>
              </div>
            </article>
          ))}
      </div>
    </>
  );
}
function Tracking({ db, open, action, role }) {
  const [q, setQ] = useState(""),
    [onlyOverdue, setOnlyOverdue] = useState(false);
  let tasks = db.tasks.filter(
    (t) =>
      (t.id + t.cveId + db.projects.find((p) => p.id === t.projectId)?.name)
        .toLowerCase()
        .includes(q.toLowerCase()) &&
      (!onlyOverdue ||
        (t.status !== "已关闭" && new Date(t.dueAt) < Date.now())),
  );
  return (
    <>
      <div className="tracking-tools">
        <div className="view-label">
          <Workflow size={18} />
          流程看板<span>{tasks.length} 项任务</span>
        </div>
        <div className="toolbar-controls">
          <label className="input-search">
            <Search size={16} />
            <input
              placeholder="搜索任务、项目或 CVE"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </label>
          <button
            className={`button ${onlyOverdue ? "selected" : ""}`}
            onClick={() => setOnlyOverdue(!onlyOverdue)}
          >
            <Filter size={15} />
            {onlyOverdue ? "仅 SLA 超期" : "全部任务"}
          </button>
        </div>
      </div>
      <div className="kanban">
        {steps.map((s, i) => (
          <section className="kanban-column" key={s}>
            <div className="kanban-heading">
              <i
                style={{
                  background: [
                    "#94a3c7",
                    "#6a99dc",
                    "#6b78de",
                    "#a085cb",
                    "#4fb69b",
                  ][i],
                }}
              />
              <b>{s}</b>
              <span>{tasks.filter((t) => t.status === s).length}</span>
            </div>
            {tasks
              .filter((t) => t.status === s)
              .map((t) => {
                const p = db.projects.find((p) => p.id === t.projectId),
                  v = db.vulnerabilities.find((v) => v.id === t.cveId);
                const elapsed =
                  (Date.now() - new Date(t.createdAt)) /
                  (new Date(t.dueAt) - new Date(t.createdAt));
                return (
                  <article className="task-card" key={t.id}>
                    <button
                      className="task-main"
                      onClick={() => open({ type: "task", t })}
                    >
                      <div>
                        <Badge>{v.severity}</Badge>
                        <span>{t.id}</span>
                      </div>
                      <h3>{v.title}</h3>
                      <code>{v.id}</code>
                      <p>
                        <Box size={13} />
                        {p.name}
                      </p>
                    </button>
                    <div
                      className={`task-sla ${elapsed >= 0.8 && s !== "已关闭" ? "danger-text" : elapsed >= 0.5 && s !== "已关闭" ? "warning-text" : ""}`}
                    >
                      <Clock size={13} />
                      {s === "已关闭"
                        ? "修复流程已完成"
                        : new Date(t.dueAt) < Date.now()
                          ? "SLA 已超期"
                          : `截止 ${fmt(t.dueAt)}`}
                    </div>
                    <div className="task-footer">
                      <span className="owner">
                        <span className="avatar mini">{p.initial}</span>
                        {p.owner}
                      </span>
                      <button
                        className="icon-button"
                        aria-label="任务详情"
                        onClick={() => open({ type: "task", t })}
                      >
                        <MoreHorizontal size={18} />
                      </button>
                    </div>
                  </article>
                );
              })}
            {!tasks.some((t) => t.status === s) && (
              <div className="kanban-empty">暂无任务</div>
            )}
          </section>
        ))}
      </div>
      <div className="info-line">
        <Info size={15} />
        SLA 使用超过 50% 标记预警，超过 80%
        升级报警。演示环境不发送短信或拨打电话。
      </div>
    </>
  );
}
function Projects({ db, open, role }) {
  const [tab, setTab] = useState("projects"),
    [q, setQ] = useState("");
  return (
    <>
      <div className="asset-stats">
        {[
          [FolderKanban, db.projects.length, "业务项目"],
          [
            Box,
            db.projects.reduce((s, p) => s + p.components.length, 0),
            "软件组件",
          ],
          [
            Server,
            db.servers.filter((s) =>
              db.projects.some((p) => p.id === s.projectId),
            ).length,
            "服务器资产",
          ],
          [Globe, new Set(db.projects.map((p) => p.zone)).size, "网络区域"],
        ].map(([I, n, t]) => (
          <div key={t}>
            <span>
              <I size={22} />
            </span>
            <b>{n}</b>
            <small>{t}</small>
          </div>
        ))}
      </div>
      <section className="panel">
        <div className="list-toolbar">
          <div className="tabs">
            <button
              className={tab === "projects" ? "selected" : ""}
              onClick={() => setTab("projects")}
            >
              项目管理
            </button>
            <button
              className={tab === "servers" ? "selected" : ""}
              onClick={() => setTab("servers")}
            >
              服务器资产
            </button>
          </div>
          <label className="input-search">
            <Search size={16} />
            <input
              placeholder="搜索项目或服务器"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </label>
        </div>
        {tab === "projects" ? (
          <div className="project-grid">
            {db.projects
              .filter((p) =>
                (p.name + p.stack).toLowerCase().includes(q.toLowerCase()),
              )
              .map((p) => (
                <div className="project-card" key={p.id}>
                  <div className="project-card-top">
                    <span
                      className="project-square large"
                      style={{ background: p.color + "16", color: p.color }}
                    >
                      <Box size={25} />
                    </span>
                    <Badge type={p.criticality === 3 ? "critical" : "blue"}>
                      P{3 - p.criticality} 核心业务
                    </Badge>
                  </div>
                  <h2>{p.name}</h2>
                  <code>{p.code}</code>
                  <p>{p.stack}</p>
                  <div className="project-details">
                    <span>
                      <Box size={14} />
                      {p.components.length} 个组件
                    </span>
                    <span>
                      <Server size={14} />
                      {
                        db.servers.filter((s) => s.projectId === p.id).length
                      }{" "}
                      台服务器
                    </span>
                  </div>
                  <div className="project-card-footer">
                    <span className="owner">
                      <span className="avatar mini">{p.initial}</span>
                      {p.owner}
                    </span>
                    <button
                      className="text-button"
                      onClick={() => open({ type: "project", p })}
                    >
                      查看详情
                      <ChevronRight size={14} />
                    </button>
                  </div>
                  {["security", "sre"].includes(role) && (
                    <button
                      className="button import-button"
                      onClick={() => open({ type: "import", p })}
                    >
                      <Upload size={15} />
                      导入 SBOM
                    </button>
                  )}
                </div>
              ))}
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>服务器名称 / IP</th>
                  <th>所属项目</th>
                  <th>操作系统</th>
                  <th>部署类型</th>
                  <th>网络区域</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {db.servers
                  .filter(
                    (s) =>
                      db.projects.some((p) => p.id === s.projectId) &&
                      (
                        s.name +
                        s.ip +
                        db.projects.find((p) => p.id === s.projectId).name
                      )
                        .toLowerCase()
                        .includes(q.toLowerCase()),
                  )
                  .map((s) => (
                    <tr key={s.id}>
                      <td>
                        <b className="server-name">
                          <Server size={16} />
                          {s.name}
                        </b>
                        <small className="block mono">{s.ip}</small>
                      </td>
                      <td>
                        {db.projects.find((p) => p.id === s.projectId)?.name}
                      </td>
                      <td>{s.os}</td>
                      <td>
                        <Badge type="blue">{s.type}</Badge>
                      </td>
                      <td>
                        <Badge
                          type={s.zone === "Public DMZ" ? "high" : "muted"}
                        >
                          {s.zone}
                        </Badge>
                      </td>
                      <td>
                        <button
                          className="text-button"
                          onClick={() => open({ type: "server", s })}
                        >
                          排查详情
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
function Graph({ db, open, ask }) {
  const svgRef = useRef(null),
    [selected, setSelected] = useState(null),
    [drag, setDrag] = useState(null),
    [offsets, setOffsets] = useState({}),
    [focus, setFocus] = useState(false),
    [cve, setCve] = useState("all");
  const cols = [
    {
      name: "业务项目",
      color: "#7182e8",
      icon: "P",
      nodes: db.projects.map((p) => ({
        id: "p" + p.id,
        label: p.name,
        kind: "project",
        value: p,
      })),
    },
    {
      name: "软件组件",
      color: "#50afa3",
      icon: "C",
      nodes: [
        ...new Set(db.projects.flatMap((p) => p.components.map((c) => c.name))),
      ]
        .slice(0, 8)
        .map((n) => ({ id: "c" + n, label: n, kind: "component" })),
    },
    {
      name: "漏洞情报",
      color: "#e57b89",
      icon: "V",
      nodes: db.vulnerabilities
        .filter(
          (v) =>
            (cve === "all" || v.id === cve) &&
            db.projects.some((p) => hit(p, v)),
        )
        .slice(0, 6)
        .map((v) => ({
          id: v.id,
          label: v.id,
          kind: "vulnerability",
          value: v,
        })),
    },
    {
      name: "服务器",
      color: "#b28bda",
      icon: "S",
      nodes: db.projects.map((p) => ({
        id: "s" + p.id,
        label: db.servers.find((s) => s.projectId === p.id)?.name || "无服务器",
        kind: "server",
        projectId: p.id,
      })),
    },
    {
      name: "网络区域",
      color: "#e1ae60",
      icon: "N",
      nodes: [...new Set(db.projects.map((p) => p.zone))].map((z) => ({
        id: "z" + z,
        label: z,
        kind: "zone",
      })),
    },
  ];
  const all = cols
    .flatMap((c, i) =>
      c.nodes.map((n, j) => ({
        ...n,
        x: 78 + i * 205,
        y: 95 + j * (340 / Math.max(c.nodes.length - 1, 1)),
        color: c.color,
        icon: c.icon,
      })),
    )
    .map((n) => ({ ...n, ...offsets[n.id] }));
  const links = [];
  db.projects.forEach((p) =>
    p.components.forEach((c) => {
      if (all.some((n) => n.id === "c" + c.name))
        links.push(["p" + p.id, "c" + c.name]);
    }),
  );
  db.vulnerabilities.forEach((v) => {
    if (
      all.some((n) => n.id === v.id) &&
      all.some((n) => n.id === "c" + v.component)
    ) {
      links.push(["c" + v.component, v.id]);
      db.projects
        .filter((p) => hit(p, v))
        .forEach((p) => links.push([v.id, "s" + p.id]));
    }
  });
  db.projects.forEach((p) => links.push(["s" + p.id, "z" + p.zone]));
  function move(e) {
    if (!drag) return;
    const pt = svgRef.current.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const p = pt.matrixTransform(svgRef.current.getScreenCTM().inverse());
    setOffsets((o) => ({
      ...o,
      [drag]: {
        x: Math.max(30, Math.min(960, p.x)),
        y: Math.max(65, Math.min(455, p.y)),
      },
    }));
  }
  return (
    <section className={`panel graph-panel ${focus ? "graph-fullscreen" : ""}`}>
      <div className="section-head">
        <div>
          <h2>
            企业安全关系网络 <span>五层 Ontology</span>
          </h2>
        </div>
        <div className="toolbar-controls">
          <select
            aria-label="图谱漏洞筛选"
            value={cve}
            onChange={(e) => setCve(e.target.value)}
          >
            <option value="all">全部攻击路径</option>
            {db.vulnerabilities.map((v) => (
              <option key={v.id}>{v.id}</option>
            ))}
          </select>
          <button
            className="icon-button"
            aria-label="切换全屏图谱"
            onClick={() => setFocus(!focus)}
          >
            {focus ? <X size={18} /> : <Maximize2 size={18} />}
          </button>
        </div>
      </div>
      <div className="graph-meta">
        <span>
          <i className="tiny-dot" />
          {all.length} 个可视节点
        </span>
        <span>{links.length} 条资产关系</span>
        <span>可拖动节点 · 点击查看详情</span>
        <button
          className="text-button"
          onClick={() => {
            setOffsets({});
            setSelected(null);
          }}
        >
          重置视图
        </button>
      </div>
      <div className="graph-canvas">
        <svg
          ref={svgRef}
          viewBox="0 0 990 510"
          onPointerMove={move}
          onPointerUp={() => setDrag(null)}
          onPointerLeave={() => setDrag(null)}
        >
          {cols.map((c, i) => (
            <g key={c.name}>
              <text
                x={78 + i * 205}
                y="28"
                textAnchor="middle"
                className="graph-col-title"
              >
                {c.name}
              </text>
              <line
                x1={78 + i * 205}
                x2={78 + i * 205}
                y1="45"
                y2="475"
                stroke="#e7eaf3"
                strokeDasharray="3 7"
              />
            </g>
          ))}
          {links.map(([a, b], i) => {
            const na = all.find((n) => n.id === a),
              nb = all.find((n) => n.id === b);
            if (!na || !nb) return null;
            const active = selected && (a === selected || b === selected);
            return (
              <path
                key={i}
                d={`M${na.x} ${na.y} C${(na.x + nb.x) / 2} ${na.y}, ${(na.x + nb.x) / 2} ${nb.y}, ${nb.x} ${nb.y}`}
                fill="none"
                stroke={active ? "#756bd0" : "#dce1ed"}
                strokeWidth={active ? 2.5 : 1.1}
                opacity={selected && !active ? 0.25 : 1}
              />
            );
          })}
          {all.map((n) => (
            <g
              className="graph-node"
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              onPointerDown={(e) => {
                setDrag(n.id);
                setSelected(n.id);
                e.currentTarget.setPointerCapture(e.pointerId);
              }}
              onDoubleClick={() =>
                n.kind === "vulnerability"
                  ? open({ type: "report", v: n.value })
                  : n.kind === "project"
                    ? open({ type: "project", p: n.value })
                    : null
              }
            >
              <circle
                r="24"
                fill={n.color + "15"}
                stroke={selected === n.id ? n.color : n.color + "60"}
                strokeWidth={selected === n.id ? 2 : 1}
              />
              <circle r="16" fill={n.color} />
              <text
                y="5"
                textAnchor="middle"
                fill="white"
                fontSize="12"
                fontWeight="600"
              >
                {n.icon}
              </text>
              <rect
                x="-72"
                y="28"
                width="144"
                height="23"
                rx="5"
                fill="#fafbfd"
              />
              <text y="43" textAnchor="middle" className="node-label">
                {n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label}
              </text>
            </g>
          ))}
        </svg>
      </div>
      {selected && (
        <div className="selected-node">
          <Network size={17} />
          <b>{all.find((n) => n.id === selected)?.label}</b>
          <span>
            {links.filter((l) => l.includes(selected)).length} 条关联关系
          </span>
          <button
            className="text-button"
            onClick={() => {
              const n = all.find((n) => n.id === selected);
              if (n?.kind === "vulnerability")
                open({ type: "report", v: n.value });
              else if (n?.kind === "project")
                open({ type: "project", p: n.value });
              else ask();
            }}
          >
            探索关联详情
            <ChevronRight size={14} />
          </button>
        </div>
      )}
      <div className="graph-bottom">
        <div>
          {cols.map((c) => (
            <span key={c.name}>
              <i style={{ background: c.color }} />
              {c.name}
            </span>
          ))}
        </div>
        <button className="button primary" onClick={ask}>
          <Sparkles size={16} />
          向安全 Agent 提问
        </button>
      </div>
    </section>
  );
}
function PM({ db, open, action }) {
  const [tab, setTab] = useState("voc");
  return (
    <>
      <div className="pm-summary">
        <div>
          <MessageSquare size={22} />
          <b>{db.feedback.length}</b>
          <span>真实反馈记录</span>
        </div>
        <div>
          <Star size={22} />
          <b>
            {db.feedback.length
              ? (
                  db.feedback.reduce((s, f) => s + f.rating, 0) /
                  db.feedback.length
                ).toFixed(1)
              : "—"}
          </b>
          <span>报告满意度 / 5</span>
        </div>
        <div>
          <Users size={22} />
          <b>{db.personas.length}</b>
          <span>用户画像</span>
        </div>
        <div>
          <Target size={22} />
          <b>{db.requirements.length}</b>
          <span>需求洞察</span>
        </div>
      </div>
      <section className="panel">
        <div className="list-toolbar">
          <div className="tabs">
            {[
              ["voc", "VOC Board"],
              ["personas", "用户画像"],
              ["matrix", "需求跟踪矩阵"],
            ].map(([k, v]) => (
              <button
                key={k}
                className={tab === k ? "selected" : ""}
                onClick={() => setTab(k)}
              >
                {v}
              </button>
            ))}
          </div>
          {tab === "personas" ? (
            <button
              className="button primary"
              onClick={() => open({ type: "persona" })}
            >
              <Plus size={15} />
              添加画像
            </button>
          ) : (
            <button
              className="button primary"
              onClick={() =>
                action(
                  () => api("/factory", {}),
                  "需求建议已生成，请在跟踪矩阵中评审。",
                )
              }
            >
              <Sparkles size={15} />
              运行需求工厂
            </button>
          )}
        </div>
        {tab === "voc" ? (
          <div className="voc-list">
            <div className="info-line">
              <Info size={15} />
              反馈来自分析报告内嵌表单；需求工厂当前使用规则示例归类，尚未连接大模型。
            </div>
            {db.feedback.map((f) => (
              <article key={f.id} className="feedback-card">
                <span className="avatar">{f.role.slice(0, 1)}</span>
                <div>
                  <div className="feedback-header">
                    <b>{f.role}</b>
                    <span>{fmt(f.createdAt)}</span>
                    <Badge>{f.tag}</Badge>
                  </div>
                  <p>{f.text || "用户提交了评分反馈"}</p>
                  <span className="stars">
                    {"★".repeat(f.rating)}
                    <span>{"★".repeat(5 - f.rating)}</span>
                  </span>
                  <small className="mono">{f.cveId}</small>
                </div>
              </article>
            ))}
          </div>
        ) : tab === "personas" ? (
          <div className="persona-grid">
            {db.personas.map((p, i) => (
              <article className="persona-card" key={p.id}>
                <div className="persona-header">
                  <span className="persona-avatar">{p.role.slice(0, 1)}</span>
                  <Badge type={p.validated ? "success" : "medium"}>
                    {p.validated ? "已验证（文档）" : "待验证"}
                  </Badge>
                </div>
                <h2>{p.role}</h2>
                <label>核心痛点</label>
                <p>{p.pain}</p>
                <label>期望价值</label>
                <p>{p.value}</p>
              </article>
            ))}
          </div>
        ) : db.requirements.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>需求 / 功能建议</th>
                  <th>源头痛点</th>
                  <th>影响角色</th>
                  <th>优先级</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {db.requirements.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <b>{r.title}</b>
                      <small className="block">{r.suggestion}</small>
                      <small className="block">
                        {r.evidence.length} 条关联反馈 · {r.mode}
                      </small>
                    </td>
                    <td>
                      <code>{r.pain}</code>
                    </td>
                    <td>{r.role}</td>
                    <td>
                      <Badge type={r.priority === "P0" ? "critical" : "medium"}>
                        {r.priority}
                      </Badge>
                    </td>
                    <td>{r.status}</td>
                    <td>
                      <button
                        className="text-button"
                        disabled={r.status === "已纳入 Sprint"}
                        onClick={() =>
                          action(
                            () => api("/requirements/" + r.id, {}, "PATCH"),
                            "已加入下个 Sprint",
                          )
                        }
                      >
                        {r.status === "已纳入 Sprint"
                          ? "已纳入"
                          : "纳入 Sprint"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty text="运行需求工厂，将用户反馈转化为可追溯的需求建议" />
        )}
      </section>
    </>
  );
}
function SettingsPage({ db, role, open }) {
  return (
    <div className="settings-grid">
      <section className="panel">
        <SectionHeader title="情报源管理">
          <button
            className="text-button"
            disabled={role !== "security"}
            onClick={() => open({ type: "source" })}
          >
            <Plus size={15} />
            添加情报源
          </button>
        </SectionHeader>
        {db.sources.map((s) => (
          <div className="setting-row" key={s.id}>
            <Radio size={20} />
            <div>
              <b>{s.name}</b>
              <small>{s.url || `${s.type} · 演示数据，未建立外部连接`}</small>
            </div>
            <Badge type="muted">未连接</Badge>
          </div>
        ))}
      </section>
      <section className="panel">
        <SectionHeader title="运行环境与集成" />
        {[
          ["运行模式", "本地演示 MVP"],
          ["数据持久化", "本地 JSON · 原子写入"],
          ["LLM 服务", "未配置 · 使用模板报告"],
          ["通知服务", "站内任务 · 外部推送未配置"],
          ["身份认证", "演示角色会话 · 非生产登录"],
          ["生产部署", "需配置 SSO、数据库、TLS 与密钥管理"],
        ].map(([k, v]) => (
          <div className="setting-row" key={k}>
            <span>{k}</span>
            <b>{v}</b>
          </div>
        ))}
      </section>
      <section className="panel wide">
        <SectionHeader title="操作审计" sub="最近 20 条记录" />
        {db.audit.length ? (
          <div className="audit-list">
            {db.audit.slice(0, 20).map((a) => (
              <div key={a.id}>
                <span className="audit-icon">
                  <Activity size={15} />
                </span>
                <div>
                  <b>{a.action}</b>
                  <small>
                    {a.actor} · {fmt(a.at)}
                  </small>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <Empty text="当前角色无可见审计记录" />
        )}
      </section>
    </div>
  );
}
function Agent({ onClose, open, db }) {
  const [question, setQuestion] = useState(""),
    [messages, setMessages] = useState([]),
    [loading, setLoading] = useState(false);
  const bottom = useRef(null);
  async function ask(q) {
    if (!q.trim() || loading) return;
    setQuestion("");
    setMessages((m) => [...m, { kind: "user", text: q }]);
    setLoading(true);
    try {
      const a = await api("/agent", { question: q });
      setMessages((m) => [...m, { kind: "agent", ...a }]);
    } catch (e) {
      setMessages((m) => [...m, { kind: "agent", answer: e.message }]);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);
  return (
    <aside className="agent-panel">
      <div className="agent-header">
        <span className="agent-symbol">
          <Sparkles size={20} />
        </span>
        <div>
          <b>安全 Agent</b>
          <small>您的安全知识探索助手</small>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="关闭 Agent"
        >
          <PanelRightClose size={19} />
        </button>
      </div>
      <div className="agent-messages">
        <div className="agent-welcome">
          <span className="welcome-spark">
            <Sparkles size={29} />
          </span>
          <h2>一起，看清风险全貌</h2>
          <p>
            基于当前角色可见的资产关系，
            <br />
            快速查找受影响项目与网络暴露面。
          </p>
          <span className="agent-mode">结构化查询演示 · 未连接 LLM</span>
        </div>
        {!messages.length && (
          <div className="suggestions">
            {[
              "CVE-2024-38816 影响哪些项目？",
              "哪些项目有公网暴露的超高危 CVE？",
              "列出需要关注的项目与服务器",
            ].map((q) => (
              <button key={q} onClick={() => ask(q)}>
                <MessageSquare size={15} />
                {q}
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`chat-message ${m.kind}`}>
            {m.kind === "user" ? (
              m.text
            ) : (
              <>
                <span className="chat-label">
                  <Sparkles size={14} />
                  安全 Agent
                </span>
                <p>{m.answer}</p>
                {m.rows?.map((r) => (
                  <div className="agent-result" key={r.name}>
                    <b>{r.name}</b>
                    <small>
                      {r.zone} · {r.servers} 台项目服务器
                    </small>
                    {r.cves.slice(0, 3).map((c) => (
                      <button
                        key={c}
                        onClick={() =>
                          open({
                            type: "report",
                            v: db.vulnerabilities.find((v) => v.id === c),
                          })
                        }
                      >
                        {c}
                        <ExternalLink size={11} />
                      </button>
                    ))}
                  </div>
                ))}
                <small className="agent-disclaimer">
                  基于演示资产关系，需人工核验实际可利用性。
                </small>
              </>
            )}
          </div>
        ))}
        {loading && (
          <div className="agent-thinking">
            <span className="pulse" />
            正在查询资产关系…
          </div>
        )}
        <div ref={bottom} />
      </div>
      <form
        className="agent-input"
        onSubmit={(e) => {
          e.preventDefault();
          ask(question);
        }}
      >
        <textarea
          aria-label="向安全 Agent 提问"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="询问漏洞、项目或攻击路径…"
          maxLength={1000}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              ask(question);
            }
          }}
        />
        <div>
          <small>Enter 发送 · Shift + Enter 换行</small>
          <button
            className="send-button"
            disabled={loading || !question.trim()}
            aria-label="发送"
            type="submit"
          >
            <Send size={16} />
          </button>
        </div>
      </form>
    </aside>
  );
}
function Modal({ modal, close, db, role, action, notify, refresh, busy }) {
  const { type, v, p, t, s } = modal;
  const [rating, setRating] = useState(0),
    [tag, setTag] = useState("准确"),
    [text, setText] = useState(""),
    [file, setFile] = useState(null),
    [form, setForm] = useState({}),
    [reviewed, setReviewed] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const old = document.activeElement;
    ref.current?.focus();
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
      old?.focus?.();
    };
  }, []);
  const submit = async (fn, msg) => {
    try {
      await fn();
      await refresh();
      notify(msg);
      close();
    } catch (e) {
      notify(e.message);
    }
  };
  const task = t && db.tasks.find((x) => x.id === t.id);
  const title = {
    report: "漏洞影响分析报告",
    project: "项目安全详情",
    task: "修复任务详情",
    import: "导入项目 SBOM",
    persona: "添加用户画像",
    notifications: "工作空间通知",
    source: "添加自定义情报源",
    workspace: "企业工作空间",
    server: "服务器排查详情",
  }[type];
  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={ref}
        className={`modal ${["report", "project"].includes(type) ? "modal-large" : ""}`}
        onKeyDown={(e) => {
          if (e.key === "Tab") {
            const els = ref.current.querySelectorAll(
              'button:not(:disabled),input,select,textarea,[tabindex="0"]',
            );
            const first = els[0],
              last = els[els.length - 1];
            if (e.shiftKey && document.activeElement === first) {
              e.preventDefault();
              last?.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
              e.preventDefault();
              first?.focus();
            }
          }
        }}
      >
        <div className="modal-header">
          <div>
            <span className="eyebrow">VUNHUNTER WORKSPACE</span>
            <h2>{title}</h2>
          </div>
          <button className="icon-button" onClick={close} aria-label="关闭弹窗">
            <X size={21} />
          </button>
        </div>
        <div className="modal-body">
          {type === "report" && (
            <>
              <div className="report-kicker">
                <Badge>{v.severity}</Badge>
                <code>{v.id}</code>
                <span className="report-score">
                  {v.score}
                  <small>VH Score</small>
                </span>
              </div>
              <h1 className="report-title">{v.title}</h1>
              <div className="report-meta">
                <span>
                  <Radio size={14} />
                  {v.source}
                </span>
                <span>
                  <Clock size={14} />
                  {fmt(v.published)}
                </span>
                <span>
                  <Sparkles size={14} />
                  模板报告 · 非 LLM 生成
                </span>
              </div>
              <div className="report-warning">
                <Info size={17} />
                <p>
                  本报告使用样例情报与本地 SBOM
                  生成。组件版本命中不代表实际可利用，请核对厂商公告、部署配置和攻击前提后再通报。
                </p>
              </div>
              <div className="report-stepper">
                {["情报读取", "SBOM 版本匹配", "资产关联", "生成报告"].map(
                  (x) => (
                    <span key={x}>
                      <CheckCircle2 size={14} />
                      {x}
                    </span>
                  ),
                )}
              </div>
              <h3>漏洞解读与攻击路径</h3>
              <p className="report-prose">{v.description}</p>
              <div className="attack-path">
                <span>
                  <Globe size={17} />
                  外部请求
                </span>
                <ChevronRight size={16} />
                <span>
                  <Box size={17} />
                  {v.component}
                </span>
                <ChevronRight size={16} />
                <span>
                  <Server size={17} />
                  关联应用服务
                </span>
                <ChevronRight size={16} />
                <span className="danger-text">
                  <TriangleAlert size={17} />
                  潜在业务影响
                </span>
              </div>
              <h3>项目影响与差异化修复</h3>
              <div className="report-projects">
                {db.projects
                  .filter((p) =>
                    p.components.some((c) => c.name === v.component),
                  )
                  .map((p) => {
                    const c = p.components.find((c) => c.name === v.component);
                    return (
                      <div key={p.id}>
                        <div>
                          <b>{p.name}</b>
                          <Badge
                            type={
                              c.managed
                                ? "success"
                                : hit(p, v)
                                  ? "critical"
                                  : "muted"
                            }
                          >
                            {c.managed
                              ? "厂商负责"
                              : hit(p, v)
                                ? "版本命中"
                                : "未命中范围"}
                          </Badge>
                        </div>
                        <p>
                          <code>
                            {c.name} {c.version}
                          </code>
                          <span>目标版本</span>
                          <code>{v.fix}</code>
                        </p>
                        <small>
                          {c.managed
                            ? "云托管组件排除主动修复任务，请联系厂商核验。"
                            : `${p.zone} 网络区域；评估业务兼容性后升级，在预发布环境回归测试。`}
                        </small>
                      </div>
                    );
                  })}
              </div>
              <h3>
                多维威胁评分 <span className="subtle">计算权重可解释</span>
              </h3>
              <div className="score-breakdown">
                {[
                  ["CVSS 基础分", v.cvss * 10, 30],
                  ["可利用性", v.exploit, 25],
                  ["社交热度", v.heat, 15],
                  ["企业影响面", v.impact, 20],
                  ["厂商紧急公告", v.urgent, 10],
                ].map(([name, val, weight]) => (
                  <div key={name}>
                    <span>
                      {name}
                      <small>{weight}%</small>
                    </span>
                    <div className="progress-track">
                      <i style={{ width: val + "%" }} />
                    </div>
                    <b>{Math.round(val)}</b>
                  </div>
                ))}
              </div>
              <h3>建议修复步骤</h3>
              <ol className="fix-list">
                <li>核验实际部署版本和厂商公告，确认漏洞攻击前提。</li>
                <li>
                  将 <code>{v.component}</code>{" "}
                  升级至经厂商确认的修复版本（样例建议 {v.fix}
                  ），运行兼容性与回归测试。
                </li>
                <li>
                  采用灰度发布，记录验证结果；更新 SBOM 并进入修复验证流程。
                </li>
              </ol>
              <div className="report-review">
                <label>
                  <input
                    type="checkbox"
                    checked={reviewed}
                    onChange={(e) => setReviewed(e.target.checked)}
                  />
                  我已人工核对影响范围及修复建议
                </label>
                {role === "security" && (
                  <button
                    className="button primary"
                    disabled={
                      !reviewed || busy || !db.projects.some((p) => hit(p, v))
                    }
                    onClick={() =>
                      action(async () => {
                        const r = await api("/notify", { cveId: v.id });
                        notify(
                          r.count
                            ? `已创建 ${r.count} 条站内修复通报`
                            : "相关项目已有任务，无需重复通报",
                        );
                      }, null)
                    }
                  >
                    <Send size={15} />
                    确认并一键通报
                  </button>
                )}
              </div>
              <div className="voc-inline">
                <div>
                  <h3>这份分析对您有帮助吗？</h3>
                  <p>您的反馈会帮助我们改进分析体验。</p>
                </div>
                <div className="rating-stars">
                  {[1, 2, 3, 4, 5].map((n) => (
                    <button
                      aria-label={`${n} 星`}
                      key={n}
                      onClick={() => setRating(n)}
                    >
                      <Star
                        size={24}
                        fill={n <= rating ? "#e8ae49" : "none"}
                        color={n <= rating ? "#e8ae49" : "#bac2d0"}
                      />
                    </button>
                  ))}
                </div>
                <div className="feedback-tags">
                  {["准确", "无效", "缺少信息"].map((x) => (
                    <button
                      key={x}
                      className={tag === x ? "selected" : ""}
                      onClick={() => setTag(x)}
                    >
                      {x}
                    </button>
                  ))}
                </div>
                <textarea
                  placeholder="哪些内容有帮助？还有什么需要补充？"
                  value={text}
                  maxLength={2000}
                  onChange={(e) => setText(e.target.value)}
                />
                <button
                  className="button"
                  disabled={!rating}
                  onClick={() =>
                    submit(
                      () =>
                        api("/feedback", { rating, text, tag, cveId: v.id }),
                      "反馈已保存至 VOC Board，感谢您的建议",
                    )
                  }
                >
                  提交反馈
                </button>
              </div>
              <div className="report-export">
                <button className="text-button" onClick={() => window.print()}>
                  <Download size={15} />
                  打印 / 保存 PDF
                </button>
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${v.id}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  核验 NVD 原始公告
                  <ExternalLink size={13} />
                </a>
              </div>
            </>
          )}
          {type === "project" && (
            <>
              <div className="project-detail-heading">
                <span
                  className="project-square large"
                  style={{ color: p.color, background: p.color + "15" }}
                >
                  <Box size={28} />
                </span>
                <div>
                  <h2>{p.name}</h2>
                  <p>
                    {p.code} · {p.stack}
                  </p>
                </div>
              </div>
              <div className="detail-facts">
                <div>
                  <small>项目负责人</small>
                  <b>{p.owner}</b>
                </div>
                <div>
                  <small>网络区域</small>
                  <b>{p.zone}</b>
                </div>
                <div>
                  <small>组件数量</small>
                  <b>{p.components.length}</b>
                </div>
                <div>
                  <small>服务器规模</small>
                  <b>
                    {db.servers.filter((s) => s.projectId === p.id).length} 台
                  </b>
                </div>
              </div>
              <h3>
                软件物料清单 <span className="subtle">SBOM</span>
              </h3>
              <table>
                <thead>
                  <tr>
                    <th>组件</th>
                    <th>当前版本</th>
                    <th>责任边界</th>
                    <th>关联漏洞</th>
                  </tr>
                </thead>
                <tbody>
                  {p.components.map((c, i) => (
                    <tr key={i}>
                      <td>
                        <code>{c.name}</code>
                      </td>
                      <td>{c.version}</td>
                      <td>
                        <Badge type={c.managed ? "success" : "blue"}>
                          {c.managed ? "云厂商托管" : "自建维护"}
                        </Badge>
                      </td>
                      <td>
                        {db.vulnerabilities
                          .filter(
                            (v) =>
                              v.component === c.name &&
                              hit({ ...p, components: [c] }, v),
                          )
                          .map((v) => (
                            <span className="block mono" key={v.id}>
                              {v.id}
                            </span>
                          ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {type === "task" && task && (
            <>
              <div className="task-detail-top">
                <code>{task.id}</code>
                <Badge>{task.status}</Badge>
              </div>
              <h2>
                {db.vulnerabilities.find((v) => v.id === task.cveId)?.title}
              </h2>
              <p className="subtle">
                {task.cveId} ·{" "}
                {db.projects.find((p) => p.id === task.projectId)?.name}
              </p>
              <div className="detail-facts">
                <div>
                  <small>创建时间</small>
                  <b>{fmt(task.createdAt)}</b>
                </div>
                <div>
                  <small>SLA 截止</small>
                  <b
                    className={
                      new Date(task.dueAt) < Date.now() &&
                      task.status !== "已关闭"
                        ? "danger-text"
                        : ""
                    }
                  >
                    {fmt(task.dueAt)}
                  </b>
                </div>
              </div>
              <h3>操作时间线</h3>
              <div className="timeline">
                {task.history.map((h, i) => (
                  <div key={i}>
                    <i />
                    <b>{h.status}</b>
                    <small>
                      {fmt(h.at)} · {h.actor}
                    </small>
                    {h.reason && <p>{h.reason}</p>}
                  </div>
                ))}
              </div>
              {role !== "pm" &&
                (task.status !== "已关闭" ? (
                  <button
                    className="button primary"
                    disabled={busy}
                    onClick={() =>
                      action(
                        () =>
                          api(
                            "/tasks/" + task.id,
                            { status: steps[steps.indexOf(task.status) + 1] },
                            "PATCH",
                          ),
                        "任务状态已更新",
                      )
                    }
                  >
                    <Check size={16} />
                    推进至{steps[steps.indexOf(task.status) + 1]}
                  </button>
                ) : (
                  <div className="form-stack">
                    <label>
                      重新打开原因
                      <input
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        placeholder="例如：验证未通过，问题仍然存在"
                      />
                    </label>
                    <button
                      className="button"
                      disabled={!text.trim() || busy}
                      onClick={() =>
                        action(
                          () =>
                            api(
                              "/tasks/" + task.id,
                              { status: "已确认", reason: text },
                              "PATCH",
                            ),
                          "任务已重新打开",
                        )
                      }
                    >
                      重新打开任务
                    </button>
                  </div>
                ))}
            </>
          )}
          {type === "import" && (
            <div className="form-stack">
              <p>
                为 <b>{p.name}</b> 导入组件清单，导入后将替换该项目现有 SBOM。
              </p>
              <label className="upload-zone">
                <Upload size={32} />
                <b>{file?.name || "点击选择 SBOM 文件"}</b>
                <span>CycloneDX / SPDX / package.json / pom.xml / go.mod</span>
                <small>最大 2MB · 仅支持精确版本</small>
                <input
                  type="file"
                  accept=".json,.xml,.mod"
                  onChange={(e) => setFile(e.target.files[0])}
                />
              </label>
              <div className="info-line">
                <Info size={16} />
                版本范围（如 ^1.2.0）不代表已安装版本，导入时将提示更换为精确
                SBOM。
              </div>
              <button
                className="button primary"
                disabled={!file}
                onClick={() =>
                  submit(async () => {
                    if (file.size > 2 * 1024 * 1024)
                      throw new Error("文件超过 2MB 限制");
                    await api(`/projects/${p.id}/sbom`, {
                      filename: file.name,
                      text: await file.text(),
                    });
                  }, "SBOM 已导入并更新关联")
                }
              >
                确认替换并导入
              </button>
            </div>
          )}
          {type === "persona" && (
            <form
              className="form-stack"
              onSubmit={(e) => {
                e.preventDefault();
                submit(() => api("/personas", form), "用户画像已创建");
              }}
            >
              {[
                ["role", "用户角色", "例如：应用安全工程师"],
                ["pain", "核心痛点", "描述用户当前最困扰的问题"],
                ["value", "期望价值", "用户希望获得什么改善"],
              ].map(([k, label, placeholder]) => (
                <label key={k}>
                  {label}
                  <input
                    required
                    maxLength={k === "role" ? 100 : 1000}
                    value={form[k] || ""}
                    placeholder={placeholder}
                    onChange={(e) => setForm({ ...form, [k]: e.target.value })}
                  />
                </label>
              ))}
              <button className="button primary" type="submit">
                保存用户画像
              </button>
            </form>
          )}
          {type === "source" && (
            <form
              className="form-stack"
              onSubmit={(e) => {
                e.preventDefault();
                submit(
                  () => api("/sources", form),
                  "情报源配置已保存；需后续连接采集服务",
                );
              }}
            >
              <label>
                情报源名称
                <input
                  required
                  value={form.name || ""}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="例如：企业安全公告"
                />
              </label>
              <label>
                数据源类型
                <select
                  value={form.type || "API"}
                  onChange={(e) => setForm({ ...form, type: e.target.value })}
                >
                  <option>API</option>
                  <option>RSS</option>
                </select>
              </label>
              <label>
                源地址
                <input
                  type="url"
                  required
                  value={form.url || ""}
                  onChange={(e) => setForm({ ...form, url: e.target.value })}
                  placeholder="https://example.com/security/feed"
                />
              </label>
              <p className="subtle">
                首版保存配置，不会从浏览器或服务端抓取任意地址。
              </p>
              <button className="button primary" type="submit">
                保存配置
              </button>
            </form>
          )}
          {type === "notifications" && (
            <div>
              {db.tasks
                .filter((t) => t.status !== "已关闭")
                .slice(0, 8)
                .map((t) => (
                  <div className="notification-item" key={t.id}>
                    <span className="stat-icon indigo">
                      <Bell size={16} />
                    </span>
                    <div>
                      <b>{t.cveId} 待跟进</b>
                      <p>
                        {db.projects.find((p) => p.id === t.projectId)?.name} ·{" "}
                        {t.status}
                      </p>
                      <small>{fmt(t.createdAt)}</small>
                    </div>
                  </div>
                ))}
              {!db.tasks.length && <Empty text="暂无待处理通知" />}
            </div>
          )}
          {type === "workspace" && (
            <>
              <div className="workspace-detail">
                <span className="workspace-icon">
                  <Layers size={32} />
                </span>
                <h2>星云科技</h2>
                <p>企业安全工作空间 · 本地演示</p>
                <Badge type="blue">Enterprise Demo</Badge>
              </div>
              <div className="info-line">
                <Info size={16} />
                预置数据仅供功能体验。当前角色：{roles[role]}
                。可通过左下角切换演示身份；生产环境需要接入企业身份认证。
              </div>
            </>
          )}
          {type === "server" && (
            <>
              <h2 className="server-name">
                <Server size={23} />
                {s.name}
              </h2>
              <div className="detail-facts">
                <div>
                  <small>IP 地址</small>
                  <b>{s.ip}</b>
                </div>
                <div>
                  <small>操作系统</small>
                  <b>{s.os}</b>
                </div>
                <div>
                  <small>网络区域</small>
                  <b>{s.zone}</b>
                </div>
                <div>
                  <small>部署方式</small>
                  <b>{s.type}</b>
                </div>
              </div>
              <h3>项目组件排查范围</h3>
              <p className="subtle">
                以下为所属项目的组件关联，不等同于该服务器已确认安装的清单。需要主机
                Agent 验证。
              </p>
              {db.projects
                .find((p) => p.id === s.projectId)
                ?.components.map((c, i) => (
                  <div className="setting-row" key={i}>
                    <code>
                      {c.name} {c.version}
                    </code>
                    <Badge type={c.managed ? "success" : "muted"}>
                      {c.managed ? "厂商负责" : "待主机验证"}
                    </Badge>
                  </div>
                ))}
            </>
          )}
        </div>
      </section>
    </div>
  );
}
const container = document.getElementById("root");
const appRoot =
  container.__vunhunterRoot ||
  (container.__vunhunterRoot = createRoot(container));
appRoot.render(<App />);
