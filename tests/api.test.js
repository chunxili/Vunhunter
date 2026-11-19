import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import net from "node:net";
let child, dir, base;
before(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "vh-test-"));
  const port = await new Promise((resolve) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ["server/index.js"], {
    env: { ...process.env, PORT: String(port), DATA_DIR: dir },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("API startup timed out")),
      12000,
    );
    child.once("error", reject);
    child.stdout.once("data", () => {
      clearTimeout(timer);
      resolve();
    });
  });
});
after(async () => {
  child?.kill();
  await new Promise((r) =>
    child?.exitCode !== null ? r() : child.once("exit", r),
  );
  await rm(dir, { recursive: true, force: true });
});
async function session(role) {
  const r = await fetch(base + "/api/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
  return r.headers.get("set-cookie").split(";")[0];
}
async function request(url, cookie, body, method) {
  return fetch(base + "/api" + url, {
    method: method || (body ? "POST" : "GET"),
    headers: {
      "Content-Type": "application/json",
      ...(cookie ? { Cookie: cookie } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}
test("API rejects unauthenticated reads", async () =>
  assert.equal((await request("/state")).status, 401));
test("服务端拦截跨角色写入和越权项目操作", async () => {
  const cookie = await session("developer");
  assert.equal(
    (await request("/notify", cookie, { cveId: "CVE-2024-3094" })).status,
    403,
  );
  assert.equal(
    (await request("/tasks/VH-1002", cookie, { status: "修复中" }, "PATCH"))
      .status,
    404,
  );
  assert.equal((await request("/factory", cookie, {})).status, 403);
});
test("通报幂等，状态机禁止跳步，关闭后须带原因重开，并持久化", async () => {
  const cookie = await session("security");
  const payload = { cveId: "CVE-2024-3094" };
  const first = await (await request("/notify", cookie, payload)).json();
  assert.ok(first.count >= 0);
  assert.equal(
    (await (await request("/notify", cookie, payload)).json()).count,
    0,
  );
  let db = await (await request("/state", cookie)).json();
  const t = db.tasks.find((t) => t.status === "已通报");
  assert.equal(
    (await request("/tasks/" + t.id, cookie, { status: "已关闭" }, "PATCH"))
      .status,
    400,
  );
  for (const status of ["已确认", "修复中", "验证中", "已关闭"])
    assert.equal(
      (await request("/tasks/" + t.id, cookie, { status }, "PATCH")).status,
      200,
    );
  assert.equal(
    (await request("/tasks/" + t.id, cookie, { status: "已确认" }, "PATCH"))
      .status,
    400,
  );
  assert.equal(
    (
      await request(
        "/tasks/" + t.id,
        cookie,
        { status: "已确认", reason: "回归测试未通过" },
        "PATCH",
      )
    ).status,
    200,
  );
  const disk = JSON.parse(await readFile(path.join(dir, "db.json"), "utf8"));
  assert.equal(
    disk.tasks.find((x) => x.id === t.id).history.at(-1).reason,
    "回归测试未通过",
  );
});
test("用户反馈进入仅 PM 可见的 VOC 并可形成需求", async () => {
  const cookie = await session("developer");
  assert.equal(
    (
      await request("/feedback", cookie, {
        rating: 5,
        text: "需要不同项目的对比分析",
        tag: "缺少信息",
        cveId: "CVE-2024-38816",
      })
    ).status,
    200,
  );
  const pm = await session("pm");
  const db = await (await request("/state", pm)).json();
  assert.ok(db.feedback.some((f) => f.text === "需要不同项目的对比分析"));
  const rows = await (await request("/factory", pm, {})).json();
  assert.equal(rows.length, 3);
  assert.equal(
    (await request("/requirements/" + rows[0].id, pm, {}, "PATCH")).status,
    200,
  );
});
