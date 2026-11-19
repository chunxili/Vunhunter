import test from "node:test";
import assert from "node:assert/strict";
import { parseSbom, matches, score, publicState } from "../server/domain.js";
import { seed } from "../server/seed.js";
test("评分使用 PRD 五项权重", () =>
  assert.equal(
    score({ cvss: 10, exploit: 100, heat: 100, impact: 100, urgent: 100 }),
    100,
  ));
test("版本匹配必须遵守漏洞区间与组件名称", () => {
  const v = { component: "xz", range: ">=5.6.0 <5.6.2" };
  assert.equal(matches({ name: "xz", version: "5.6.1" }, v), true);
  assert.equal(matches({ name: "xz", version: "5.4.0" }, v), false);
  assert.equal(matches({ name: "xz", version: "5.6.2" }, v), false);
  assert.equal(matches({ name: "other", version: "5.6.1" }, v), false);
});
test("支持五种文档要求的 SBOM 输入", () => {
  for (const [text, file] of [
    [
      JSON.stringify({
        bomFormat: "CycloneDX",
        components: [{ name: "xz", version: "5.6.1" }],
      }),
      "bom.json",
    ],
    [
      JSON.stringify({
        spdxVersion: "SPDX-2.3",
        packages: [{ name: "xz", versionInfo: "5.6.1" }],
      }),
      "spdx.json",
    ],
    [JSON.stringify({ dependencies: { xz: "5.6.1" } }), "package.json"],
    [
      "<project><dependencies><dependency><artifactId>xz</artifactId><version>5.6.1</version></dependency></dependencies></project>",
      "pom.xml",
    ],
    ["module test\nrequire (\n example.com/xz v5.6.1\n)\n", "go.mod"],
  ])
    assert.equal(parseSbom(text, file)[0].version, "5.6.1");
});
test("拒绝把版本范围当作真实安装版本", () =>
  assert.throws(
    () => parseSbom('{"dependencies":{"xz":"^5.6.1"}}', "package.json"),
    /精确版本/,
  ));
test("开发角色的项目、任务及服务器都必须按授权隔离", () => {
  const s = publicState(seed(), "developer");
  assert.deepEqual(
    s.projects.map((p) => p.id),
    [1, 3],
  );
  assert.ok(s.tasks.every((t) => [1, 3].includes(t.projectId)));
  assert.ok(s.servers.every((t) => [1, 3].includes(t.projectId)));
  assert.equal(s.feedback.length, 0);
  assert.equal(s.personas.length, 0);
  assert.equal(s.audit.length, 0);
});
test("种子资产规模符合 PRD 的五项目演示约束", () => {
  const d = seed();
  assert.equal(d.projects.length, 5);
  assert.equal(
    d.projects.reduce((s, p) => s + p.components.length, 0),
    61,
  );
  assert.equal(d.servers.length, 92);
  assert.equal(d.vulnerabilities.length, 12);
});
