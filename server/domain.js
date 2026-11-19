import semver from "semver";
import { XMLParser } from "fast-xml-parser";
export const states = ["已通报", "已确认", "修复中", "验证中", "已关闭"];
export function score(v) {
  return Math.round(
    v.cvss * 3 +
      v.exploit * 0.25 +
      v.heat * 0.15 +
      v.impact * 0.2 +
      v.urgent * 0.1,
  );
}
export function matches(component, vuln) {
  return (
    component.name.toLowerCase() === vuln.component.toLowerCase() &&
    !!semver.valid(semver.coerce(component.version)) &&
    semver.satisfies(semver.coerce(component.version), vuln.range)
  );
}
export function parseSbom(text, filename) {
  let components = [];
  if (filename.endsWith("pom.xml")) {
    const xml = new XMLParser({ ignoreAttributes: false }).parse(text);
    let deps = xml.project?.dependencies?.dependency || [];
    if (!Array.isArray(deps)) deps = [deps];
    components = deps.map((d) => ({
      name: String(d.artifactId || ""),
      version: String(d.version || ""),
    }));
  } else if (filename.endsWith("go.mod")) {
    components = [
      ...text.matchAll(/^\s*([\w./-]+)\s+v([\d.]+)(?:[^\n]*)$/gm),
    ].map((m) => ({ name: m[1], version: m[2] }));
  } else {
    const j = JSON.parse(text);
    if (j.bomFormat === "CycloneDX")
      components = (j.components || []).map((c) => ({
        name: c.name,
        version: c.version,
      }));
    else if (j.spdxVersion)
      components = (j.packages || []).map((c) => ({
        name: c.name,
        version: c.versionInfo,
      }));
    else if (j.dependencies || j.devDependencies)
      components = Object.entries({
        ...j.dependencies,
        ...j.devDependencies,
      }).map(([name, version]) => ({ name, version }));
    else
      throw new Error("无法识别格式，请导入 CycloneDX、SPDX 或 package.json");
  }
  if (!components.length) throw new Error("文件中没有可导入的依赖组件");
  if (components.some((c) => !c.name || !semver.coerce(c.version)))
    throw new Error("包含缺失或无法解析的版本，请使用已解析的 SBOM 版本");
  if (components.some((c) => /^[~^*><=]|\|\||\$\{/.test(c.version)))
    throw new Error(
      "依赖包含版本范围，无法确认实际安装版本，请改用 CycloneDX/SPDX 或填写精确版本",
    );
  return components.map((c) => ({
    ...c,
    version: String(c.version),
    managed: false,
  }));
}
export function visibleProjects(db, role) {
  return db.projects.filter(
    (p) =>
      !["developer", "sre"].includes(role) ||
      (role === "developer"
        ? [1, 3].includes(p.id)
        : [1, 2, 4, 5].includes(p.id)),
  );
}
export function publicState(db, role) {
  const projects = visibleProjects(db, role);
  const ids = projects.map((p) => p.id);
  const tasks = db.tasks
    .filter((t) => ids.includes(t.projectId))
    .map((t) => {
      const project = projects.find((p) => p.id === t.projectId);
      const blastRadius = db.servers.filter(
        (s) => s.projectId === project.id,
      ).length;
      const exposure =
        project.zone === "Public DMZ"
          ? 3
          : project.zone === "Isolated PCI"
            ? 1
            : 2;
      return { ...t, priority: project.criticality * blastRadius * exposure };
    })
    .sort((a, b) => b.priority - a.priority);
  return {
    ...db,
    projects,
    servers: db.servers.filter((s) => ids.includes(s.projectId)),
    tasks,
    feedback: role === "pm" ? db.feedback : [],
    personas: role === "pm" ? db.personas : [],
    requirements: role === "pm" ? db.requirements : [],
    audit: ["security", "director"].includes(role) ? db.audit : [],
  };
}
