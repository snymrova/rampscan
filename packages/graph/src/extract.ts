import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { posix } from "node:path";
import ts from "typescript";

// The M4 code graph — plan §M4, SPEC §3 (graph.db). TypeScript/JavaScript
// only in the prototype, by design.
//
// Parsing is the TypeScript compiler's; resolution is deliberately NOT a
// full SCIP index (the plan's own risk table names that rabbit hole). The
// layering is the same as the code-graph doc §3.2 — structure plus resolved
// references — with resolution done lexically:
//
//   exact    — the edge target came from a lexical fact: a local declaration,
//              an import binding, or a resolved relative module path.
//   inferred — the target was matched by name across the project (unique
//              match only; ambiguous names produce no edge).
//
// Every edge carries its resolution, so downstream queries can say which
// claims rest on inference. scip-typescript slots in later behind the same
// node/edge schema.

export type NodeKind = "file" | "symbol" | "dependency" | "route";
export type EdgeKind = "imports" | "declares" | "exports" | "calls" | "handles";
export type Resolution = "exact" | "inferred";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  /** display name: repo-relative path, symbol name, package[/subpath], "GET /x" */
  name: string;
  /** repo-relative source file (file / symbol / route nodes) */
  path?: string;
  /** 1-based line of the declaration (symbol / route nodes) */
  line?: number;
  /** dependency nodes: the npm package the node belongs to */
  package?: string;
}

export interface GraphEdge {
  src: string;
  dst: string;
  kind: EdgeKind;
  resolution: Resolution;
  detail?: string;
}

export interface RouteDecl {
  id: string;
  method: string;
  routePath: string;
  file: string; // repo-relative
  line: number;
}

export interface ExtractedGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  routes: RouteDecl[];
  /** repo-relative source files walked, sorted */
  files: string[];
}

export const fileId = (rel: string): string => `file:${rel}`;
export const symId = (rel: string, name: string): string => `sym:${rel}#${name}`;
export const depId = (pkg: string): string => `dep:${pkg}`;
export const depMemberId = (pkg: string, member: string): string => `dep:${pkg}#${member}`;
export const routeNodeId = (method: string, routePath: string): string =>
  `route:${method} ${routePath}`;

const SOURCE_EXT = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx"];
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".turbo",
  "vendor",
]);
const ROUTE_METHODS = new Set(["get", "post", "put", "delete", "patch", "options", "head", "all"]);

/** repo-relative source files, sorted, skipping build/dependency dirs */
export async function listSourceFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  async function walk(relDir: string): Promise<void> {
    const entries = await readdir(join(root, relDir), { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith(".") && entry.name !== ".") {
        if (entry.isDirectory()) continue; // dotdirs (.git, .next) never hold app entry points
      }
      const rel = relDir === "" ? entry.name : posix.join(relDir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(rel);
      } else if (SOURCE_EXT.some((e) => entry.name.endsWith(e)) && !entry.name.endsWith(".d.ts")) {
        files.push(rel);
      }
    }
  }
  await walk("");
  return files.sort();
}

/** "lodash/merge" → { pkg: "lodash", member: "merge" }; "@scope/pkg/x" keeps the scope */
export function packageOf(spec: string): { pkg: string; member?: string } {
  const parts = spec.split("/");
  const pkg = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0]!;
  const rest = spec.slice(pkg.length + 1);
  return rest ? { pkg, member: rest } : { pkg };
}

/** resolve a relative import against the walked file set; undefined = unresolved */
export function resolveRelative(
  fromRel: string,
  spec: string,
  fileSet: ReadonlySet<string>,
): string | undefined {
  const base = posix.normalize(posix.join(posix.dirname(fromRel), spec));
  const candidates = [base];
  for (const e of SOURCE_EXT) candidates.push(base + e);
  const jsExt = /\.(js|mjs|cjs|jsx)$/;
  if (jsExt.test(base)) {
    // TS convention: "./x.js" in source resolves to x.ts on disk
    const stripped = base.replace(jsExt, "");
    for (const e of SOURCE_EXT) candidates.push(stripped + e);
  }
  for (const e of SOURCE_EXT) candidates.push(posix.join(base, "index" + e));
  return candidates.find((c) => fileSet.has(c));
}

type AliasTarget =
  | { kind: "dep"; pkg: string; member?: string }
  | { kind: "file"; rel: string; member?: string }
  | { kind: "phantom"; id: string }; // unresolved relative import

interface CallSite {
  scope: string;
  callee: { form: "ident"; name: string } | { form: "member"; obj: string; name: string };
}

interface PendingHandler {
  routeId: string;
  name: string; // identifier passed as a route handler / middleware
}

interface FileInfo {
  rel: string;
  decls: Map<string, string>; // local symbol name → symbol node id
  aliases: Map<string, AliasTarget>; // imported binding → target
  exportNames: Set<string>;
  callSites: CallSite[];
  pendingHandlers: PendingHandler[];
}

class GraphBuilder {
  nodes = new Map<string, GraphNode>();
  edges = new Map<string, GraphEdge>();
  routes = new Map<string, RouteDecl>();

  node(n: GraphNode): string {
    const existing = this.nodes.get(n.id);
    if (!existing) this.nodes.set(n.id, n);
    else if (existing.line === undefined && n.line !== undefined) this.nodes.set(n.id, n);
    return n.id;
  }

  edge(e: GraphEdge): void {
    const key = `${e.src}|${e.dst}|${e.kind}`;
    const existing = this.edges.get(key);
    // an exact observation of the same edge beats an inferred one
    if (!existing || (existing.resolution === "inferred" && e.resolution === "exact")) {
      this.edges.set(key, e);
    }
  }
}

/** create the dependency node(s) for an import spec and return the import target id */
function depTarget(b: GraphBuilder, pkg: string, member?: string): string {
  const pkgId = b.node({ id: depId(pkg), kind: "dependency", name: pkg, package: pkg });
  if (!member) return pkgId;
  const memberId = b.node({
    id: depMemberId(pkg, member),
    kind: "dependency",
    name: `${pkg}/${member}`,
    package: pkg,
  });
  // member → package, so package-level reachability follows from any member
  b.edge({ src: memberId, dst: pkgId, kind: "imports", resolution: "exact" });
  return memberId;
}

export async function extractGraph(root: string, files?: string[]): Promise<ExtractedGraph> {
  const rels = files ?? (await listSourceFiles(root));
  const fileSet = new Set(rels);
  const b = new GraphBuilder();
  const infos = new Map<string, FileInfo>();

  for (const rel of rels) {
    b.node({ id: fileId(rel), kind: "file", name: rel, path: rel });
  }

  // ---- pass 1: per-file lexical facts + call sites --------------------------
  for (const rel of rels) {
    const source = await readFile(join(root, rel), "utf8");
    const sf = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true);
    const info: FileInfo = {
      rel,
      decls: new Map(),
      aliases: new Map(),
      exportNames: new Set(),
      callSites: [],
      pendingHandlers: [],
    };
    infos.set(rel, info);
    walkSourceFile(sf, rel, info, b, fileSet);
  }

  // ---- pass 2: resolve exports, call sites, route handlers ------------------
  const globalDecls = new Map<string, string[]>(); // name → symbol ids across the project
  for (const info of infos.values()) {
    for (const [name, id] of info.decls) {
      const list = globalDecls.get(name);
      if (list) list.push(id);
      else globalDecls.set(name, [id]);
    }
  }

  const resolveTarget = (
    info: FileInfo,
    name: string,
  ): { id: string; resolution: Resolution; detail?: string } | undefined => {
    const local = info.decls.get(name);
    if (local) return { id: local, resolution: "exact" };
    const alias = info.aliases.get(name);
    if (alias) return resolveAlias(alias, name);
    const hits = globalDecls.get(name);
    if (hits && hits.length === 1) return { id: hits[0]!, resolution: "inferred" };
    return undefined; // ambiguous or unknown — no edge beats a wrong edge
  };

  const resolveAlias = (
    alias: AliasTarget,
    boundName: string,
  ): { id: string; resolution: Resolution; detail?: string } => {
    switch (alias.kind) {
      case "dep":
        return {
          id: alias.member ? depMemberId(alias.pkg, alias.member) : depId(alias.pkg),
          resolution: "exact",
        };
      case "file": {
        if (alias.member) {
          const target = infos.get(alias.rel)?.decls.get(alias.member);
          if (target) return { id: target, resolution: "exact" };
          return { id: fileId(alias.rel), resolution: "inferred", detail: alias.member };
        }
        return { id: fileId(alias.rel), resolution: "exact", detail: boundName };
      }
      case "phantom":
        return { id: alias.id, resolution: "inferred" };
    }
  };

  for (const info of infos.values()) {
    for (const name of info.exportNames) {
      const target = info.decls.get(name);
      if (target) {
        b.edge({ src: fileId(info.rel), dst: target, kind: "exports", resolution: "exact" });
      }
    }
    for (const site of info.callSites) {
      if (site.callee.form === "ident") {
        const r = resolveTarget(info, site.callee.name);
        if (r) {
          b.edge({
            src: site.scope,
            dst: r.id,
            kind: "calls",
            resolution: r.resolution,
            ...(r.detail !== undefined ? { detail: r.detail } : {}),
          });
        }
        continue;
      }
      // member call obj.name(...)
      const alias = info.aliases.get(site.callee.obj);
      if (alias) {
        if (alias.kind === "dep") {
          const target = depTarget(b, alias.pkg, alias.member ?? site.callee.name);
          b.edge({ src: site.scope, dst: target, kind: "calls", resolution: "exact" });
          continue;
        }
        if (alias.kind === "file") {
          const target = infos.get(alias.rel)?.decls.get(site.callee.name);
          b.edge({
            src: site.scope,
            dst: target ?? fileId(alias.rel),
            kind: "calls",
            resolution: target ? "exact" : "inferred",
            detail: site.callee.name,
          });
          continue;
        }
        b.edge({
          src: site.scope,
          dst: alias.id,
          kind: "calls",
          resolution: "inferred",
          detail: site.callee.name,
        });
        continue;
      }
      const hits = globalDecls.get(site.callee.name);
      if (hits && hits.length === 1) {
        b.edge({ src: site.scope, dst: hits[0]!, kind: "calls", resolution: "inferred" });
      }
    }
    for (const pending of info.pendingHandlers) {
      const r = resolveTarget(info, pending.name);
      if (r) {
        b.edge({ src: pending.routeId, dst: r.id, kind: "handles", resolution: r.resolution });
      }
    }
  }

  return {
    nodes: [...b.nodes.values()],
    edges: [...b.edges.values()],
    routes: [...b.routes.values()],
    files: rels,
  };
}

function walkSourceFile(
  sf: ts.SourceFile,
  rel: string,
  info: FileInfo,
  b: GraphBuilder,
  fileSet: ReadonlySet<string>,
): void {
  const lineOf = (node: ts.Node): number =>
    sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

  const importTarget = (spec: string): AliasTarget => {
    if (spec.startsWith(".") || spec.startsWith("/")) {
      const resolved = resolveRelative(rel, spec, fileSet);
      if (resolved) return { kind: "file", rel: resolved };
      const id = b.node({
        id: fileId(posix.normalize(posix.join(posix.dirname(rel), spec))),
        kind: "file",
        name: spec,
      });
      return { kind: "phantom", id };
    }
    return { kind: "dep", ...packageOf(spec) };
  };

  const importEdge = (target: AliasTarget): void => {
    const dst =
      target.kind === "dep"
        ? depTarget(b, target.pkg, target.member)
        : target.kind === "file"
          ? fileId(target.rel)
          : target.id;
    b.edge({
      src: fileId(rel),
      dst,
      kind: "imports",
      resolution: target.kind === "phantom" ? "inferred" : "exact",
    });
  };

  const declareSymbol = (name: string, at: ts.Node, exported: boolean): string => {
    const id = b.node({
      id: symId(rel, name),
      kind: "symbol",
      name,
      path: rel,
      line: lineOf(at),
    });
    info.decls.set(name, id);
    b.edge({ src: fileId(rel), dst: id, kind: "declares", resolution: "exact" });
    if (exported) info.exportNames.add(name);
    return id;
  };

  const isExported = (node: ts.HasModifiers): boolean =>
    ts.getModifiers(node)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;

  const requireSpec = (node: ts.Node): string | undefined => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "require" &&
      node.arguments.length === 1 &&
      ts.isStringLiteralLike(node.arguments[0]!)
    ) {
      return (node.arguments[0] as ts.StringLiteralLike).text;
    }
    return undefined;
  };

  const visit = (node: ts.Node, scope: string): void => {
    // ---- imports ----
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
      const spec = node.moduleSpecifier.text;
      const root = importTarget(spec);
      importEdge(root);
      const clause = node.importClause;
      if (clause) {
        if (clause.name) info.aliases.set(clause.name.text, root);
        const bindings = clause.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings)) {
          info.aliases.set(bindings.name.text, root);
        } else if (bindings && ts.isNamedImports(bindings)) {
          for (const el of bindings.elements) {
            const member = (el.propertyName ?? el.name).text;
            const target: AliasTarget =
              root.kind === "dep"
                ? { kind: "dep", pkg: root.pkg, member: root.member ?? member }
                : root.kind === "file"
                  ? { kind: "file", rel: root.rel, member }
                  : root;
            if (target.kind === "dep") depTarget(b, target.pkg, target.member);
            info.aliases.set(el.name.text, target);
          }
        }
      }
      return;
    }

    if (ts.isExportDeclaration(node)) {
      if (node.exportClause && ts.isNamedExports(node.exportClause)) {
        for (const el of node.exportClause.elements) {
          info.exportNames.add((el.propertyName ?? el.name).text);
        }
      }
      return;
    }

    if (ts.isExportAssignment(node)) {
      collectExportedExpr(node.expression);
      return;
    }

    // module.exports = …  /  exports.name = …
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left)
    ) {
      const left = node.left;
      const isModuleExports =
        ts.isIdentifier(left.expression) &&
        left.expression.text === "module" &&
        left.name.text === "exports";
      const isExportsMember = ts.isIdentifier(left.expression) && left.expression.text === "exports";
      if (isModuleExports) {
        collectExportedExpr(node.right);
        visit(node.right, scope);
        return;
      }
      if (isExportsMember) {
        const name = left.name.text;
        if (ts.isFunctionExpression(node.right) || ts.isArrowFunction(node.right)) {
          const id = declareSymbol(name, node, false);
          info.exportNames.add(name);
          visit(node.right.body, id);
          return;
        }
        if (ts.isIdentifier(node.right)) info.exportNames.add(node.right.text);
        else info.exportNames.add(name);
      }
    }

    // ---- declarations ----
    if (ts.isFunctionDeclaration(node) && node.name) {
      const id = declareSymbol(node.name.text, node, isExported(node));
      if (node.body) visit(node.body, id);
      return;
    }

    if (ts.isClassDeclaration(node) && node.name) {
      const cls = node.name.text;
      declareSymbol(cls, node, isExported(node));
      for (const member of node.members) {
        if (
          (ts.isMethodDeclaration(member) || ts.isConstructorDeclaration(member)) &&
          member.body
        ) {
          const name = ts.isConstructorDeclaration(member)
            ? `${cls}.constructor`
            : `${cls}.${(member.name as ts.Identifier).text ?? "method"}`;
          const id = declareSymbol(name, member, false);
          visit(member.body, id);
        }
      }
      return;
    }

    if (ts.isVariableStatement(node)) {
      const exported = isExported(node);
      for (const decl of node.declarationList.declarations) {
        const spec = decl.initializer ? requireSpec(decl.initializer) : undefined;
        if (spec !== undefined) {
          const root = importTarget(spec);
          importEdge(root);
          if (ts.isIdentifier(decl.name)) {
            info.aliases.set(decl.name.text, root);
          } else if (ts.isObjectBindingPattern(decl.name)) {
            for (const el of decl.name.elements) {
              if (!ts.isIdentifier(el.name)) continue;
              const member = el.propertyName && ts.isIdentifier(el.propertyName)
                ? el.propertyName.text
                : el.name.text;
              const target: AliasTarget =
                root.kind === "dep"
                  ? { kind: "dep", pkg: root.pkg, member: root.member ?? member }
                  : root.kind === "file"
                    ? { kind: "file", rel: root.rel, member }
                    : root;
              if (target.kind === "dep") depTarget(b, target.pkg, target.member);
              info.aliases.set(el.name.text, target);
            }
          }
          continue;
        }
        if (
          ts.isIdentifier(decl.name) &&
          decl.initializer &&
          (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))
        ) {
          const id = declareSymbol(decl.name.text, decl, exported);
          visit(decl.initializer.body, id);
          continue;
        }
        if (decl.initializer) visit(decl.initializer, scope);
        if (exported && ts.isIdentifier(decl.name)) info.exportNames.add(decl.name.text);
      }
      return;
    }

    // ---- calls ----
    if (ts.isCallExpression(node)) {
      const spec = requireSpec(node);
      if (spec !== undefined) {
        importEdge(importTarget(spec));
        return;
      }
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteralLike(arg)) importEdge(importTarget(arg.text));
        return;
      }

      // route registration: app.get("/path", …handlers) — express-style
      if (
        ts.isPropertyAccessExpression(node.expression) &&
        ROUTE_METHODS.has(node.expression.name.text) &&
        node.arguments.length >= 2 &&
        ts.isStringLiteralLike(node.arguments[0]!) &&
        (node.arguments[0] as ts.StringLiteralLike).text.startsWith("/")
      ) {
        const method = node.expression.name.text.toUpperCase();
        const routePath = (node.arguments[0] as ts.StringLiteralLike).text;
        const rid = routeNodeId(method, routePath);
        b.node({ id: rid, kind: "route", name: `${method} ${routePath}`, path: rel, line: lineOf(node) });
        if (!b.routes.has(rid)) {
          b.routes.set(rid, { id: rid, method, routePath, file: rel, line: lineOf(node) });
        }
        node.arguments.slice(1).forEach((arg, i) => {
          if (ts.isIdentifier(arg)) {
            info.pendingHandlers.push({ routeId: rid, name: arg.text });
          } else if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
            const name = `${method} ${routePath} handler${i > 0 ? ` ${i + 1}` : ""}`;
            const id = declareSymbol(name, arg, false);
            b.edge({ src: rid, dst: id, kind: "handles", resolution: "exact" });
            visit(arg.body, id);
          }
        });
        return;
      }

      if (ts.isIdentifier(node.expression)) {
        info.callSites.push({ scope, callee: { form: "ident", name: node.expression.text } });
      } else if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression)
      ) {
        info.callSites.push({
          scope,
          callee: {
            form: "member",
            obj: node.expression.expression.text,
            name: node.expression.name.text,
          },
        });
      }
      node.arguments.forEach((a) => visit(a, scope));
      return;
    }

    ts.forEachChild(node, (child) => visit(child, scope));
  };

  function collectExportedExpr(expr: ts.Expression): void {
    if (ts.isIdentifier(expr)) {
      info.exportNames.add(expr.text);
      return;
    }
    if (ts.isObjectLiteralExpression(expr)) {
      for (const prop of expr.properties) {
        if (ts.isShorthandPropertyAssignment(prop)) info.exportNames.add(prop.name.text);
        else if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.initializer)) {
          info.exportNames.add(prop.initializer.text);
        } else if (
          ts.isPropertyAssignment(prop) &&
          ts.isIdentifier(prop.name) &&
          (ts.isArrowFunction(prop.initializer) || ts.isFunctionExpression(prop.initializer))
        ) {
          const id = b.node({
            id: symId(rel, prop.name.text),
            kind: "symbol",
            name: prop.name.text,
            path: rel,
            line: sf.getLineAndCharacterOfPosition(prop.getStart(sf)).line + 1,
          });
          info.decls.set(prop.name.text, id);
          b.edge({ src: fileId(rel), dst: id, kind: "declares", resolution: "exact" });
          info.exportNames.add(prop.name.text);
        }
      }
    }
  }

  visit(sf, fileId(rel));
}
