// JSON Schema 转成页面类型，不依赖外部包。
const HEADER = [
  "// 自动生成，不要手改。",
  "// 重新生成：cargo run -q -p wharf-cli -- schema web | node web/scripts/gen-types.mjs > web/src/types.gen.ts",
].join("\n");

function fail(path, reason) {
  throw new Error(`${path}：${reason}`);
}

function comment(description, indent = "") {
  if (!description) return "";
  const lines = description.replaceAll("*/", "* /").split("\n");
  return `${indent}/**\n${lines.map(line => `${indent} * ${line}`).join("\n")}\n${indent} */\n`;
}

function fields(schema, path) {
  const required = new Set(schema.required ?? []);
  return Object.entries(schema.properties).map(([name, field]) => {
    const key = /^[a-zA-Z_$][\w$]*$/.test(name) ? name : JSON.stringify(name);
    return comment(field.description, "  ")
      + `  ${key}${required.has(name) ? "" : "?"}: ${type(field, `${path}.${name}`)};`;
  }).join("\n");
}

function type(schema, path) {
  if (schema === true || schema === false || Object.keys(schema).length === 0) {
    return "unknown";
  }
  for (const key of ["allOf", "not", "prefixItems", "if", "then", "else"]) {
    if (key in schema) fail(path, `不支持 ${key}`);
  }
  if ("const" in schema) {
    const value = schema.const;
    if (value !== null && !["string", "number", "boolean"].includes(typeof value)) {
      fail(path, "const 只支持字符串、数字、布尔或 null");
    }
    return JSON.stringify(value);
  }
  if (schema.$ref) {
    if (!schema.$ref.startsWith("#/$defs/")) fail(path, `不支持引用 ${schema.$ref}`);
    return schema.$ref.slice("#/$defs/".length);
  }
  const union = schema.oneOf ?? schema.anyOf;
  if (union) {
    const variants = union.map((s, i) => type(s, `${path}[${i}]`)).join(" | ");
    return schema.properties ? `(${variants}) & {
${fields(schema, path)}
}` : variants;
  }
  if (Array.isArray(schema.type)) {
    return schema.type.map(t => type({ ...schema, type: t }, path)).join(" | ");
  }
  if (schema.type === undefined) {
    // 只有 default、description 这类注解，没有类型约束。
    if (Array.isArray(schema.enum)) {
      return schema.enum.map(value => JSON.stringify(value)).join(" | ");
    }
    return "unknown";
  }
  switch (schema.type) {
    case "object":
      if (schema.properties) return `{\n${fields(schema, path)}\n}`;
      if ("additionalProperties" in schema) {
        return `Record<string, ${type(schema.additionalProperties, `${path}.*`)}>`;
      }
      return "unknown";
    case "string":
      if (schema.enum) {
        return schema.enum.map(value => JSON.stringify(value)).join(" | ");
      }
      return "string";
    case "boolean":
      return "boolean";
    case "integer":
    case "number":
      return "number";
    case "null":
      return "null";
    case "array": {
      if (!schema.items || Array.isArray(schema.items)) fail(path, "数组缺少受支持的 items");
      const item = type(schema.items, `${path}[]`);
      return `${item.includes(" | ") ? `(${item})` : item}[]`;
    }
    default:
      fail(path, `不支持的 schema：${JSON.stringify(schema)}`);
  }
}

try {
  // 先拼好再解码：逐块转字符串会把块边界上的汉字切坏。
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = Buffer.concat(chunks).toString("utf8");
  const schema = JSON.parse(input);
  const output = Object.entries(schema.$defs).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([name, definition]) => {
      const value = type(definition, name);
      const declaration = definition.type === "object" && definition.properties && !definition.oneOf && !definition.anyOf
        ? `export interface ${name} ${value}`
        : `export type ${name} = ${value};`;
      return comment(definition.description) + declaration;
    });
  process.stdout.write(`${HEADER}\n\n${output.join("\n\n")}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
