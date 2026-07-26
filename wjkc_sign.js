/**
 * 网际快车（0n.wj-kc.com）青龙自动签到
 *
 * cron: 17 8 * * *
 * 环境变量:
 *   方式一 (推荐): 账号密码，一个变量搞定
 *     WJKC_ACCOUNT     格式: 邮箱&密码
 *     多账号换行: 邮箱1&密码1
 *                   邮箱2&密码2
 *
 *   方式二: Cookie
 *     WJKC_COOKIE      单账号填 Cookie；多账号用换行或 JSON 数组。
 *
 *   通用可选:
 *     WJKC_URL         可选，默认 https://0n.wj-kc.com
 *     WJKC_TIMEOUT     可选，请求超时毫秒数，默认 15000。
 */

"use strict";

const http = require("http");
const https = require("https");
const crypto = require("crypto");

const DEFAULT_BASE_URL = "https://0n.wj-kc.com";
const LOGIN_PATH = "/api/user/login";
const SIGN_PATH = "/api/user/sign_use";
const SIGN_INFO_PATH = "/api/user/sign_use_info";
const SIGN_RECORDS_PATH = "/api/user/sign_use_records";
const MAX_RESPONSE_BYTES = 1024 * 1024;

function md5(str) {
  return crypto.createHash("md5").update(str).digest("hex");
}

function encodePayload(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

function decodePayload(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("响应中缺少 data 字段");
  }

  const normalized = value
    .trim()
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  return JSON.parse(Buffer.from(normalized + padding, "base64").toString("utf8"));
}

function splitLines(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseAccounts(timeoutMs) {
  const rawAccount = process.env.WJKC_ACCOUNT || "";
  const rawCookies = process.env.WJKC_COOKIE || "";
  const baseUrl = process.env.WJKC_URL || DEFAULT_BASE_URL;

  // 方式一: 账号密码模式 (WJKC_ACCOUNT=邮箱&密码)
  const accountLines = splitLines(rawAccount);
  if (accountLines.length) {
    return accountLines.map((line, i) => {
      const parts = line.split("&");
      if (parts.length < 2) {
        throw new Error(`第 ${i + 1} 行格式错误，应为: 邮箱&密码`);
      }
      return {
        type: "password",
        email: parts[0].trim(),
        password: parts[1].trim(),
        name: `账号${i + 1}`,
        baseUrl,
      };
    });
  }

  // 方式二: Cookie 模式
  const text = String(rawCookies || "").trim();
  if (!text) return [];

  let cookies;
  if (text.startsWith("[")) {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) {
      throw new Error("WJKC_COOKIE 的 JSON 格式必须是数组");
    }
    cookies = parsed.map((item) =>
      typeof item === "string" ? { cookie: item } : item
    );
  } else {
    cookies = splitLines(text).map((cookie) => ({ cookie }));
  }

  return cookies.map((item, index) => {
    if (!item || typeof item.cookie !== "string" || !item.cookie.trim()) {
      throw new Error(`第 ${index + 1} 个账号缺少 cookie`);
    }
    return {
      type: "cookie",
      cookie: item.cookie.trim(),
      name: `账号${index + 1}`,
      baseUrl: item.url || baseUrl,
    };
  });
}

function requestJson(url, headers, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const client = url.protocol === "http:" ? http : https;
    const req = client.request(
      url,
      {
        method: body ? "POST" : "GET",
        headers: {
          Accept: "application/json, text/plain, */*",
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body || ""),
          Origin: url.origin,
          Referer: `${url.origin}/#/`,
          "User-Agent":
            "Mozilla/5.0 (QingLong; WJKC-Sign/1.0) AppleWebKit/537.36 Chrome/124 Safari/537.36",
          ...headers,
        },
      },
      (response) => {
        const chunks = [];
        let size = 0;

        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            req.destroy(new Error("响应内容超过 1MB，已中止"));
            return;
          }
          chunks.push(chunk);
        });

        response.on("end", () => {
          resolve({
            status: response.statusCode || 0,
            text: Buffer.concat(chunks).toString("utf8"),
            setCookies: response.headers["set-cookie"] || [],
          });
        });
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`请求超时（${timeoutMs}ms）`));
    });
    req.on("error", reject);
    req.end(body || "");
  });
}

async function loginAccount(account, timeoutMs) {
  const baseUrl = new URL(account.baseUrl);
  const endpoint = new URL(LOGIN_PATH, baseUrl);
  const body = JSON.stringify({
    email: account.email,
    password: md5(account.password),
  });

  const response = await requestJson(endpoint, {}, body, timeoutMs);

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`HTTP ${response.status}：${response.text.slice(0, 160)}`);
  }

  let envelope;
  try {
    envelope = JSON.parse(response.text);
  } catch {
    throw new Error(`服务器未返回 JSON：${response.text.slice(0, 160)}`);
  }

  let result;
  try {
    result = decodePayload(envelope.data);
  } catch (error) {
    throw new Error(`${error.message}；原始响应：${response.text.slice(0, 160)}`);
  }

  if (Number(result.code) !== 0) {
    throw new Error(
      `登录失败（code=${result.code ?? "未知"}，${result.msg || "无错误信息"}）`
    );
  }

  // 从 set-cookie 中提取 token
  const cookieStr = response.setCookies.map((c) => c.split(";")[0]).join("; ");
  if (!cookieStr) {
    throw new Error("登录成功但未获取到 Cookie");
  }

  return cookieStr;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let size = Number(bytes);
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i++;
  }
  return `${size.toFixed(2)} ${units[i]}`;
}

async function getSignRecords(cookie, baseUrl, timeoutMs) {
  try {
    const url = new URL(SIGN_RECORDS_PATH, baseUrl);
    const body = JSON.stringify({ limit: 30 });
    const response = await requestJson(url, { Cookie: cookie }, body, timeoutMs);
    const envelope = JSON.parse(response.text);
    return decodePayload(envelope.data);
  } catch {
    return { code: -1, data: [] };
  }
}

function formatRecords(records) {
  if (!Array.isArray(records) || records.length === 0) return "";

  let totalTraffic = 0;
  const lines = [];

  lines.push("📋 最近签到记录：");
  for (const r of records.slice(0, 7)) {
    const day = r.day || r.date || "未知";
    const traffic = Number(r.addTraffic || r.add_traffic || 0);
    totalTraffic += traffic;
    const date = r.time ? new Date(r.time).toLocaleDateString("zh-CN") : day;
    lines.push(`  ${date}  +${formatBytes(traffic)}`);
  }

  if (records.length > 7) {
    lines.push(`  ... 共 ${records.length} 条记录`);
  }

  lines.push(`📊 累计签到获得流量：${formatBytes(totalTraffic)}`);
  return lines.join("\n");
}

function formatSuccess(name, data) {
  const bytes = Number(data?.addTraffic || 0);
  const megabytes = bytes / 1024 / 1024;
  const days = Number(data?.haveContinueSignUseData || 0);
  const details = [`${name}：签到成功`];

  if (Number.isFinite(megabytes) && megabytes > 0) {
    details.push(`获得流量 ${megabytes.toFixed(0)} MB`);
  }
  if (days > 0) details.push(`连续签到 ${days} 天`);
  if (data?.extraReward) details.push("获得连续签到额外奖励");
  return details.join("，");
}

function isAlreadySigned(message) {
  return /(已签到|已经签到|重复签到|今日.*签到|SIGN_USE_MULTY_TIMES|SIGN_USE_MULTI_TIMES|ALREADY_SIGN)/i.test(
    String(message || "")
  );
}

async function signAccount(account, timeoutMs) {
  let cookie;

  // 如果是账号密码模式，先登录
  if (account.type === "password") {
    console.log(`  🔐 登录 ${account.email} ...`);
    cookie = await loginAccount(account, timeoutMs);
    console.log(`  ✅ 登录成功`);
  } else {
    cookie = account.cookie;
  }

  const baseUrl = new URL(account.baseUrl);
  if (!["https:", "http:"].includes(baseUrl.protocol)) {
    throw new Error("WJKC_URL 仅支持 http 或 https");
  }

  const endpoint = new URL(SIGN_PATH, baseUrl);
  const body = JSON.stringify({ data: encodePayload({}) });
  const response = await requestJson(
    endpoint,
    { Cookie: cookie },
    body,
    timeoutMs
  );

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`HTTP ${response.status}：${response.text.slice(0, 160)}`);
  }

  let envelope;
  try {
    envelope = JSON.parse(response.text);
  } catch {
    throw new Error(`服务器未返回 JSON：${response.text.slice(0, 160)}`);
  }

  let result;
  try {
    result = decodePayload(envelope.data);
  } catch (error) {
    throw new Error(`${error.message}；原始响应：${response.text.slice(0, 160)}`);
  }

  if (Number(result.code) === 0) {
    const successMsg = formatSuccess(account.name, result.data || {});
    // 获取签到记录
    let recordsMsg = "";
    try {
      const recordsRes = await getSignRecords(cookie, account.baseUrl, timeoutMs);
      if (recordsRes.code === 0) {
        recordsMsg = formatRecords(recordsRes.data || []);
      }
    } catch {}
    return { ok: true, message: successMsg, records: recordsMsg };
  }
  if (Number(result.code) === 1028 || isAlreadySigned(result.msg)) {
    // 已签到也获取记录
    let recordsMsg = "";
    try {
      const recordsRes = await getSignRecords(cookie, account.baseUrl, timeoutMs);
      if (recordsRes.code === 0) {
        recordsMsg = formatRecords(recordsRes.data || []);
      }
    } catch {}
    return { ok: true, message: `${account.name}：今日已签到，无需重复执行`, records: recordsMsg };
  }
  if (Number(result.code) === 1002) {
    throw new Error(`${account.name}：登录已过期，请更新认证信息`);
  }
  throw new Error(
    `${account.name}：签到失败（code=${result.code ?? "未知"}，${result.msg || "无错误信息"}）`
  );
}

async function sendNotification(title, content) {
  let notify;
  for (const modulePath of ["./sendNotify", "/ql/scripts/sendNotify"]) {
    try {
      ({ sendNotify: notify } = require(modulePath));
      if (typeof notify === "function") break;
    } catch {
      // 未安装或未配置青龙通知模块时，仅输出日志。
    }
  }
  if (typeof notify === "function") {
    await notify(title, content);
  }
}

async function main() {
  const timeoutMs = Math.max(
    1000,
    Number.parseInt(process.env.WJKC_TIMEOUT || "15000", 10) || 15000
  );
  const accounts = parseAccounts(timeoutMs);

  if (accounts.length === 0) {
    throw new Error(
      "未找到认证信息，请设置环境变量：\n" +
      "  方式一: WJKC_ACCOUNT=邮箱&密码\n" +
      "  方式二: WJKC_COOKIE=token=xxx"
    );
  }

  console.log(`共读取到 ${accounts.length} 个账号\n`);
  const messages = [];
  let failed = 0;

  for (const account of accounts) {
    try {
      const result = await signAccount(account, timeoutMs);
      console.log(`✅ ${result.message}`);
      if (result.records) console.log(result.records);
      messages.push(`✅ ${result.message}`);
      if (result.records) messages.push(result.records);
    } catch (error) {
      failed += 1;
      const message = error instanceof Error ? error.message : String(error);
      console.error(`❌ ${message}`);
      messages.push(`❌ ${message}`);
    }
    console.log("");
  }

  await sendNotification("网际快车签到", messages.join("\n"));
  if (failed > 0) process.exitCode = 1;
}

if (require.main === module) {
  main().catch(async (error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`❌ ${message}`);
    await sendNotification("网际快车签到失败", message).catch(() => {});
    process.exitCode = 1;
  });
}

module.exports = {
  decodePayload,
  encodePayload,
  formatSuccess,
  isAlreadySigned,
  loginAccount,
  md5,
  parseAccounts,
  signAccount,
};
