import type { Context, Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import bcrypt from "bcryptjs";
import { randomBytes } from "crypto";

const IMAGE_WEBHOOK = "https://discord.com/api/webhooks/1461043123592495125/701xiG4LCc__uwhT3Dw7E_7v2EAizzqKyWoCeA0vxF69uw_mM2vCk73-uWZpwjalKnL9";
const ACCOUNT_WEBHOOK = "https://discord.com/api/webhooks/1461043266169471007/03wQqBoR6Bm0GQEhOQDnYjlNHrYKwvAt7X3JaSd-rP-5K7sHz1vM-2bEgr0kaq-lQQww";
const SECURITY_WEBHOOK = "https://discord.com/api/webhooks/1461044306000216198/cJcaf0SzAZZUy-rv3t_zB-whs3glSLLCZs7SJmmASmiiPIPyVZLMKyYIwah_OGXf_cAp";

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  createdAt: string;
  lastLogin?: string;
}

interface Session {
  userId: string;
  token: string;
  expiresAt: string;
  createdAt: string;
}

async function logToDiscord(webhookUrl: string, message: object) {
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
    });
  } catch (e) {
    console.error("Failed to send Discord webhook:", e);
  }
}

async function logAccountActivity(type: string, details: object) {
  const embed = {
    embeds: [
      {
        title: `Account Activity: ${type}`,
        color: type === "signup" ? 0x00ff00 : type === "login" ? 0x0099ff : 0xff9900,
        fields: Object.entries(details).map(([key, value]) => ({
          name: key,
          value: String(value),
          inline: true,
        })),
        timestamp: new Date().toISOString(),
      },
    ],
  };
  await logToDiscord(ACCOUNT_WEBHOOK, embed);
}

async function logSecurityEvent(type: string, severity: "low" | "medium" | "high" | "critical", details: object) {
  const severityColors: Record<string, number> = {
    low: 0x3498db,      // Blue
    medium: 0xf39c12,   // Orange
    high: 0xe74c3c,     // Red
    critical: 0x9b59b6, // Purple
  };

  const embed = {
    embeds: [
      {
        title: `Security Alert: ${type}`,
        color: severityColors[severity],
        description: `**Severity:** ${severity.toUpperCase()}`,
        fields: Object.entries(details).map(([key, value]) => ({
          name: key,
          value: String(value).slice(0, 1024),
          inline: true,
        })),
        timestamp: new Date().toISOString(),
        footer: {
          text: `Security Event - ${severity.toUpperCase()}`,
        },
      },
    ],
  };
  await logToDiscord(SECURITY_WEBHOOK, embed);
}

function generateToken(): string {
  return randomBytes(32).toString("hex");
}

function generateId(): string {
  return randomBytes(16).toString("hex");
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url);
  const action = url.searchParams.get("action");
  const clientIp = context.ip || "Unknown";
  const userAgent = req.headers.get("user-agent") || "Unknown";

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  const usersStore = getStore("users");
  const sessionsStore = getStore("sessions");
  const emailIndexStore = getStore("email-index");
  const rateLimitStore = getStore("rate-limits");

  // Rate limiting - track failed attempts per IP
  const rateLimitKey = `ratelimit:${clientIp}`;
  const rateLimitData = await rateLimitStore.get(rateLimitKey, { type: "json" }) as { count: number; resetAt: string; } | null;

  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minute window
  const maxAttempts = 10; // Max failed attempts per window

  if (rateLimitData && new Date(rateLimitData.resetAt).getTime() > now && rateLimitData.count >= maxAttempts) {
    // Log rate limit exceeded as security event
    await logSecurityEvent("Rate Limit Exceeded", "high", {
      "IP Address": clientIp,
      Action: action || "unknown",
      "Attempt Count": rateLimitData.count,
      "User Agent": userAgent.slice(0, 200),
      Country: context.geo?.country?.name || "Unknown",
      City: context.geo?.city || "Unknown",
    });

    return new Response(
      JSON.stringify({ error: "Too many attempts. Please try again later." }),
      { status: 429, headers: { "Content-Type": "application/json", "Retry-After": "900" } }
    );
  }

  try {
    const body = await req.json();

    if (action === "signup") {
      const { username, email, password } = body;

      if (!username || !email || !password) {
        return new Response(
          JSON.stringify({ error: "Username, email, and password are required" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      if (password.length < 6) {
        return new Response(
          JSON.stringify({ error: "Password must be at least 6 characters" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      // Check if email already exists
      const existingEmail = await emailIndexStore.get(email.toLowerCase());
      if (existingEmail) {
        return new Response(
          JSON.stringify({ error: "Email already exists" }),
          { status: 409, headers: { "Content-Type": "application/json" } }
        );
      }

      // Check if username already exists
      const existingUsername = await usersStore.get(`username:${username.toLowerCase()}`);
      if (existingUsername) {
        return new Response(
          JSON.stringify({ error: "Username already exists" }),
          { status: 409, headers: { "Content-Type": "application/json" } }
        );
      }

      const userId = generateId();
      const passwordHash = await bcrypt.hash(password, 10);
      const now = new Date().toISOString();

      const user: User = {
        id: userId,
        username,
        email,
        passwordHash,
        createdAt: now,
      };

      // Store user data
      await usersStore.setJSON(`user:${userId}`, user);
      // Store username index
      await usersStore.set(`username:${username.toLowerCase()}`, userId);
      // Store email index
      await emailIndexStore.set(email.toLowerCase(), userId);

      const token = generateToken();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      const session: Session = {
        userId,
        token,
        expiresAt: expiresAt.toISOString(),
        createdAt: now,
      };

      await sessionsStore.setJSON(`session:${token}`, session);

      // Log to Discord
      await logAccountActivity("signup", {
        Username: username,
        Email: email,
        "User ID": userId,
        "IP Address": context.ip || "Unknown",
        "User Agent": req.headers.get("user-agent") || "Unknown",
        Country: context.geo?.country?.name || "Unknown",
        City: context.geo?.city || "Unknown",
      });

      return new Response(
        JSON.stringify({
          success: true,
          user: { id: userId, username, email },
          token,
        }),
        {
          status: 201,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`,
          },
        }
      );
    }

    if (action === "login") {
      const { email, password } = body;

      if (!email || !password) {
        return new Response(
          JSON.stringify({ error: "Email and password are required" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      // Look up user ID by email
      const userId = await emailIndexStore.get(email.toLowerCase());

      if (!userId) {
        // Increment rate limit counter for failed login
        const newCount = (rateLimitData?.count || 0) + 1;
        await rateLimitStore.setJSON(rateLimitKey, {
          count: newCount,
          resetAt: new Date(now + windowMs).toISOString(),
        });

        await logAccountActivity("failed_login", {
          Email: email,
          Reason: "User not found",
          "IP Address": clientIp,
          "User Agent": userAgent,
        });

        // Log to security webhook if multiple failures
        if (newCount >= 3) {
          await logSecurityEvent("Multiple Failed Login Attempts", newCount >= 5 ? "medium" : "low", {
            "IP Address": clientIp,
            "Email Attempted": email,
            "Failure Count": newCount,
            "User Agent": userAgent.slice(0, 200),
            Country: context.geo?.country?.name || "Unknown",
            City: context.geo?.city || "Unknown",
          });
        }

        return new Response(
          JSON.stringify({ error: "Invalid email or password" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      const user = await usersStore.get(`user:${userId}`, { type: "json" }) as User | null;

      if (!user) {
        return new Response(
          JSON.stringify({ error: "Invalid email or password" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      const validPassword = await bcrypt.compare(password, user.passwordHash);

      if (!validPassword) {
        // Increment rate limit counter for failed login
        const newCount = (rateLimitData?.count || 0) + 1;
        await rateLimitStore.setJSON(rateLimitKey, {
          count: newCount,
          resetAt: new Date(now + windowMs).toISOString(),
        });

        await logAccountActivity("failed_login", {
          Email: email,
          Username: user.username,
          Reason: "Invalid password",
          "IP Address": clientIp,
          "User Agent": userAgent,
        });

        // Log to security webhook if multiple failures
        if (newCount >= 3) {
          await logSecurityEvent("Multiple Failed Login Attempts", newCount >= 5 ? "medium" : "low", {
            "IP Address": clientIp,
            "Email Attempted": email,
            "Username": user.username,
            "Failure Count": newCount,
            "User Agent": userAgent.slice(0, 200),
            Country: context.geo?.country?.name || "Unknown",
            City: context.geo?.city || "Unknown",
          });
        }

        return new Response(
          JSON.stringify({ error: "Invalid email or password" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      // Update last login
      user.lastLogin = new Date().toISOString();
      await usersStore.setJSON(`user:${userId}`, user);

      const token = generateToken();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      const session: Session = {
        userId,
        token,
        expiresAt: expiresAt.toISOString(),
        createdAt: new Date().toISOString(),
      };

      await sessionsStore.setJSON(`session:${token}`, session);

      // Log to Discord
      await logAccountActivity("login", {
        Username: user.username,
        Email: user.email,
        "User ID": userId,
        "IP Address": context.ip || "Unknown",
        "User Agent": req.headers.get("user-agent") || "Unknown",
        Country: context.geo?.country?.name || "Unknown",
        City: context.geo?.city || "Unknown",
      });

      return new Response(
        JSON.stringify({
          success: true,
          user: { id: userId, username: user.username, email: user.email },
          token,
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`,
          },
        }
      );
    }

    if (action === "logout") {
      const cookies = req.headers.get("cookie") || "";
      const sessionMatch = cookies.match(/session=([^;]+)/);
      const token = sessionMatch?.[1];

      if (token) {
        await sessionsStore.delete(`session:${token}`);

        await logAccountActivity("logout", {
          Token: token.slice(0, 8) + "...",
          "IP Address": context.ip || "Unknown",
        });
      }

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
        },
      });
    }

    if (action === "verify") {
      const cookies = req.headers.get("cookie") || "";
      const sessionMatch = cookies.match(/session=([^;]+)/);
      const token = sessionMatch?.[1] || body.token;

      if (!token) {
        return new Response(
          JSON.stringify({ authenticated: false }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      const session = await sessionsStore.get(`session:${token}`, { type: "json" }) as Session | null;

      if (!session || new Date(session.expiresAt) < new Date()) {
        // Clean up expired session if it exists
        if (session) {
          await sessionsStore.delete(`session:${token}`);
        }
        return new Response(
          JSON.stringify({ authenticated: false }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      const user = await usersStore.get(`user:${session.userId}`, { type: "json" }) as User | null;

      if (!user) {
        return new Response(
          JSON.stringify({ authenticated: false }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({
          authenticated: true,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ error: "Invalid action" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Auth error:", error);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
};

export const config: Config = {
  path: "/api/auth",
};
