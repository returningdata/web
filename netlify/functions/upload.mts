import type { Context, Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";

const IMAGE_WEBHOOK = "https://discord.com/api/webhooks/1461043123592495125/701xiG4LCc__uwhT3Dw7E_7v2EAizzqKyWoCeA0vxF69uw_mM2vCk73-uWZpwjalKnL9";
const ACCOUNT_WEBHOOK = "https://discord.com/api/webhooks/1461043266169471007/03wQqBoR6Bm0GQEhOQDnYjlNHrYKwvAt7X3JaSd-rP-5K7sHz1vM-2bEgr0kaq-lQQww";
const SECURITY_WEBHOOK = "https://discord.com/api/webhooks/1461044306000216198/cJcaf0SzAZZUy-rv3t_zB-whs3glSLLCZs7SJmmASmiiPIPyVZLMKyYIwah_OGXf_cAp";

interface User {
  id: string;
  username: string;
  email: string;
}

interface Session {
  userId: string;
  token: string;
  expiresAt: string;
}

interface ImageMetadata {
  id: string;
  name: string;
  originalFilename: string;
  contentType: string;
  fileSize: number;
  userId: string | null;
  isAnonymous: boolean;
  expiresAt: string | null;
  createdAt: string;
  blobKey: string;
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

async function getUserFromSession(req: Request): Promise<User | null> {
  const cookies = req.headers.get("cookie") || "";
  const sessionMatch = cookies.match(/session=([^;]+)/);
  const token = sessionMatch?.[1];

  if (!token) return null;

  const sessionsStore = getStore("sessions");
  const usersStore = getStore("users");

  const session = await sessionsStore.get(`session:${token}`, { type: "json" }) as Session | null;

  if (!session || new Date(session.expiresAt) < new Date()) {
    return null;
  }

  const user = await usersStore.get(`user:${session.userId}`, { type: "json" }) as (User & { passwordHash: string }) | null;

  if (!user) return null;

  return {
    id: user.id,
    username: user.username,
    email: user.email,
  };
}

function sanitizeName(name: string): string {
  // Only allow alphanumeric, hyphens, and underscores
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-_]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 100);
}

function generateId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async (req: Request, context: Context) => {
  const clientIp = context.ip || "Unknown";
  const userAgent = req.headers.get("user-agent") || "Unknown";

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Rate limiting for uploads
  const rateLimitStore = getStore("rate-limits");
  const uploadRateLimitKey = `upload:${clientIp}`;
  const rateLimitData = await rateLimitStore.get(uploadRateLimitKey, { type: "json" }) as { count: number; resetAt: string; } | null;

  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour window
  const maxUploads = 50; // Max uploads per hour per IP

  // Check if rate limit exceeded
  if (rateLimitData && new Date(rateLimitData.resetAt).getTime() > now && rateLimitData.count >= maxUploads) {
    await logSecurityEvent("Upload Rate Limit Exceeded", "high", {
      "IP Address": clientIp,
      "Upload Count": rateLimitData.count,
      "User Agent": userAgent.slice(0, 200),
      Country: context.geo?.country?.name || "Unknown",
      City: context.geo?.city || "Unknown",
      "Potential DDoS/Abuse": "Yes",
    });

    return new Response(
      JSON.stringify({ error: "Too many uploads. Please try again later." }),
      { status: 429, headers: { "Content-Type": "application/json", "Retry-After": "3600" } }
    );
  }

  try {
    const formData = await req.formData();
    const file = formData.get("image") as File | null;
    const imageName = formData.get("name") as string | null;
    const anonymous = formData.get("anonymous") === "true";

    if (!file) {
      return new Response(
        JSON.stringify({ error: "No image file provided" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    if (!imageName || imageName.trim().length === 0) {
      return new Response(
        JSON.stringify({ error: "Image name is required" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Validate file type
    const validTypes = ["image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"];
    if (!validTypes.includes(file.type)) {
      return new Response(
        JSON.stringify({ error: "Invalid file type. Supported: JPEG, PNG, GIF, WebP, SVG" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Validate file size (max 10MB)
    const maxSize = 10 * 1024 * 1024;
    if (file.size > maxSize) {
      return new Response(
        JSON.stringify({ error: "File too large. Maximum size is 10MB" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    const sanitizedName = sanitizeName(imageName);
    if (sanitizedName.length < 1) {
      return new Response(
        JSON.stringify({ error: "Invalid image name" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    const imagesStore = getStore("images");
    const imageDataStore = getStore("image-data");

    // Check if name already exists
    const existing = await imagesStore.get(`image:${sanitizedName}`, { type: "json" });

    if (existing) {
      return new Response(
        JSON.stringify({ error: "An image with this name already exists. Please choose a different name." }),
        { status: 409, headers: { "Content-Type": "application/json" } }
      );
    }

    // Get user info (if logged in)
    const user = await getUserFromSession(req);
    const isAnonymous = anonymous || !user;

    // Anonymous uploads expire in 30 days
    const expiresAt = isAnonymous
      ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      : null;

    // Store image data in blob storage
    const imageId = generateId();
    const blobKey = `img-${Date.now()}-${sanitizedName}`;
    const arrayBuffer = await file.arrayBuffer();

    await imageDataStore.set(blobKey, new Uint8Array(arrayBuffer));

    // Save image metadata
    const imageMetadata: ImageMetadata = {
      id: imageId,
      name: sanitizedName,
      originalFilename: file.name,
      contentType: file.type,
      fileSize: file.size,
      userId: user?.id || null,
      isAnonymous,
      expiresAt: expiresAt?.toISOString() || null,
      createdAt: new Date().toISOString(),
      blobKey,
    };

    await imagesStore.setJSON(`image:${sanitizedName}`, imageMetadata);

    // Update upload rate limit counter
    const currentCount = (rateLimitData && new Date(rateLimitData.resetAt).getTime() > now) ? rateLimitData.count : 0;
    await rateLimitStore.setJSON(uploadRateLimitKey, {
      count: currentCount + 1,
      resetAt: new Date(now + windowMs).toISOString(),
    });

    // Store in expiration index for cleanup (if anonymous)
    if (isAnonymous && expiresAt) {
      const expirationStore = getStore("expiration-index");
      await expirationStore.set(`expire:${expiresAt.getTime()}:${sanitizedName}`, sanitizedName);
    }

    const imageUrl = `https://tazeliteplays.netlify.app/img/${sanitizedName}`;
    const rawImageUrl = `${imageUrl}?raw`;

    // Log to Discord image webhook
    const discordEmbed = {
      embeds: [
        {
          title: "New Image Uploaded",
          color: isAnonymous ? 0xff9900 : 0x00ff00,
          fields: [
            { name: "Image Name", value: sanitizedName, inline: true },
            { name: "Original Filename", value: file.name, inline: true },
            { name: "File Size", value: `${(file.size / 1024).toFixed(2)} KB`, inline: true },
            { name: "Content Type", value: file.type, inline: true },
            { name: "Uploaded By", value: user?.username || "Anonymous", inline: true },
            { name: "Anonymous", value: isAnonymous ? "Yes (expires in 30 days)" : "No (permanent)", inline: true },
            { name: "URL", value: imageUrl, inline: false },
          ],
          image: { url: rawImageUrl },
          timestamp: new Date().toISOString(),
          footer: {
            text: `${context.geo?.country?.name || "Unknown"}`,
          },
        },
      ],
    };

    await logToDiscord(IMAGE_WEBHOOK, discordEmbed);

    // Also log to account webhook for detailed tracking
    await logToDiscord(ACCOUNT_WEBHOOK, {
      embeds: [
        {
          title: "Image Upload Activity",
          color: 0x9b59b6,
          fields: [
            { name: "Image Name", value: sanitizedName, inline: true },
            { name: "User", value: user?.username || "Anonymous", inline: true },
            { name: "User ID", value: user?.id?.toString() || "N/A", inline: true },
            { name: "File Size", value: `${(file.size / 1024).toFixed(2)} KB`, inline: true },
            { name: "Content Type", value: file.type, inline: true },
            { name: "IP Address", value: context.ip || "Unknown", inline: true },
            { name: "Country", value: context.geo?.country?.name || "Unknown", inline: true },
            { name: "City", value: context.geo?.city || "Unknown", inline: true },
            { name: "User Agent", value: (req.headers.get("user-agent") || "Unknown").slice(0, 100), inline: false },
            { name: "Expires", value: expiresAt ? expiresAt.toISOString() : "Never (permanent)", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    return new Response(
      JSON.stringify({
        success: true,
        image: {
          id: imageId,
          name: sanitizedName,
          url: imageUrl,
          createdAt: imageMetadata.createdAt,
          expiresAt: expiresAt?.toISOString() || null,
        },
      }),
      { status: 201, headers: { "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Upload error:", error);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
};

export const config: Config = {
  path: "/api/upload",
};
