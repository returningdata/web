import type { Context, Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";

const SECURITY_WEBHOOK = "https://discord.com/api/webhooks/1461044306000216198/cJcaf0SzAZZUy-rv3t_zB-whs3glSLLCZs7SJmmASmiiPIPyVZLMKyYIwah_OGXf_cAp";

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

export default async (req: Request, context: Context) => {
  const clientIp = context.ip || "Unknown";
  const userAgent = req.headers.get("user-agent") || "Unknown";

  // Extract the image name from the URL path
  const url = new URL(req.url);
  const pathMatch = url.pathname.match(/^\/img\/(.+)$/);

  if (!pathMatch) {
    return new Response("Not found", { status: 404 });
  }

  const imageName = pathMatch[1];

  try {
    const imagesStore = getStore("images");
    const imageDataStore = getStore("image-data");
    const rateLimitStore = getStore("rate-limits");

    // Look up image metadata
    const image = await imagesStore.get(`image:${imageName}`, { type: "json" }) as ImageMetadata | null;

    if (!image) {
      // Track 404 hits per IP to detect enumeration/scanning attacks
      const notFoundKey = `404:${clientIp}`;
      const notFoundData = await rateLimitStore.get(notFoundKey, { type: "json" }) as { count: number; resetAt: string; } | null;
      const now = Date.now();
      const windowMs = 10 * 60 * 1000; // 10 minute window

      const currentCount = (notFoundData && new Date(notFoundData.resetAt).getTime() > now) ? notFoundData.count : 0;
      const newCount = currentCount + 1;

      await rateLimitStore.setJSON(notFoundKey, {
        count: newCount,
        resetAt: new Date(now + windowMs).toISOString(),
      });

      // Log security event if excessive 404s (potential scanning attack)
      if (newCount >= 20 && newCount % 10 === 0) {
        await logSecurityEvent("Possible Enumeration/Scanning Attack", newCount >= 50 ? "high" : "medium", {
          "IP Address": clientIp,
          "404 Count": newCount,
          "Last Requested": imageName.slice(0, 50),
          "User Agent": userAgent.slice(0, 200),
          Country: context.geo?.country?.name || "Unknown",
          City: context.geo?.city || "Unknown",
          "Window": "10 minutes",
        });
      }

      return new Response(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Image Not Found</title>
  <style>
    body { font-family: system-ui; background: #1a1a2e; color: white; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { text-align: center; }
    h1 { color: #f67280; }
  </style>
</head>
<body>
  <div class="container">
    <h1>404 - Image Not Found</h1>
    <p>The image "${imageName}" does not exist or has been deleted.</p>
    <a href="/" style="color: #f67280;">Go back home</a>
  </div>
</body>
</html>`,
        { status: 404, headers: { "Content-Type": "text/html" } }
      );
    }

    // Check if image has expired
    if (image.expiresAt && new Date(image.expiresAt) < new Date()) {
      // Delete expired image from blob storage and metadata
      await imageDataStore.delete(image.blobKey);
      await imagesStore.delete(`image:${imageName}`);

      // Also clean up expiration index
      const expirationStore = getStore("expiration-index");
      const expireTime = new Date(image.expiresAt).getTime();
      await expirationStore.delete(`expire:${expireTime}:${imageName}`);

      return new Response(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Image Expired</title>
  <style>
    body { font-family: system-ui; background: #1a1a2e; color: white; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { text-align: center; }
    h1 { color: #f67280; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Image Expired</h1>
    <p>This image was uploaded anonymously and has expired after 30 days.</p>
    <a href="/" style="color: #f67280;">Upload a new image</a>
  </div>
</body>
</html>`,
        { status: 410, headers: { "Content-Type": "text/html" } }
      );
    }

    // Fetch image from blob storage
    const imageData = await imageDataStore.get(image.blobKey, { type: "arrayBuffer" });

    if (!imageData) {
      return new Response("Image data not found", { status: 404 });
    }

    const imageUrl = `https://tazeliteplays.netlify.app/img/${imageName}`;

    // Check if request wants HTML page (browser viewing) or raw image
    const acceptHeader = req.headers.get("accept") || "";
    const wantsHtml = acceptHeader.includes("text/html") && !url.searchParams.has("raw");
    const isDiscordBot = (req.headers.get("user-agent") || "").toLowerCase().includes("discordbot");

    // For Discord embeds or when raw image is needed, return the image directly
    if (isDiscordBot || url.searchParams.has("raw") || !wantsHtml) {
      const imageBuffer = imageData instanceof ArrayBuffer ? imageData : new Uint8Array(imageData as ArrayBuffer);
      return new Response(imageBuffer, {
        status: 200,
        headers: {
          "Content-Type": image.contentType,
          "Content-Length": imageBuffer.byteLength.toString(),
          "Cache-Control": "public, max-age=31536000",
          "Content-Disposition": `inline; filename="${image.originalFilename}"`,
        },
      });
    }

    // Return HTML page with Discord embed meta tags for browsers
    return new Response(
      `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${imageName} - Image Host</title>

  <!-- Discord/Social Media Embed Tags -->
  <meta property="og:title" content="${imageName}">
  <meta property="og:type" content="website">
  <meta property="og:image" content="${imageUrl}?raw">
  <meta property="og:image:type" content="${image.contentType}">
  <meta property="og:url" content="${imageUrl}">
  <meta property="og:site_name" content="TazelitePlays Image Host">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:image" content="${imageUrl}?raw">
  <meta name="twitter:title" content="${imageName}">
  <meta name="theme-color" content="#f67280">

  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem;
      color: white;
    }
    .container {
      max-width: 1200px;
      width: 100%;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: bold;
      color: #f67280;
      text-decoration: none;
    }
    h1 {
      font-size: 1.5rem;
      margin-bottom: 1rem;
      word-break: break-all;
    }
    .image-container {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 1rem;
      margin-bottom: 1.5rem;
    }
    img {
      max-width: 100%;
      height: auto;
      border-radius: 8px;
      display: block;
      margin: 0 auto;
    }
    .actions {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1.5rem;
      background: #f67280;
      color: #1a1a2e;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      transition: background 0.2s;
    }
    .btn:hover {
      background: #f88c97;
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: white;
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.2);
    }
    .url-box {
      background: rgba(0, 0, 0, 0.3);
      border-radius: 8px;
      padding: 1rem;
      margin-top: 1.5rem;
    }
    .url-box label {
      display: block;
      margin-bottom: 0.5rem;
      font-size: 0.875rem;
      color: rgba(255, 255, 255, 0.7);
    }
    .url-box input {
      width: 100%;
      padding: 0.75rem;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 6px;
      color: white;
      font-family: monospace;
    }
    .copy-btn {
      margin-top: 0.5rem;
      padding: 0.5rem 1rem;
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <a href="/" class="logo">Image Host</a>
      <a href="/" class="btn btn-secondary">Upload New Image</a>
    </header>

    <h1>${imageName}</h1>

    <div class="image-container">
      <img src="${imageUrl}?raw" alt="${imageName}" loading="lazy">
    </div>

    <div class="actions">
      <a href="${imageUrl}?raw" class="btn" download="${image.originalFilename}">Download Image</a>
      <a href="${imageUrl}?raw" class="btn btn-secondary" target="_blank">Open Original</a>
    </div>

    <div class="url-box">
      <label>Direct Image URL (for Discord embeds, forums, etc.)</label>
      <input type="text" value="${imageUrl}" readonly id="urlInput">
      <button class="btn copy-btn" onclick="navigator.clipboard.writeText('${imageUrl}'); this.textContent='Copied!';">Copy URL</button>
    </div>
  </div>
</body>
</html>`,
      {
        status: 200,
        headers: {
          "Content-Type": "text/html",
          "Cache-Control": "public, max-age=3600",
        },
      }
    );
  } catch (error) {
    console.error("Image serve error:", error);
    return new Response("Internal server error", { status: 500 });
  }
};

export const config: Config = {
  path: "/img/*",
};
