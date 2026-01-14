import type { Context, Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";

const ACCOUNT_WEBHOOK = "https://discord.com/api/webhooks/1461043266169471007/03wQqBoR6Bm0GQEhOQDnYjlNHrYKwvAt7X3JaSd-rP-5K7sHz1vM-2bEgr0kaq-lQQww";

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

export default async (req: Request, context: Context) => {
  console.log("Running cleanup job...");

  try {
    const imagesStore = getStore("images");
    const imageDataStore = getStore("image-data");
    const expirationStore = getStore("expiration-index");

    const now = Date.now();
    let deletedCount = 0;
    const deletedNames: string[] = [];

    // List all items in the expiration index
    const { blobs } = await expirationStore.list({ prefix: "expire:" });

    for (const blob of blobs) {
      // Key format: expire:{timestamp}:{imageName}
      const parts = blob.key.split(":");
      if (parts.length < 3) continue;

      const expireTimestamp = parseInt(parts[1], 10);
      const imageName = parts.slice(2).join(":"); // Handle image names that might contain colons

      // Check if expired
      if (expireTimestamp > now) continue;

      try {
        // Get image metadata to find blob key
        const image = await imagesStore.get(`image:${imageName}`, { type: "json" }) as ImageMetadata | null;

        if (image) {
          // Delete from blob storage
          await imageDataStore.delete(image.blobKey);
          // Delete metadata
          await imagesStore.delete(`image:${imageName}`);
          deletedNames.push(imageName);
          console.log(`Deleted expired image: ${imageName}`);
        }

        // Delete from expiration index
        await expirationStore.delete(blob.key);
        deletedCount++;
      } catch (e) {
        console.error(`Failed to delete image ${imageName}:`, e);
      }
    }

    // Log cleanup activity to Discord
    if (deletedCount > 0 || blobs.length > 0) {
      await logToDiscord(ACCOUNT_WEBHOOK, {
        embeds: [
          {
            title: "Scheduled Cleanup Completed",
            color: 0x3498db,
            fields: [
              { name: "Expired Items Found", value: blobs.length.toString(), inline: true },
              { name: "Items Deleted", value: deletedCount.toString(), inline: true },
              { name: "Deleted Images", value: deletedNames.length > 0 ? deletedNames.join(", ") : "None", inline: false },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
    }

    console.log(`Cleanup complete: ${deletedCount} items processed`);

    return new Response(
      JSON.stringify({
        success: true,
        found: blobs.length,
        deleted: deletedCount,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Cleanup error:", error);
    return new Response(
      JSON.stringify({ error: "Cleanup failed" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
};

export const config: Config = {
  // Run daily at midnight UTC
  schedule: "0 0 * * *",
};
