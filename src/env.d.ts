export {}

declare global {
  namespace Cloudflare {
    interface Env {
      IMAGES: KVNamespace;
      WORKER_UPLOAD_SECRET: string;
    }
  }
}