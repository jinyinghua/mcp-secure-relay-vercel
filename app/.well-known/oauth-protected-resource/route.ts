import { metadataCorsOptionsRequestHandler, protectedResourceHandler } from 'mcp-handler';

const handler = protectedResourceHandler({
  authServerUrls: [process.env.NEXT_PUBLIC_APP_URL || 'https://your-project.vercel.app']
});
const corsHandler = metadataCorsOptionsRequestHandler();

export { handler as GET, corsHandler as OPTIONS };
