import { randomInt } from 'node:crypto';

export async function listenLoopback(server) {
  // Some OS ephemeral ranges include ports rejected by Fetch. Use the private range.
  for (let attempt = 0; attempt < 32; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const failed = (error) => {
          server.off('listening', ready);
          reject(error);
        };
        const ready = () => {
          server.off('error', failed);
          resolve();
        };
        server.once('error', failed);
        server.once('listening', ready);
        server.listen(randomInt(49152, 65536), '127.0.0.1');
      });
      return;
    } catch (error) {
      // Windows may reserve individual ports in this range for another service.
      if (!['EADDRINUSE', 'EACCES'].includes(error.code) || attempt === 31) throw error;
    }
  }
}
