import tls from 'node:tls';

/**
 * Inspects SSL/TLS certificate directly via TLS handshake.
 */
export async function checkSslCertificate(hostname, port = 443) {
  return new Promise((resolve) => {
    const timeout = 5000;
    let isResolved = false;

    const timer = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        resolve(fallbackSsl(hostname, 'Connection timed out during TLS handshake'));
      }
    }, timeout);

    try {
      const socket = tls.connect(
        {
          host: hostname,
          port: port,
          servername: hostname,
          rejectUnauthorized: false, // We inspect even invalid/self-signed certs to report them!
        },
        () => {
          if (isResolved) return;
          isResolved = true;
          clearTimeout(timer);

          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError;

          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            return resolve({
              available: true,
              valid: false,
              issuer: 'None',
              subject: hostname,
              validFrom: null,
              validTo: null,
              daysRemaining: 0,
              isSelfSigned: false,
              isExpired: true,
              protocol: socket.getProtocol(),
              error: 'No SSL certificate served',
              source: 'Direct TLS Handshake Inspection',
            });
          }

          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();

          const daysRemaining = Math.max(0, Math.floor((validTo - now) / (1000 * 60 * 60 * 24)));
          const isExpired = now > validTo;
          const isSelfSigned = cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN;

          const issuerOrg = cert.issuer?.O || cert.issuer?.CN || 'Unknown CA';

          resolve({
            available: true,
            valid: authorized && !isExpired && !isSelfSigned,
            issuer: issuerOrg,
            subject: cert.subject?.CN || hostname,
            validFrom: validFrom.toISOString().split('T')[0],
            validTo: validTo.toISOString().split('T')[0],
            daysRemaining,
            isSelfSigned,
            isExpired,
            protocol: socket.getProtocol(),
            cipher: socket.getCipher()?.name,
            authorizationError: authorizationError || null,
            source: 'Direct TLS Handshake Inspection',
          });
        }
      );

      socket.on('error', (err) => {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timer);
          resolve(fallbackSsl(hostname, err.message));
        }
      });
    } catch (err) {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timer);
        resolve(fallbackSsl(hostname, err.message));
      }
    }
  });
}

function fallbackSsl(hostname, reason) {
  return {
    available: true,
    isFallback: true,
    valid: false,
    issuer: 'N/A',
    subject: hostname,
    validFrom: null,
    validTo: null,
    daysRemaining: 0,
    isSelfSigned: false,
    isExpired: false,
    protocol: 'None',
    error: reason || 'TLS connection unavailable',
    source: 'Direct TLS Handshake Inspection (Failed Handshake)',
  };
}
