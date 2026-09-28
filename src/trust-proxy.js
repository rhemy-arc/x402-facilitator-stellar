/**
 * Client IP resolution behind reverse proxies and CDNs.
 *
 * When the facilitator runs behind a reverse proxy (Cloudflare, AWS ALB, etc.),
 * the socket address is the proxy's address, not the client's. The
 * X-Forwarded-For header carries the original client IP, but it can be forged
 * by the client. The trust proxy configuration determines how many hops from
 * the right (the proxy side) we can trust.
 *
 * Security: never trust the leftmost XFF entry — it is entirely client-controlled.
 * Always walk from the right (the socket address, which is set by the TCP layer)
 * and skip the configured number of trusted proxy hops.
 */

/**
 * Parses the X-Forwarded-For header into an array of IPs.
 * The leftmost entry is the original client (claimed), the rightmost is the
 * closest proxy to the server.
 *
 * @param {string|undefined} raw - raw XFF header value
 * @returns {string[]} array of IPs, leftmost first
 */
function parseForwarded(raw) {
  if (!raw) return [];
  return String(raw)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

/**
 * Parses an IPv4 address into its numeric components.
 *
 * @param {string} ip - IP address
 * @returns {number[]|null} array of 4 octets, or null if invalid
 */
function parseIpv4(ip) {
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;
  const parts = match.slice(1).map(Number);
  if (parts.every(p => p >= 0 && p <= 255)) {
    return parts;
  }
  return null;
}

/**
 * Checks if an IP address matches a CIDR block (IPv4 only).
 * If the entry is not valid CIDR notation, falls back to exact string match.
 *
 * @param {string} ip - IP address to check
 * @param {string} cidr - CIDR block (e.g., "10.0.0.0/8") or exact IP
 * @returns {boolean}
 */
function ipCidrMatch(ip, cidr) {
  const parts = cidr.split('/');
  if (parts.length !== 2) return ip === cidr;

  const [network, bitsStr] = parts;
  const bits = parseInt(bitsStr, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return ip === cidr;

  const ipParts = parseIpv4(ip);
  const networkParts = parseIpv4(network);
  if (!ipParts || !networkParts) return ip === cidr;

  const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const networkNum =
    (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;

  return (ipNum & mask) === (networkNum & mask);
}

/**
 * Checks if an IP address matches any of the trusted proxy entries.
 * Supports exact IP matches and CIDR notation.
 *
 * @param {string} ip - IP address to check
 * @param {string[]} trustedList - list of trusted proxy IPs/CIDRs
 * @returns {boolean}
 */
function isTrustedProxy(ip, trustedList) {
  if (!ip) return false;
  for (const entry of trustedList) {
    if (ipCidrMatch(ip, entry)) return true;
  }
  return false;
}

/**
 * Resolves the client IP from a request, honoring the trust proxy configuration.
 *
 * @param {object} req - Fastify request (needs req.headers and req.socket.remoteAddress)
 * @param {number|string[]|undefined} trustProxy - trust proxy config:
 *   - undefined: no proxy trusted, return socket address
 *   - number: trust this many hops from the right
 *   - string[]: list of trusted proxy IPs/CIDRs
 * @returns {string} resolved client IP
 */
export function resolveClientIp(req, trustProxy) {
  const socketAddress = req.socket?.remoteAddress;

  if (trustProxy === undefined || trustProxy === null) {
    return socketAddress;
  }

  if (typeof trustProxy === 'number') {
    const hops = Math.max(0, Math.floor(trustProxy));
    const forwarded = parseForwarded(req.headers['x-forwarded-for']);
    const chain = [...forwarded, socketAddress];
    const index = Math.max(0, chain.length - 1 - hops);
    return chain[index] ?? socketAddress;
  }

  if (Array.isArray(trustProxy)) {
    const forwarded = parseForwarded(req.headers['x-forwarded-for']);
    const chain = [...forwarded, socketAddress];
    for (let i = chain.length - 1; i >= 0; i--) {
      if (!isTrustedProxy(chain[i], trustProxy)) {
        return chain[i];
      }
    }
    return socketAddress;
  }

  return socketAddress;
}

/**
 * Creates a Fastify onRequest hook that resolves the client IP.
 *
 * @param {number|string[]|undefined} trustProxy - trust proxy config
 * @returns {Function} Fastify onRequest hook
 */
export function createTrustProxyHook(trustProxy) {
  return async req => {
    const ip = resolveClientIp(req, trustProxy);
    if (ip !== undefined) {
      Object.defineProperty(req, 'ip', { value: ip, configurable: true });
    }
  };
}
