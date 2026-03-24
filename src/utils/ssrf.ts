/**
 * Checks if a hostname or IP is potentially internal.
 * Returns true if the hostname is safe (not a local/private IP), false otherwise.
 */
export function isSafeUrl(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    // Reject localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      return false;
    }

    // Reject other private IPv4 ranges (simplified for this exercise)
    if (/^10\./.test(hostname)) return false;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)) return false;
    if (/^192\.168\./.test(hostname)) return false;
    
    // Reject internal tlds
    if (hostname.endsWith('.internal') || hostname.endsWith('.local')) {
      return false;
    }

    return true;
  } catch (e) {
    return false; // Invalid URL
  }
}
