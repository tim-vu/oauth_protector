export function createUrl(urlString: string, base?: string): URL {
  const url = new URL(urlString, base);
  const query = new Map(Array.from(url.searchParams.entries()));

  return {
    protocol: url.protocol,
    hostname: url.hostname,
    path: url.pathname,
    port: url.port,
    query: query,
    fragment: url.hash.substring(1),
    href: url.href,
    origin: url.origin,
  };
}

export default interface URL {
  protocol: string;
  hostname: string;
  path: string;
  port: string;
  query: ReadonlyMap<string, string>;
  fragment: string;
  href: string;
  origin: string;
}
