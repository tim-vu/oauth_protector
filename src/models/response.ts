export default interface Response {
  statusCode: number;
  statusLine: string;
  headers: ReadonlyMap<string, string>;
}
