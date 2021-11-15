import URL from "./url";

export interface UploadData {
  bytes?: ArrayBuffer;
  file?: string;
}

export interface RequestBody {
  error?: string;
  formData?: ReadonlyMap<string, string>;
  raw?: UploadData[];
}

export default interface Request {
  method: string;
  url: URL;
  headers: ReadonlyMap<string, string>;
  body?: RequestBody;
}
