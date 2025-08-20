export interface User {
  id: string | number;
  email: string;
  username: string;
  grants?: (string | number)[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}
