declare namespace Express {
  interface User {
    id: string;
    username: string;
    [key: string]: any;
  }
}