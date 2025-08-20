export interface SessionPayload {
  id: string | number;
  username: string;
  type: "access";
  grands?: (string | number)[];
}
