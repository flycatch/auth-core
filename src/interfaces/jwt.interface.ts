import { JwtPayload } from "jsonwebtoken";

export interface JWTPayload extends JwtPayload {
  id: string;
  username: string;
  type: "refresh" | "access";
}
