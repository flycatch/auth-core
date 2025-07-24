import { JwtPayload } from "jsonwebtoken";

export default interface JWTPayload extends JwtPayload {
  id: string;
  username: string;
  type: "refresh" | "access";
}
