export default interface JWTPayload {
    id: string;
    username: string;
    type: "refresh" | "access";
}
