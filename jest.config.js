/** @type {import("jest").Config} **/
// eslint-disable-next-line no-undef
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/tests/**/*.test.ts"],
  coverageThreshold: { global: { lines: 85 } },
  forceExit: true,
};
