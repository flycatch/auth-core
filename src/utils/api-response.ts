export default (
  code: number,
  message: string,
  status: boolean,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data?: any[]
) => {
  return {
    timestamp: new Date().toISOString(),
    code,
    message,
    status,
    data,
  };
};
