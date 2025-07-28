export default (
  code: number,
  message: string,
  status: boolean,
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
