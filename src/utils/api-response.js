module.exports = (code, message, status, data = []) => {
    return {
      timestamp: new Date().toISOString(),
      code,
      message,
      status,
      data,
    };
  };
  