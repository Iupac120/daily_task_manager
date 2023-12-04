import { CustomError } from "./customError.js";
export const errorHandler = ((err, req, res, next) => {
    if (err instanceof CustomError) {
      res.status(err.statusCode).json({ error: err.message });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  