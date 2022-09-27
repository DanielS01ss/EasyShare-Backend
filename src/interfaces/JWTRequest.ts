import { Request } from 'express';

interface JWTRequest extends Request {
  authorization: string;
}

export default JWTRequest;
