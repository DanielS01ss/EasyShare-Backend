import { User } from './User';

export type DecodedJWT = {
  user: User;
  iat: number;
  exp: number;
};
