import { MinimalDocInfo } from '../types/MinimalDocInfo';

export interface IUser {
  id?: string;
  username?: string;
  email?: string;
  password?: string;
  documents?: Array<MinimalDocInfo>;
}
