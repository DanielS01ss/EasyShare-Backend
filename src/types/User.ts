import { ObjectId } from 'mongoose';

export type User = {
  _id: ObjectId;
  id: string;
  username: string;
  email: string;
  password: string;
  documents: Array<string>;
  isUserConfirmed: boolean;
};
