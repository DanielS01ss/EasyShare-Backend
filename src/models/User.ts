import mongoose from 'mongoose';
import { IUser } from '../interfaces/IUser';

const UserSchema = new mongoose.Schema<IUser>({
  id: String,
  username: String,
  email: String,
  password: {
    type: String,
    required: false,
    max: 50,
    min: 5,
  },
  documents: [
    {
      documentId: String,
      name: String,
      size: String,
      docType: String,
    },
  ],
});

const User: mongoose.Model<IUser> = mongoose.model<IUser>('User', UserSchema);
export default User;
