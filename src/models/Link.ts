import mongoose from 'mongoose';
import { ILink } from '../interfaces/ILink';

const LinkSchema = new mongoose.Schema({
  linkId: String,
  documentId: String,
  userInfo: String,
  createdAt: { type: Date, expires: '24h', default: Date.now },
});

const User: mongoose.Model<ILink> = mongoose.model<ILink>('Link', LinkSchema);
export default User;
