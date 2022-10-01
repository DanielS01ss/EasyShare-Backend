import mongoose from 'mongoose';
import { IResetLink } from '../interfaces/IResetLink';

const ResetLinkSchema = new mongoose.Schema({
  resetLink: String,
  userEmail: String,
});

const ResetLink: mongoose.Model<IResetLink> = mongoose.model<IResetLink>('ResetLink', ResetLinkSchema);
export default ResetLink;
