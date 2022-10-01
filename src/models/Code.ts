import mongoose from 'mongoose';
import { CodeType } from '../types/CodeType';

const CodeSchema = new mongoose.Schema({
  code: String,
  userId: String,
});

const Code: mongoose.Model<CodeType> = mongoose.model<CodeType>('Code', CodeSchema);
export default Code;
