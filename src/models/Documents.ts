import mongoose from 'mongoose';
import { Document as DocumentType } from '../types/Document';

const DocumentSchema = new mongoose.Schema({
  name: String,
  size: Number,
  type: String,
  file: String,
});

const Document: mongoose.Model<DocumentType> = mongoose.model<DocumentType>('Document', DocumentSchema);
export default Document;
