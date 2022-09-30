import mongoose from 'mongoose';
import { IRefreshTokens } from '../interfaces/IRefreshTokens';

const RefreshTokensSchema = new mongoose.Schema({
  token: String,
  createdAt: { type: Date, expires: '7d', default: Date.now },
});

const RefreshTokens: mongoose.Model<IRefreshTokens> = mongoose.model<IRefreshTokens>(
  'RefreshTokens',
  RefreshTokensSchema,
);

export default RefreshTokens;
