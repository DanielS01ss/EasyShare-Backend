/* eslint-disable import/prefer-default-export */
import dotenv from 'dotenv';

dotenv.config();
export const MONGO_DB_CONNECTION_STRING: string = process.env.MONGO_DB_CONNECTION_STRING || '';
export const ACCESS_TOKEN_SECRET: string = process.env.ACCESS_TOKEN_SECRET || '';
export const REFRESH_TOKEN_SECRET: string = process.env.REFRESH_TOKEN_SECRET || '';
export const GOOGLE_ACC_PASS: string = process.env.GOOGLE_APP_PASSWORD || '';
