/* eslint-disable import/prefer-default-export */
import dotenv from 'dotenv';

dotenv.config();
export const MONGO_DB_CONNECTION_STRING: string = process.env.MONGO_DB_CONNECTION_STRING || '';
