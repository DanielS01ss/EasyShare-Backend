import express from 'express';
import cors from 'cors';
import App from './app';
import Authentication from './controllers/Authentication';
import HomeController from './controllers/HomeController';
import UserController from './controllers/UserController';
import MongoConnection from './database/MongoConnection';
import DocumentController from './controllers/DocumentController';
import LinkController from './controllers/LinkController';

const app = new App({
  port: 5000,
  controllers: [
    new HomeController(),
    new Authentication(),
    new UserController(),
    new DocumentController(),
    new LinkController(),
  ],
  middleWares: [
    express.json({ limit: '10mb' }),
    express.urlencoded({ limit: '10mb', extended: true, parameterLimit: 50000 }),
    cors(),
  ],
});

app.listen();
MongoConnection.getInstance().startConnection();
