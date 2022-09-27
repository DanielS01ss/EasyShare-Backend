import bodyParser from 'body-parser';
import App from './app';
import Authentication from './controllers/Authentication';
import HomeController from './controllers/HomeController';
import UserController from './controllers/UserController';
import MongoConnection from './database/MongoConnection';

const app = new App({
  port: 5000,
  controllers: [new HomeController(), new Authentication(), new UserController()],
  middleWares: [bodyParser.json(), bodyParser.urlencoded({ extended: true })],
});

app.listen();
MongoConnection.getInstance().startConnection();
