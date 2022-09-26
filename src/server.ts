import bodyParser from 'body-parser';
import App from './app';
import Authentication from './controllers/Authentication';
import HomeController from './controllers/HomeController';

const app = new App({
  port: 5000,
  controllers: [new HomeController(), new Authentication()],
  middleWares: [bodyParser.json(), bodyParser.urlencoded({ extended: true })],
});

app.listen();
