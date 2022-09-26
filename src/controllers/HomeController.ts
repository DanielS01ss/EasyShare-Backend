import express, { Request, Response } from 'express';

class HomeController {
  public path = '/';

  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  private initRoutes(): void {
    this.router.get('/', this.home);
  }

  home(req: Request, resp: Response): void {
    resp.send('success');
  }
}

export default HomeController;
