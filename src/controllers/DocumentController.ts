import express, { Response } from 'express';
import Joi from 'joi';
import Document from '../models/Documents';
import authMidd from '../middlewares/AuthMiddleware';
import { RequestFuncType } from '../types/RequestFuncReturnType';

class DocumentController {
  public path = '/document';

  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  public initRoutes(): void {
    this.router.post('/add', authMidd.authenticationTokenCheck, this.addDocument);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async addDocument(req: any, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      type: Joi.string().required().min(1),
      size: Joi.number().required(),
      name: Joi.string().required().min(1),
      file: Joi.string().required(),
    });

    try {
      await validationSchema.validateAsync(req.body.data);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(400);
    }

    try {
      const doc = new Document({ ...req.body.data });
      await doc.save();
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }
    return resp.sendStatus(200);
  }
}

export default DocumentController;
