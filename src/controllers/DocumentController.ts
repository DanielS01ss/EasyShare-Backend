import jwt from 'jsonwebtoken';
import express, { Response } from 'express';
import Joi from 'joi';
import Document from '../models/Documents';
import authMidd from '../middlewares/AuthMiddleware';
import { RequestFuncType } from '../types/RequestFuncReturnType';
import { DecodedJWT } from '../types/DecodedJWT';
import User from '../models/User';

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

    const token: string = req.headers.authorization.split(' ')[1];
    const decodedToken: DecodedJWT = jwt.decode(token) as DecodedJWT;
    console.log(decodedToken);
    const userId = decodedToken.user.id;
    let foundUser;
    try {
      foundUser = await User.findOne({ id: userId });
      if (!foundUser) return resp.sendStatus(404);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }

    try {
      const doc = new Document({ ...req.body.data });
      const savedDoc = await doc.save();
      if (foundUser) {
        try {
          // eslint-disable-next-line no-underscore-dangle
          await User.updateOne({ id: foundUser.id }, { $push: { documents: savedDoc._id } });
        } catch (err) {
          console.log(err);
          return resp.sendStatus(500);
        }
      }
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }
    return resp.sendStatus(200);
  }
}

export default DocumentController;
