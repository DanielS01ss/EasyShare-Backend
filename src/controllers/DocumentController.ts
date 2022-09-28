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
    this.router.delete('/delete', authMidd.authenticationTokenCheck, this.deleteDocument);
    this.router.get('/:id', authMidd.authenticationTokenCheck, this.getDocument);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async deleteDocument(req: any, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      documentId: Joi.string().required().min(1),
    });

    try {
      await validationSchema.validateAsync(req.body);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(400);
    }
    const token: string = req.headers.authorization.split(' ')[1];
    const decodedToken: DecodedJWT = jwt.decode(token) as DecodedJWT;
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
      // eslint-disable-next-line max-len
      await User.findOneAndUpdate({ id: userId }, { $pull: { documents: { _id: req.body.documentId } } });
      await Document.deleteOne({ _id: req.body.documentId });
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }
    return resp.sendStatus(200);
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
      // eslint-disable-next-line no-underscore-dangle
      const docId: string = savedDoc._id.toString();
      const docToSave = {
        // eslint-disable-next-line no-underscore-dangle
        documentId: docId,
        name: savedDoc.name,
        size: savedDoc.size,
        docType: savedDoc.type,
      };
      if (foundUser) {
        try {
          // eslint-disable-next-line no-underscore-dangle, max-len
          await User.updateOne({ id: userId }, { $push: { documents: docToSave } });
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

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getDocument(req: any, resp: Response): RequestFuncType {
    if (!req.params.id) return resp.sendStatus(400);
    const idParam: string = req.params.id;
    if (idParam.length !== 24) return resp.sendStatus(400);

    try {
      const doc = await Document.findById(req.params.id);
      if (!doc) return resp.sendStatus(404);
      return resp.status(200).json(doc);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }
  }
}

export default DocumentController;
