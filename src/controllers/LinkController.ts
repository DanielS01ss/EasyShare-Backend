import express, { Response } from 'express';
import jwt from 'jsonwebtoken';
import Joi from 'joi';
import { v4 as uuidv4 } from 'uuid';
import { RequestFuncType } from '../types/RequestFuncReturnType';
import authMidd from '../middlewares/AuthMiddleware';
import Document from '../models/Documents';
import { DecodedJWT } from '../types/DecodedJWT';
import User from '../models/User';
import Link from '../models/Link';

class LinkController {
  public path = '/link';

  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  private initRoutes(): void {
    this.router.post('/create', authMidd.authenticationTokenCheck, this.createLink);
    this.router.get('/:id', this.accessLink);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async createLink(req: any, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      documentId: Joi.string().required(),
    });

    try {
      await validationSchema.validateAsync(req.body);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(400);
    }

    try {
      const foundDoc = await Document.findOne({ _id: req.body.documentId });
      if (!foundDoc) return resp.sendStatus(404);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }

    const token: string = req.headers.authorization.split(' ')[1];
    const decodedToken: DecodedJWT = jwt.decode(token) as DecodedJWT;
    const userId = decodedToken.user.id;
    let foundUser;
    try {
      foundUser = await User.findOne({ id: userId });
      if (!foundUser) return resp.sendStatus(404);
      // eslint-disable-next-line max-len
      const findDocumentInUserList = foundUser.documents?.find((doc) => doc.documentId === req.body.documentId);
      if (!findDocumentInUserList) return resp.sendStatus(404);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }

    const userDocSharedInfo = {
      email: decodedToken.user.email,
    };

    const newLinkId = uuidv4();

    try {
      // eslint-disable-next-line max-len
      const newLinkItem = new Link({
        linkId: newLinkId,
        documentId: req.body.documentId,
        userInfo: JSON.stringify(userDocSharedInfo),
      });
      await newLinkItem.save();
      // eslint-disable-next-line no-underscore-dangle
    } catch (err) {
      console.log(err);
      return resp.sendStatus(400);
    }

    return resp.sendStatus(200);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async accessLink(req: any, resp: Response): RequestFuncType {
    if (!req.params.id || !(req.params.id.length > 0)) return resp.sendStatus(400);

    let foundLink;
    let foundDocument;

    try {
      foundLink = await Link.findById(req.params.id);
      foundDocument = await Document.findById(foundLink?.documentId);
      return resp.status(200).json(foundDocument);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }
  }
}

export default LinkController;
