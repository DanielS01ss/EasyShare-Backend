import express, { Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import Joi from 'joi-plus';
import { RequestFuncType } from '../types/RequestFuncReturnType';
import extractJwt from '../utils/extractJWT';
import { UserDecodedJWT } from '../types/UserDecodedJWT';
import User from '../models/User';
import { IUser } from '../interfaces/IUser';

class UserController {
  public path = '/user';

  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  private initRoutes(): void {
    this.router.patch('/', this.modifyUser);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any
  async modifyUser(req: any, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      username: Joi.string().min(3).escape(),
      password: Joi.string().min(3),
      email: Joi.string().email().min(3).escape(),
    });

    try {
      await validationSchema.validateAsync(req.body);
    } catch (err) {
      console.log(err);
      resp.sendStatus(400);
    }

    const retrievedJWT: string | undefined = extractJwt(req.headers.authorization);
    let decodedJWT: string | JwtPayload | null;
    let userData: UserDecodedJWT;
    try {
      if (retrievedJWT) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        decodedJWT = jwt.decode(retrievedJWT);
        userData = decodedJWT as UserDecodedJWT;
        // eslint-disable-next-line no-underscore-dangle
        // eslint-disable-next-line max-len, no-underscore-dangle
        const foundUser: IUser | undefined = (await User.find({ id: userData.user.id })) as IUser;
        if (foundUser) {
          if (req.body.username) {
            try {
              // eslint-disable-next-line max-len, no-underscore-dangle
              await User.updateOne({ id: userData.user.id }, { $set: { username: req.body.username } });
            } catch (err) {
              console.log('Something went wrong while updating the user');
              return resp.sendStatus(500);
            }
          }
        }
        if (req.body.email) {
          try {
            // eslint-disable-next-line max-len, no-underscore-dangle
            await User.updateOne({ id: userData.user.id }, { $set: { email: req.body.email } });
          } catch (err) {
            console.log('Something went wrong while updating the user');
            return resp.sendStatus(500);
          }
        }
        if (req.body.password) {
          try {
            // eslint-disable-next-line max-len, no-underscore-dangle
            await User.updateOne({ id: userData.user.id }, { $set: { password: req.body.password } });
          } catch (err) {
            console.log('Something went wrong while updating the user');
            return resp.sendStatus(500);
          }
        }
      }
    } catch (err) {
      console.log(err);
      return resp.sendStatus(400);
    }

    if (!req.body.email && !req.body.username && !req.body.password) {
      return resp.sendStatus(400);
    }
    return resp.sendStatus(200);
  }
}

export default UserController;
