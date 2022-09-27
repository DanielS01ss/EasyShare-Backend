/* eslint-disable max-len */
import express, { Request, Response } from 'express';
import JoiPassCheck from 'joi-password-complexity';
import Joi from 'joi';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { RequestFuncType } from '../types/RequestFuncReturnType';
import User from '../models/User';
import { User as UserType } from '../types/User';
import { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } from '../utils/envConstants';
import { UserTypeResponse } from '../types/UserTypeResponse';

class Authentication {
  public path = '/auth';

  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  private initRoutes(): void {
    this.router.post('/signup', this.signUp);
    this.router.post('/login', this.login);
  }

  async googleAuth(req: Request, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      username: Joi.string().min(2).required(),
      email: Joi.string().min(3).email(),
      password: Joi.string().min(8),
    });

    try {
      await validationSchema.validateAsync(req.body);
    } catch (err) {
      return resp.sendStatus(400);
    }
    try {
      const countId = await User.countDocuments({ id: req.body.id });
      if (countId) {
        const user: UserType | null = await User.findOne({ email: req.body.email });
        if (user && user.id === req.body.id) {
          const { password, ...filteredUser } = user;
          const loggedUser = {
            loggedUsr: filteredUser,
          };
          const signed = jwt.sign(loggedUser, ACCESS_TOKEN_SECRET, { expiresIn: '2h' });
          const refreshTk = jwt.sign(loggedUser, REFRESH_TOKEN_SECRET);

          return resp.status(200).json({
            token: signed,
            refreshToken: refreshTk,
          });
        }
        return resp.status(401);
      }
      const newUser = new User({
        id: req.body.id,
        username: req.body.username,
        email: req.body.email,
        password: '',
        documents: [],
      });

      await newUser.save();
      return resp.status(200).json('User was succesfully created!!!');
    } catch (err) {
      console.log(err);
      return resp.status(500);
    }
  }

  async signUp(req: Request, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      username: Joi.string().min(1).required(),
      email: Joi.string().min(3).email(),
      password: Joi.string().min(8),
    });

    try {
      await validationSchema.validateAsync(req.body);
    } catch (err) {
      console.log(err);
      return resp.sendStatus(400);
    }

    const passwordStrengthParameters = {
      min: 8,
      max: 30,
      lowerCase: 1,
      upperCase: 1,
      numeric: 1,
      symbol: 1,
      requirementCount: 2,
    };

    const passValidationRes = JoiPassCheck(passwordStrengthParameters).validate(req.body.password);
    if (passValidationRes.error) {
      return resp.sendStatus(400);
    }
    try {
      const countUsername = await User.countDocuments({ username: req.body.username });
      const countEmail = await User.countDocuments({ username: req.body.email });

      if (countEmail && countUsername) {
        return resp.status(422).send('Username and email already exists!');
      }
      if (countEmail) {
        return resp.status(422).send('Email already exists!');
      }
      if (countUsername) {
        return resp.status(422).send('Username already exists!');
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);

      const newUser = new User({
        id: uuidv4(),
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
        documents: [],
      });

      await newUser.save();
      return resp.status(200).json('User was succesfully created!!!');
    } catch (err) {
      console.log(err);
    }

    return resp.sendStatus(200);
  }

  async login(req: Request, resp: Response): RequestFuncType {
    const validationSchema = Joi.object({
      email: Joi.string().min(3).email(),
      password: Joi.string().min(8),
    });

    try {
      await validationSchema.validateAsync(req.body);
    } catch (err) {
      resp.status(400);
    }

    try {
      // eslint-disable-next-line no-underscore-dangle
      const user: UserType | null = ((await User.findOne({ email: req.body.email })) as UserTypeResponse)._doc;
      if (user && user.password) {
        const validPassword = await bcrypt.compare(req.body.password, user.password);

        if (!validPassword) {
          return resp.status(400).json({ message: 'Incorrect password' });
        }
        const { password, ...filteredUser } = user;
        const loggedUser = {
          user: filteredUser,
        };
        const signed = jwt.sign(loggedUser, ACCESS_TOKEN_SECRET, { expiresIn: '2h' });
        const refreshTk = jwt.sign(loggedUser, REFRESH_TOKEN_SECRET);

        return resp.status(200).json({
          token: signed,
          refreshToken: refreshTk,
        });
      }
      return resp.status(404).json('User was not found!');
    } catch (err) {
      console.log(err);
      return resp.sendStatus(500);
    }
  }
}

export default Authentication;
