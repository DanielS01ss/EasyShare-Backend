import express, {Request, Response} from 'express';

import Joi from 'joi';
import JoiPassCheck from 'joi-password-complexity';
import { validationResult } from 'express-validator';

class Authentication {
    public path='/auth'
    public router = express.Router();

    constructor()
    {
        this.initRoutes();
    }

    private initRoutes()
    {
        this.router.post('/signup',this.signUp);
    }

    async signUp(req:Request, resp:Response)
    {
        const validationSchema = Joi.object({
            username:Joi.string().min(1).required(),
            email:Joi.string().min(3).email(),
            password:Joi.string().min(8)
        })
        
      try{
        await validationSchema.validateAsync(req.body);
      } catch(err)
      {
        console.log(err);
       return resp.sendStatus(400);
      } 

      const passwordStrengthParameters = {
        min:8,
        max:30,
        lowerCase:1,
        upperCase:1,
        numeric:1,
        symbol:1,
        requirementCount:2
      }

      const passValidationRes = JoiPassCheck(passwordStrengthParameters).validate(req.body.password);
      if(passValidationRes.error)
      {
        return resp.sendStatus(400);
      }
      resp.sendStatus(200);
    }
 }

 export default Authentication;