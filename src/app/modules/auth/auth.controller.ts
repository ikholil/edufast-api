import { Request, Response } from 'express';
import httpStatus from 'http-status';
import config from '../../../config';
import ApiError from '../../../errors/ApiError';
import { authService, UserType } from './auth.service';

const signUp = async (req: Request, res: Response) => {
  try {
    const result: UserType | null = await authService.signUp(req.body);
    if (result?.email) {
      res.json({
        success: true,
        statusCode: httpStatus.ok,
        message: 'User Created Successfully',
        data: result,
      });
    } else {
      throw new ApiError(httpStatus.NOT_FOUND, 'Something Went Wrong');
    }
  } catch (err) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Something Went Wrong');
  }
};
const signIn = async (req: Request, res: Response) => {
  try {
    const result = await authService.signIn(req.body);
    if (result?.accessToken) {
      const cookieOptions = {
        secure: config.env === 'production',
        httpOnly: true,
      };

      res.cookie('refreshToken', result?.refreshToken, cookieOptions);

      res.json({
        success: true,
        statusCode: httpStatus.ok,
        message: 'User Logged in Successfully',
        token: result?.accessToken,
      });
    } else {
      res.json({
        success: false,
        statusCode: httpStatus.NOT_FOUND,
        message: 'Username or password incorrect',
      });
    }
  } catch (error) {
    console.log(error);
  }
};
export const authController = {
  signUp,
  signIn,
};
