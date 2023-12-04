import Joi from "joi";

export const createUserValidator = Joi.object({
    username: Joi.string().required(),
    email: Joi.string().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
    .required()
    .messages({
      'string.pattern.base': 'Email is not a valid email format/address',
    }),
    password: Joi.string().required()
    .messages({
      'string.pattern.base': 'You need one number, one alphanumeric character and one in caps, password be more than 7 characters long',
    }),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({'string.pattern.base':'You need to confirm your password'}),
    firstName: Joi.string().optional(),
    lastName: Joi.string().optional(),
  }).strict()

  export const loginUserValidator = Joi.object({
    email: Joi.string().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
    .required()
    .messages({
      'string.pattern.base': 'Email is not a valid email format/address',
    }),
    password: Joi.string().regex(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/)
    .required()
    .messages({
      'string.pattern.base': 'You need one number, one alphanumeric character and one in caps, password be more than 7 characters long',
    })
    
  }).strict()
  
  export const emailValidator = Joi.object({
    email: Joi.string().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
    .required()
    .messages({
      'string.pattern.base': 'Email is not a valid email format/address',
    })
  }).strict()
  
  export const verifyOTPValidator = Joi.object({
    otp: Joi.string().required().messages({
      'string.pattern.base': 'Otp is not valid format/address',
    }),
    email: Joi.string().regex(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
    .required()
    .messages({
      'string.pattern.base': 'Email is not a valid email format/address',
    })
  }).strict()
  export const resetPasswordValidator = Joi.object({
    newPassword: Joi.string().regex(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/)
    .required()
    .messages({
      'string.pattern.base': 'You need one number, one alphanumeric character and one in caps, password be more than 7 characters long',
    }),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required().messages({'string.pattern.base':'You need to confirm your password'}),
    
  }).strict()