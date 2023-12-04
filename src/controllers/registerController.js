import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pool from "../database/db.js";
import { jwtToken } from "../utils/jwt.js";
import passport from "passport";
import { sendMail } from "../utils/email.js";
import {otp} from "../utils/otp.js"
import { BadRequestError, NotFoundError,UnAuthorizedError } from "../errors/customError.js";


const createUser = async (req,res) => {
        const {userName,email,password} = req.body
        const isEmail = await pool.query("SELECT user_email FROM users WHERE user_email = $1",[email])
        if(isEmail.rows.length) return res.status(401).json("Emails exist please sign in")
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)
        const otpCode = otp().toString()
        const otpTime = new Date(Date.now() + 1800000)
        console.log("otpTime",otpTime)
        const hashedOtpCode = await bcrypt.hash(otpCode,10)
        const newUser = await pool.query("INSERT INTO users (user_name,user_email,user_password,otp,otp_time) VALUES ($1,$2,$3,$4,$5) RETURNING *",[userName,email,hashedPassword,hashedOtpCode,otpTime])
        const message  =`<p>Please enter ${otpCode} to verify email and complete sign up.</p>
        <p>This code <b>expires in 30 minutes.</b></p> 
         <p>Press <a href="${process.env.CLIENT_URL}">here</a> to proceed.</p>                                                               
         `;
        const subject = "OTP VERIFICATION"
        await sendMail(email,subject,message)
        res.status(201).json({user:newUser.rows[0]})
}

const verifyOtp = async (req,res,next) => {
    const {otpCode,email} = req.body
    const user = await pool.query("SELECT otp,is_verified,user_email,otp_time FROM users WHERE user_email = $1",[email])
    if(!user.rows.length) return next(new NotFoundError("Server error"))
    console.log(user.rows[0])
    const {otp,otp_time,is_verified} = user.rows[0]
    console.log("verify",is_verified)
    if(is_verified) return next(new UnAuthorizedError("Your account has been verified, please login"))
    if(Date.now() > otp_time) return next(new UnAuthorizedError("Otp has expired"))
    const isMatch =  await bcrypt.compare(otpCode,otp)
    if(!isMatch) return next(new UnAuthorizedError("OTP does not match or expired"))
    console.log("here")
    const updateUser = await pool.query("UPDATE users SET is_verified = TRUE WHERE user_email = $1",[email])
    if(!updateUser.rows.length) return next(new NotFoundError("otp verification failed"))
    res.status(201).json({data:updateUser})
}

const resetOtpVerify = async (req,res,next) => {
    const {email} = req.body
    const user = await pool.query("SELECT user_email FROM users WHERE user_email = $1 AND is_verified = FALSE",[email])
    if(!user.rows.length) return next(new NotFoundError("Your account has been verified, please log in"))
    const otpCode = otp().toString()
    const otpTime = new Date(Date.now() + 1800000)
    console.log("otpTime",otpTime)
    const hashedOtpCode = await bcrypt.hash(otpCode,10)
    const newUser = await pool.query("UPDATE users SET otp = $1,otp_time = $2 WHERE user_email = $3",[hashedOtpCode,otpTime,email])
    const message  =`<p>Please enter ${otpCode} to verify email and complete sign up.</p>
    <p>This code <b>expires in 30 minutes.</b></p> 
     <p>Press <a href="${process.env.CLIENT_URL}">here</a> to proceed.</p>                                                               
     `;
    const subject = "RESET OTP VERIFICATION"
    await sendMail(email,subject,message)
    res.status(201).json({user:newUser.rows[0]})
}

const userLogin = async(req,res) => {
        const {email,password} = req.body
        const user = await pool.query("SELECT user_id,user_name,user_email,user_password,is_verified,is_admin FROM users WHERE user_email = $1",[email])
        if(user.rows.length === 0) return res.status(401).json({error:"email not found, please sign up"})
        const {user_password,is_verified} = user.rows[0]
        if(!is_verified) return next(new UnAuthorizedError("Your account has not been verified"))
        const isMatch =  await bcrypt.compare(password, user_password)
        if(!isMatch) return res.status(401).json({error:"Incorrect password"})
        let token = jwtToken(user.rows[0]);
    console.log("user",user.rows[0])
        req.session.user = user
        console.log("session",req.session.user.rows[0])
    //httpOnly: true, sameSite:"none", secure: true
        res.cookie("refresh_token",token.refreshToken,{httpOnly: true})
        res.status(201).json({"accessToken":token.accessToken,"refreshToken":token.refreshToken})

}
//reset password link
const resetPasswordLink = async (req,res,next) => {
    const {email} = req.body;
    const user = await pool.query("SELECT user_email FROM users WHERE user_email = $1",[email])
    if(!user.rows.length) throw new NotFoundError("Your email does not exist")
    const {user_email} = user.rows[0]
    const message  =`<p>Please use this link to reset your password and complete log in.</p>
    <p>This link <b>expires in 30 minutes.</b></p> 
     <p>Press <a href="${process.env.CLIENT_URL}">here</a> to proceed.</p>                                                               
     `;
    const subject = "RESET PASSWORD LINK"
    await sendMail(user_email,subject,message)
    res.status(201).json(`Reset your password with link send to your email ${user_email}`)
}
//reset password
const resetPassword =  async (req,res,next) => {
    const {email,newPassword} = req.body
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(newPassword,salt)
    const user = await pool.query("UPDATE users SET user_password = $1 WHERE user_email = $2 RETURNING *",[hashedPassword,email])
    if(!user.rows.length) return next(new BadRequestError("Failed to update"))
    const {user_password,...others} = user.rows[0]
    res.status(200).json({sucess:"Your password has been updated",data:others})
}
const refreshLogin = async (req,res) => {
    try {
        console.log("here")
        const refreshToken = req.cookies.refresh_token
        if(refreshToken === null) return res.status(401).json({error:"refresh is null"})
        console.log("here")
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN,(err,user) => {
        if(err) return res.status(403).json({error:err.message})
        let token = jwtToken(user)
        console.log("here")
        res.cookie("refresh_token",token.refreshToken,{httpOnly: true});
        res.status(201).json({"accessToken":token.accessToken,"refreshToken":token.refreshToken})
        })
    } catch (error) {
        res.status(500).json(error.message)
    }
}

const logout = async (req,res) => {
    try {
        res.clearCookie("refresh_token")
        res.status(200).json({message:"user log out"})
    } catch (error) {
        res.status(500).json(err.message)
    }
}

const googleAuth = passport.authenticate('google',{
    scope:['email profile']
})

const isLoggedIn = (req,res,next) => {
    req.user?next ():res.sendStatus(401)
}
const googleLogin = passport.authenticate('google',{
        successRedirect:"/profile",//process.env.CLIENT_URL,
        failureRedirect:"/login/failed"
    })

const userProfile = (req,res) => {
    console.log(req.user)
    res.status(200).json("This is user profile")
}

const facebookLogin =  passport.authenticate("facebook",{
        successRedirect:process.env.CLIENT_URL,
        failureRedirect:"/login/failed"
    })


const loginFailure = (req,res) => {
    res.status(401).json({
        error:true,
        message:"login failure"
    })
}

export default {
    createUser,
    verifyOtp,
    resetOtpVerify,
    resetPasswordLink,
    resetPassword,
    userLogin,
    refreshLogin,
    logout,
    googleAuth,
    googleLogin,
    facebookLogin,
    loginFailure,
    isLoggedIn,
    userProfile
}