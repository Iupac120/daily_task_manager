import express from "express";
import passport from "passport"
const router = express.Router()
import authController from "../controllers/registerController.js"
import { trycatchHandler } from "../utils/trycatchHandler.js";

router.post("/", trycatchHandler(authController.createUser))
router.post("/verify-otp", trycatchHandler(authController.verifyOtp))
router.post("/reset-verify-otp", trycatchHandler(authController.resetOtpVerify))
router.post("/login", trycatchHandler(authController.userLogin))
router.post("/reset-password-link", trycatchHandler(authController.resetPasswordLink))
router.post("/reset-password", trycatchHandler(authController.resetPassword))
router.get("/refresh", authController.refreshLogin)
router.get("/logout", authController.logout)
//router.get("/social/google/callback", passport.authenticate("google",{scope:['profile email']}))
router.get("/auth/google", passport.authenticate('google',{
    scope:['profile','email']
})
)
router.get("/auth/google/callback", passport.authenticate('google',{
    successRedirect:"/api/register/profile",//process.env.CLIENT_URL,
    failureRedirect:"/api/register/login/failed"
})
)

router.get("/auth/facebook", passport.authenticate('facebook'))
router.get("/auth/facebook/callback", passport.authenticate('facebook',{
    successRedirect:"/api/register/profile",//process.env.CLIENT_URL,
    failureRedirect:"/api/register/login/failed"
})
)
//router.get("/auth/facebook/callback", authController.facebookLogin)
router.get("/profile",authController.isLoggedIn,authController.userProfile)
router.get("/login/failed", authController.loginFailure)

export  {router}