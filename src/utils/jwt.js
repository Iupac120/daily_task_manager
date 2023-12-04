import jwt from "jsonwebtoken";
import dotenv from "dotenv"
dotenv.config()

function jwtToken (userJwt){
    const user = {name:userJwt.user_name,id:userJwt.user_id,email:userJwt.user_email,admin:userJwt.is_admin}
    const accessToken = jwt.sign(user,process.env.ACCESS_TOKEN,{expiresIn:"2d"});
    const refreshToken = jwt.sign(user,process.env.REFRESH_TOKEN,{expiresIn:"1y"})
    return {accessToken,refreshToken}
}
 export {jwtToken}