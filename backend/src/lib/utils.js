import jwt from "jsonwebtoken";

export const generateToken = (user, res) => {
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
  res.cookie("token", token, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true, //cookie cannot be accessed by client side script and prevents XSS attacks cross site scripting attacks
    sameSite: "strict", //cookie is sent only to the same site as the request and not to any third party site and prevents CSRF attacks cross site request forgery attacks
    secure: process.env.NODE_ENV === "production" ? true : false, //cookie is sent only over HTTPS in production mode and it would determine if the cookie is sent over HTTPS or HTTP
  });

  return token;
};
