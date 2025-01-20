import bcryptjs from "bcryptjs";
import User from "../models/user.model.js";
import { generateToken } from "../lib/utils.js";
import cloudinary from "../lib/cloudinary.js";

export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "Please fill in all fields" });
    }
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password should be atleast 6 characters" });
    }
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: "User Email already exists" });
    }
    //hash the password
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(password, salt);
    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
    });
    if (newUser) {
      //generate JWT token
      generateToken(newUser, res);
      await newUser.save();
      return res.status(201).json({ message: "User Created Successfully" });
    } else {
      return res.status(500).json({ message: "Failed to create user" });
    }
  } catch (error) {
    console.log("Error in signUp Controller", error.message);
    return res.status(500).json({ message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password, otp } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Please fill in all fields ooo" });
    }
    const user = await User.findOne({ email, otp });
    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }
    const isMatch = await bcryptjs.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }
    //generate JWT token
    generateToken(user, res);
    res.status(200).json({ message: "Login Successful" });
  } catch (error) {
    console.log("Error in login Controller", error.message);
    return res.status(500).json({ message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token");
    return res.status(200).json({ message: "Logged out Successfully" });
  } catch (error) {
    console.log("Error in logout Controller", error.message);
    return res.status(500).json({ message: error.message });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { profile_pic } = req.body;
    const userId = req.user._id;
    if (!profile_pic) {
      return res.status(400).json({ message: "Please fill in all fields" });
    }
    const uploadResponse = await cloudinary.uploader.upload(profile_pic);
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profile_pic: uploadResponse.secure_url },
      { new: true }
    );
    if (updatedUser) {
      return res.status(200).json({ user:updatedUser , message: "Profile updated successfully" });
    }
    return res.status(500).json({ message: "Failed to update profile" });
  } catch (error) {
    console.log("Error in updateProfile Controller", error.message);
    return res.status(500).json({ message: error.message });
  }
};

export const checkAuth = (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in checkAuth controller", error.message);
    res.status(500).json({ message: "Internal Server Error.." });
  }
};
