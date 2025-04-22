const bcrypt = require("bcryptjs");
const User = require("../models/User");
const OTP = require("../models/OTP");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const mailSender = require("../utils/mailSender");
const { passwordUpdated } = require("../mail/templates/passwordUpdate");
const Profile = require("../models/Profile");
require("dotenv").config();

// Constants
const OTP_EXPIRY_MINUTES = 10;
const TOKEN_EXPIRY = "24h";
const COOKIE_EXPIRY_DAYS = 3;

// Helper function for error responses
const errorResponse = (res, status, message, error = null) => {
  const response = { success: false, message };
  if (error && process.env.NODE_ENV === "development") {
    response.error = error.message;
    response.stack = error.stack;
  }
  return res.status(status).json(response);
};

// Signup Controller
exports.signup = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body;

    // Validate required fields
    const requiredFields = { firstName, lastName, email, password, confirmPassword, otp };
    const missingFields = Object.entries(requiredFields)
      .filter(([_, value]) => !value)
      .map(([key]) => key);

    if (missingFields.length > 0) {
      return errorResponse(res, 403, `Missing required fields: ${missingFields.join(", ")}`);
    }

    if (password !== confirmPassword) {
      return errorResponse(res, 400, "Password and Confirm Password do not match");
    }

    // Check for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return errorResponse(res, 400, "User already exists");
    }

    // Verify OTP
    const recentOTP = await OTP.findOne({ email }).sort({ createdAt: -1 });
    
    if (!recentOTP) {
      return errorResponse(res, 400, "OTP not found");
    }

    // Check OTP expiry
    const otpExpiryTime = new Date(recentOTP.createdAt).getTime() + (OTP_EXPIRY_MINUTES * 60 * 1000);
    if (Date.now() > otpExpiryTime) {
      return errorResponse(res, 400, "OTP expired");
    }

    if (otp !== recentOTP.otp) {
      return errorResponse(res, 400, "Invalid OTP");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user profile
    let profileDetails;
    try {
      profileDetails = await Profile.create({
        gender: null,
        dateOfBirth: null,
        about: null,
        contactNumber: contactNumber || null,
      });
    } catch (error) {
      console.error("Profile creation error:", error);
      return errorResponse(res, 500, "Profile creation failed", error);
    }

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber: contactNumber || "",
      password: hashedPassword,
      accountType,
      approved: accountType === "Instructor" ? false : true,
      additionalDetails: profileDetails._id,
      image: "",
    });

    // Clean sensitive data before response
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.token;

    return res.status(200).json({
      success: true,
      user: userResponse,
      message: "User registered successfully",
    });

  } catch (error) {
    console.error("Signup error:", error);
    return errorResponse(res, 500, "User registration failed", error);
  }
};

// Login Controller
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return errorResponse(res, 400, "Please provide both email and password");
    }

    const user = await User.findOne({ email }).populate("additionalDetails");
    if (!user) {
      return errorResponse(res, 401, "User not registered");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return errorResponse(res, 401, "Incorrect password");
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        email: user.email, 
        id: user._id, 
        role: user.role,
        accountType: user.accountType
      },
      process.env.JWT_SECRET,
      { expiresIn: TOKEN_EXPIRY }
    );

    // Update user with token
    user.token = token;
    await user.save();

    // Set HTTP-only cookie
    const cookieOptions = {
      expires: new Date(Date.now() + COOKIE_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    };

    // Prepare response data
    const responseData = {
      success: true,
      token,
      user: {
        _id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        accountType: user.accountType,
        approved: user.approved,
        additionalDetails: user.additionalDetails,
      },
      message: "Login successful",
    };

    return res.cookie("token", token, cookieOptions).status(200).json(responseData);

  } catch (error) {
    console.error("Login error:", error);
    return errorResponse(res, 500, "Login failed", error);
  }
};

// OTP Controller
exports.sendotp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return errorResponse(res, 400, "Email is required");
    }

    // Check for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return errorResponse(res, 400, "User already registered");
    }

    // Generate and verify unique OTP
    let otp;
    let isUnique = false;
    let attempts = 0;
    const maxAttempts = 5;

    while (!isUnique && attempts < maxAttempts) {
      otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });

      const existingOTP = await OTP.findOne({ otp });
      if (!existingOTP) {
        isUnique = true;
      }
      attempts++;
    }

    if (!isUnique) {
      return errorResponse(res, 500, "Failed to generate unique OTP");
    }

    // Create OTP record
    await OTP.create({ email, otp });

    // Send email
    const emailSubject = "StudyNotion - OTP Verification";
    const emailBody = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">StudyNotion OTP Verification</h2>
        <p>Your OTP for account verification is:</p>
        <div style="background: #f3f4f6; padding: 16px; text-align: center; margin: 16px 0;">
          <h1 style="margin: 0; font-size: 32px; letter-spacing: 8px;">${otp}</h1>
        </div>
        <p>This OTP is valid for ${OTP_EXPIRY_MINUTES} minutes.</p>
      </div>
    `;

    await mailSender(email, emailSubject, emailBody);

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      otp: process.env.NODE_ENV === "development" ? otp : undefined,
    });

  } catch (error) {
    console.error("OTP sending error:", error);
    return errorResponse(res, 500, "Failed to send OTP", error);
  }
};

// Password Change Controller
exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return errorResponse(res, 400, "Both old and new passwords are required");
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return errorResponse(res, 404, "User not found");
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return errorResponse(res, 401, "Current password is incorrect");
    }

    // Update password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Send notification email
    try {
      await mailSender(
        user.email,
        "Password Updated",
        passwordUpdated(
          user.email,
          `Password updated successfully for ${user.firstName} ${user.lastName}`
        )
      );
    } catch (emailError) {
      console.error("Password change email failed:", emailError);
    }

    return res.status(200).json({
      success: true,
      message: "Password updated successfully",
    });

  } catch (error) {
    console.error("Password change error:", error);
    return errorResponse(res, 500, "Password update failed", error);
  }
};