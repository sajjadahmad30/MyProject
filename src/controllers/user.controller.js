import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";


const generateAccessAndRefereshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave: false})
        return {accessToken, refreshToken};        
    } catch (error) {
        throw new ApiError(500, "Something went wrong, while generating access and referesh token.")
    }
}


const registerUser = asyncHandler( async(req, res)=>{
   //get user details from the frontend 
   // validation - not empty
   // check if user is already registered: username , email
   // check for images and check for avatar
   // upload them into cloudinary
   // create user object - create entry in db
   // reomve password and refresh token field from response-*
   // check for user creation
   // return response


    const {fullName , email, username, password} =  req.body;
    // console.log("email " , email);
    
    if(
        [fullName, email, username, password].some((field)=> field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are required")
    }

    const existUser = await User.findOne({
        $or: [{username}, {email}]
    })

    if(existUser){
        throw new ApiError(409, "User with email or username already exists.")
    }

    // console.log(req.files)

    const avatarLocalPath =  req.files?.avatar[0]?.path; 
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
       coverImageLocalPath = req.files.coverImage[0].path; 
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar is required")
    }


   const avatar = await uploadOnCloudinary(avatarLocalPath)
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)

   if(!avatar){
    throw new ApiError(400, "Avatar file is required")
   }

   const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
   })
//    console.log(user)
   const createdUser = await User.findById(user._id).select(
   "-password -refreshToken"
   )

   if(!createdUser){
    throw new ApiError(500, "something went wrong while registering the user")
   }

   return res.status(201).json(
    new ApiResponse(200, createdUser, "User registered Successfully")
   )

})


const loginUser = asyncHandler(async(req, res)=>{
    //req body - data
    // username or email 
    // find user
    // password check
    // access and refresh token 
    // send cookie

    const {username, password, email} = req.body;

        if(!username && !email){
            throw new ApiError(400, "Username or email is required")
        }

    // if(!username || !email){
    //     throw new ApiError(400, "Username or email is required")
    // }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if(!user){
        throw new ApiError(404, "User Does not exist.")
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid User Credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)
    
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly : true,
        secure: true
    }

    return res.status(200).cookie("accessToken", accessToken,options).cookie("refreshToken", refreshToken, options).json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,accessToken, refreshToken
            },
            "User logged in successfully"
        )
    )
})


const logoutUser = asyncHandler(async(req,res)=>{
     await User.findByIdAndUpdate(
        req.user._id,   
        {
         $set: {
            refreshToken: undefined
            }   
        },
        {
            new : true,
        }
    )
    
    const options ={
        httpOnly: true,
        secure: true,
    }

    return res.status(200).clearCookie("accessToken", options).clearCookie("refreshToken", options).json(new ApiResponse(200, {}, "User Logged Out"))
})

const refreshAccessToken = asyncHandler(async(req,res)=>{
   const incommingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

   if(!incommingRefreshToken){
    throw new ApiError(401, "UnAuthorized Request")
   }

   try {
    const decodedToken = jwt.verify(
     incommingRefreshToken,
     process.env.REFRESH_TOKEN_EXPIRY,
    )
 
    const user = await User.findById(decodedToken._id);
 
    if(!user){
     throw new ApiError(401, "invalid refresh token")
    }
 
    if(incommingRefreshToken !== user?.refreshToken){
     throw new ApiError(401, "Refresh token is expired or used")
    }
 
    const options = {
     httpOnly: true,
     secure: true,   
    }
 
    const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
 
    return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
     new ApiResponse(200, {accessToken, refreshToken: newRefreshToken},
     "Access token refreshed successfully"
     )
    )
 
   } catch (error) {
    throw new ApiError(401, error?.message || "invalid refresh token")
   }
}) 


const changeCurrentPassword = asyncHandler(async(req, res)=>{
    const {oldPassword, newPassword} = req.body;

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false})

    return res.status(200).json(new ApiResponse(200, {}, "Password Changed Successfully"))

})


const getCurrentUser = asyncHandler(async(req, res)=>{
    return res.status(200).json(200, req.user, "User fetched successfully")
})


const updateAccountDetails = asyncHandler(async(req, res)=>{
    const {fullName, email} = req.body;

    if(!fullName || !email){
        throw new ApiError(400, "All fields are required")
    }

   const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            fullName,
            email:email
        },
        {new : true}
    ).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "Account Detials updated successfully"))
})

const updateUserAvatar = asyncHandler(async(req, res)=>{
    const avatarLocalPath = req.file?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on avatar");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "avatar image updated successfully"))
})


const updateUserCoverImage= asyncHandler(async(req, res)=>{
    const coverImageLocalPath = req.file?.path;

    if(!coverImageLocalPath){
        throw new ApiError(400, "cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading on coverImage");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "Cover image updated successfully"))

})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
    
};