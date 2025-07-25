import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"


const userSchema = new Schema(
    {
        username :{
            type : String,
            required : true,
            unique : true,
            lowwercase : true,
            trim : true,
            index : true
        },
        email :{
            type : String,
            required : true,
            unique : true,
            lowwercase : true,
            trim : true,
        },
        fullName :{
            type: String,
            required : true,
            trim : true,
            index : true
        },
        avatar:{
            type : String, // couldinary url
            required : true,
        },
        coverImage:{
            type : String  // couldinary url
        },
        watchHistory:[
            {
            type : Schema.Types.ObjectId,
            ref : "Video"
            }
        ],
        password :{
            type : String,
            required : [true, " Password is required"]
        },
        refreshToken: {
            type: String
        }
    },
    {
        timestamps: true
    }
)

// userSchema.pre("save", async function(next){
//     if(!this.ismodified("password")) return next();

//     this.password = await bcrypt.hash(this.password, 10)
//     next();
// } )

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
  
    // Hash password logic here
    this.password = await bcrypt.hash(this.password, 10);
    next();
  });
  

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
   return jwt.sign(
        {
            _id : this._id,
            email : this.email,
            username : this.username,
            fullName : this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: "7d",
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id : this._id
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: "4d",
        }
    )
}

export const User = mongoose.model("User", userSchema);