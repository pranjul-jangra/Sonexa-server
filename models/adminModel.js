import mongoose from "mongoose";

const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, trim: true, unique: true },
    email: { type: String, required: true, unique: true, index: true, trim: true },
    password: { type: String, required: true, select: false },
    profileImage: { type: String, trim: true, default: '/user.png' },
    nickname: { type: String, trim: true },
    bio: { type: String },
    sessions: { type: [String], select: false },
    is_account_disabled: { type: Boolean, default: false, select: false },
},
    {
        timestamps: true
    }
);



// MongoDb TTL to delete the expired tokens
const emailUpdateSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 900 }
});

const forgotPasswordSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 900 }
})


// Models
const adminModel = mongoose.model('Admin', adminSchema);
const emailUpdateModel = mongoose.model('EmailUpdate', emailUpdateSchema);
const forgotPasswordModel = mongoose.model('ForgotPassword', forgotPasswordSchema);

export { adminModel, emailUpdateModel, forgotPasswordModel };
