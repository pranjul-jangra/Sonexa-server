import mongoose from "mongoose";


const musicSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    artist: { type: String, default: "Unknown", trim: true },
    filePath: { type: String, required: true },
    imagePath: { type: String, default: "/template.png" },
    category: { type: String },
    duration: { type: Number, default: 0 },
    playCount: { type: Number, default: 0 },
    
    musicId: { type: String, required: true, unique: true },
    adminId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: true,
        select: false
    },
    // music should not be feched if the user account is disabled
    stop_fechable: { type: Boolean, default: false, select: false },
},
    {
        timestamps: true
    }
);


const musicModal = mongoose.model('music', musicSchema);
export default musicModal;