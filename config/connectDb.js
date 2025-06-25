import mongoose from "mongoose";

const connectDB = async () => {
    await mongoose.connect(process.env.MONGODB_URI)
        .then(() => {
            console.log("MongoDB connected successfully");
        })
        .catch(err => {
            console.error("MongoDB connection failed:", err.message);
            process.exit(1);
        });
}

export default connectDB;