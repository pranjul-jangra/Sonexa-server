import { adminModel, emailUpdateModel, forgotPasswordModel } from "../models/adminModel.js";
import musicModal from "../models/musicModal.js";
import songPlaysModal from "../models/songPlays.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v2 as cloudinary } from "cloudinary";
import mongoose from "mongoose";
import { generateAlphanumericId, generateTokens, verifyAccessToken, verifyRefreshToken } from "../utils/adminUtils.js";
import { sendMail } from "../utils/sendMail.js";

// Finding cloudinary public id
const extractPublicId = (url) => {
    try {
        if (!url || !url.includes('cloudinary')) return null;

        // Remove Cloudinary base URL and get the path
        const urlParts = url.split('/');
        const uploadIndex = urlParts.findIndex(part => part === 'upload');
        if (uploadIndex === -1) return null;

        // Get everything after 'upload' and version (if present)
        let pathParts = urlParts.slice(uploadIndex + 1);

        // Remove version if present (starts with 'v' followed by numbers)
        if (pathParts[0] && pathParts[0].match(/^v\d+$/)) {
            pathParts = pathParts.slice(1);
        }

        // Join the remaining parts and remove file extension
        const fullPath = pathParts.join('/');
        const withoutExtension = fullPath.replace(/\.[^/.]+$/, '');

        return withoutExtension;

    } catch (error) {
        return null;
    }
};

// New register
export const register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: "All fields are required" });

        // Check for existing user
        const existingEmail = await adminModel.findOne({ email });
        if (existingEmail) return res.status(409).json({ error: "Email is already in use" });

        const existingUsername = await adminModel.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
        if (existingUsername) return res.status(409).json({ error: "Username is already taken" });

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens({ username, email });

        // Hash refresh token and password
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        const hashedPassword = await bcrypt.hash(password, 10);

        // New user
        const newUser = new adminModel({ username, email, password: hashedPassword, sessions: [hashedRefreshToken], is_account_disabled: false });
        await newUser.save();

        res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: "Lax", maxAge: 14 * 24 * 60 * 60 * 1000 });
        res.status(201).json({ message: "User registered successfully", user: newUser, accessToken });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error' })
    }
}

// Login
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || email.trim() === '') { return res.status(401).json({ error: "Username is required" }) }
        if (!password) { return res.status(401).json({ error: "Password is required" }) }

        const user = await adminModel.findOne({ email }).select("+password +sessions");
        if (!user) { return res.status(404).json({ error: "There's no user with this email." }) }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) { return res.status(401).json({ error: "Invalid password" }) }

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens({ username: user.username, email });

        // Hash the refresh token
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

        // Add new session info (multi-device support)
        user.sessions.push(hashedRefreshToken);
        user.is_account_disabled = false;

        // Make the songs fetchable if account as disabled before and save the user's new session
        await musicModal.updateMany({ adminId: user._id }, { $set: { stop_fechable: false } });
        await user.save();

        res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: "Lax", maxAge: 14 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'User logged in successfully', user, accessToken });

    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
    }
}

// Logout user
export const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) return res.status(400).json({ error: "Refresh token not found" });

        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        } catch (err) {
            return res.status(400).json({ error: "Failed to verify token." });
        }

        const user = await adminModel.findOne({ email: decoded?.email }).select("+sessions");
        if (!user) return res.status(404).json({ error: "User not found" });

        // Filter out the session matching the current hashed refreshToken
        user.sessions = user.sessions.filter(token => {
            return !bcrypt.compareSync(refreshToken, token);
        });
        await user.save();

        res.clearCookie("refreshToken");
        res.status(200).json({ message: "Logged out successfully" });

    } catch (error) {
        if (error.name === "TokenExpiredError" || error.name === "JsonWebTokenError") {
            return res.status(401).json({ error: "Unauthorised access" });
        }
        res.status(500).json({ error: "Internal server error" });
    }
};

// Logout from all devices
export const logoutAll = async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: "Password is required" });
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });

        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        const user = await adminModel.findOne({ email: decoded.email }).select("+password +sessions");
        if (!user) return res.status(404).json({ error: "User not found" });

        const isValidUser = await bcrypt.compare(password, user.password);
        if (!isValidUser) return res.status(400).json({ error: "Invalid password" });

        user.sessions = [];
        await user.save();

        res.clearCookie("refreshToken");
        res.status(200).json({ message: "Logged out from all devices successfully" });

    } catch (error) {
        if (error.name === "TokenExpiredError" || error.name === "JsonWebTokenError") {
            return res.status(401).json({ error: "Unauthorised access" });
        }
        res.status(500).json({ error: "Internal server error" });
    }
};

// Verify user | check login status | refresh expired access token
export const verifyUser = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) return res.status(401).json({ error: "Invalid or expired refresh token" });

        const decoded = verifyRefreshToken(refreshToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Invalid or expired refresh token" });

        const user = await adminModel.findOne({ email: decoded.email }).select("+sessions");
        if (!user) return res.status(404).json({ error: "User not found" });

        // Find the hashed token
        let matchingHashedToken = null;
        for (const hashedToken of user.sessions) {
            const isMatch = await bcrypt.compare(refreshToken, hashedToken);
            if (isMatch) {
                matchingHashedToken = hashedToken;
                break;
            }
        }
        if (!matchingHashedToken) return res.status(401).json({ error: "Invalid session. Please login again." });

        // Generate new tokens (sliding refresh)
        const { accessToken, refreshToken: newRefreshToken, error } = generateTokens({ username: user.username, email: user.email });
        if (error) return res.status(500).json({ error: "Error generating new tokens" });

        // Hash the new refresh token
        const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);

        // Replace the old hashed token with the new hashed token
        const updatedSessions = user.sessions.filter(session => session !== matchingHashedToken);
        updatedSessions.push(hashedNewRefreshToken);
        await adminModel.findOneAndUpdate(
            { email: decoded.email },
            { $set: { sessions: updatedSessions } }
        );

        res.cookie('refreshToken', newRefreshToken, { httpOnly: true, sameSite: 'Lax', maxAge: 14 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'Authenticated successfully', newToken: accessToken, newUser: user });

    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
};

// Uploads music
export const uploadMusic = async (req, res) => {
    try {
        let { title, artist, category, duration } = req.body;
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!title) return res.status(400).json({ error: "Title is required" });
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });

        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        // find the _id user id 
        const user = await adminModel.findOne({ email: decoded?.email }, { _id: 1 });
        if (!user) return res.status(404).json({ error: "User not found" });

        const musicFile = req.files?.music?.[0];
        const imageFile = req.files?.image?.[0];
        if (!musicFile) return res.status(400).json({ error: "Music file is required" });

        const musicURL = musicFile.path;
        const imageURL = imageFile?.path || "/template.png";

        const newMusic = new musicModal({ 
            title, 
            artist: artist?.trim() ? artist : "Unknown artist", 
            filePath: musicURL, 
            imagePath: imageURL, 
            category: category || "Not categorized", 
            duration, 
            adminId: user._id, 
            musicId: generateAlphanumericId(), 
            stop_fechable: false
        });

        await newMusic.save();
        res.status(201).json({ message: "Music uploaded and saved to Cloudinary", newMusic });

    } catch (error) {
        return res.status(500).json({ error: "Failed to upload to Cloudinary" });
    }
};

// Update profile image
export const updateProfileImage = async (req, res) => {
    try {
        const { deleteProfileImage = false } = req.body;
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });

        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        const user = await adminModel.findOne({ email: decoded?.email });
        if (!user) return res.status(404).json({ error: "User not found" });

        // Delete profile image if requested
        if (deleteProfileImage === 'true' || deleteProfileImage === true) {
            if (user.profileImage && user.profileImage !== '/user.png') {
                const publicId = extractPublicId(user.profileImage);
                await cloudinary.uploader.destroy(publicId, { resource_type: 'image' });

                user.profileImage = '/user.png';
                await user.save();
                return res.status(200).json({ message: 'Profile image deleted successfully' });
            }
        }

        // Replace with new uploaded image
        if (req.file && req.file.path) {
            // Delete previous image
            if (user.profileImage && user.profileImage !== '/user.png') {
                const publicId = extractPublicId(user.profileImage);
                await cloudinary.uploader.destroy(publicId, { resource_type: 'image' });
            }

            // Update with new image
            user.profileImage = req.file.path;
            await user.save();
            return res.status(200).json({ message: 'Profile image updated successfully', imageUrl: req.file.path });
        }

        return res.status(400).json({ message: 'No image uploaded or delete flag provided' });
    } catch (error) {
        return res.status(500).json({ message: 'Server error' });
    }
}

// Update user bio
export const updateProfile = async (req, res) => {
    try {
        const { username, nickname, bio } = req.body;
        if (!username || username?.length === 0) res.status(400).json({ error: "Bad request." });
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });

        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        const currentUser = await adminModel.findOne({ email: decoded?.email });
        if (!currentUser) return res.status(404).json({ error: "User not found." });

        // Check if the username is taken by another user (case-insensitive match)
        const existingUsername = await adminModel.findOne({
            username: { $regex: new RegExp(`^${username}$`, 'i') },
            _id: { $ne: currentUser._id }
        });
        if (existingUsername) return res.status(409).json({ error: "Username is already taken by another user." });

        // Make changes if conflict occurs
        currentUser.username = username;
        currentUser.nickname = nickname;
        currentUser.bio = bio;

        await currentUser.save();
        res.status(200).json({ message: "Profile updated successfully" });

    } catch (error) {
        res.status(500).json({ error: "Error updating profile due to internal server error." });
    }
}

// Get user profile + user uploaded songs
export const getProfileUser = async (req, res) => {
    try {
        const adminId = req.params?.adminId;
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        if (!adminId || adminId === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        if (!mongoose.Types.ObjectId.isValid(adminId)) return res.status(400).json({ error: "Invalid user id" });
        const objectId = new mongoose.Types.ObjectId(adminId);

        // Fetch user data without songs first
        let user = await adminModel.findById(objectId).lean();   // .lean() will return the plain js object without hydration
        if (!user) return res.status(404).json({ error: "User not found" });
        const totalSongs = await musicModal.countDocuments({ adminId: objectId });

        // Fetch paginated songs
        const songs = await musicModal.find({ adminId: objectId }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
        user = { ...user, musics: songs, currentPage: page, totalSongs, totalPages: Math.ceil(totalSongs / limit) }
        res.status(200).json({ user });

    } catch (error) {
        res.status(500).json({ error: "Error getting user due to internal server error" });
    }
};

// Update song metadata
export const updateSongMetadata = async (req, res) => {
    try {
        const { musicId, title, artist } = req.body;
        if (!musicId || !title) return res.status(400).json({ error: "Bad request" });
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });

        const decoded = verifyAccessToken(accessToken);
        if (!decoded) return res.status(401).json({ error: "Unauthorized access." });

        await musicModal.findOneAndUpdate({ musicId }, { $set: { title, artist } });
        res.status(200).json({ message: "Song metadata updated" })

    } catch (error) {
        res.status(500).json({ error: "Error updating song metadata due to internal server error." })
    }
}

// Get all music on home page
export const getMusics = async (req, res) => {
    try {
        const { category } = req.query;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 25;
        const skip = (page - 1) * limit;

        const query = { stop_fechable: false };

        if (category) {
            const categories = category.split(',').map(cat => cat.trim());
            query.category = { $in: categories };
        }

        const musics = await musicModal.find(query).populate('adminId', 'username profileImage').sort({ createdAt: -1 }).skip(skip).limit(limit);
        const total = await musicModal.countDocuments(query);
        const hasMore = skip + musics.length < total;

        if (!musics || musics.length === 0) return res.status(200).json({ musics: [], hasMore: false });
        return res.status(200).json({ musics, hasMore });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error" });
    }
};

// Get musics grouped by users
export const getMusicsGroupedByUsers = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const usersLimit = 15;
        const songsPerUser = 35;
        const skipUsers = (page - 1) * usersLimit;
        const categoryFilter = req.query.category?.split(',') || [];

        // Step 1: Filter users who have songs in that category
        const userIds = await musicModal
            .find({ stop_fechable: false, ...(categoryFilter.length > 0 && { category: { $in: categoryFilter } }) })
            .distinct("adminId")
            .then(ids => ids.slice(skipUsers, skipUsers + usersLimit));

        const grouped = {};
        const userSongCounts = {};

        for (const userId of userIds) {
            const query = { stop_fechable: false, adminId: userId, ...(categoryFilter.length > 0 && { category: { $in: categoryFilter } }) };

            const songs = await musicModal.find(query).populate('adminId', 'username profileImage').sort({ createdAt: -1 }).limit(songsPerUser);

            if (songs.length > 0) {
                grouped[userId] = songs;
                userSongCounts[userId] = await musicModal.countDocuments(query);
            }
        }

        const totalUsers = await musicModal
            .find({ stop_fechable: false, ...(categoryFilter.length > 0 && { category: { $in: categoryFilter } }) })
            .distinct("adminId")   // returns only the distinct adminId values
            .then(ids => ids.length);

        const hasMoreUsers = skipUsers + userIds.length < totalUsers;
        res.status(200).json({ musicsByUser: grouped, userSongCounts, hasMoreUsers, currentPage: page });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error" });
    }
};

// Get more songs for a specific user
export const getUserSongs = async (req, res) => {
    try {
        const { userId } = req.params;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 35;
        const skip = (page - 1) * limit;
        const categoryFilter = req.query.category?.split(',') || [];

        const query = { stop_fechable: false, adminId: userId, ...(categoryFilter.length > 0 && { category: { $in: categoryFilter } }) };
        const songs = await musicModal.find(query).populate('adminId', 'username profileImage').sort({ createdAt: -1 }).skip(skip).limit(limit);

        const total = await musicModal.countDocuments(query);
        const hasMore = skip + songs.length < total;
        res.status(200).json({ songs, hasMore, total, currentPage: page });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error" });
    }
};

// Increament play count
export const incrementPlayCount = async (req, res) => {
    try {
        const { musicId, visitorId } = req.params;
        if (!musicId || musicId === 'undefined' || !visitorId || visitorId === 'undefined') return res.status(400).json({ error: "Bad request." });

        const alreadyPlayed = await songPlaysModal.findOne({ musicId, visitorId });
        if (alreadyPlayed) return res.status(200).json({ message: "Already counted" });

        await songPlaysModal.create({ musicId, visitorId });

        // Increment play count on song
        const music = await musicModal.findOneAndUpdate({ musicId }, { $inc: { playCount: 1 } }, { new: true });
        res.status(200).json({ playCount: music.playCount });

    } catch (error) {
        if (error.code === 11000) return res.status(200).json({ message: "Already counted" });
        res.status(500).json({ error: "Internal server error." });
    }
};

// Delete music
export const deleteMusic = async (req, res) => {
    try {
        // Verifying user
        const musicId = req.params?.musicId;
        if (!musicId) return res.status(400).json({ error: "Bad request" });

        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        const decoded = verifyAccessToken(accessToken);
        if (!decoded) return res.status(401).json({ error: "Unauthorized access." });

        // Deleting musics from cloudinary + database
        const music = await musicModal.findOne({ musicId });
        if (!music) return res.status(404).json({ error: "Music not found or not authorized" });

        const fileId = extractPublicId(music.filePath);
        const imageId = extractPublicId(music.imagePath);

        // Delete files from Cloudinary
        const deletionPromises = [];

        if (music.filePath && music.filePath.startsWith("http") && fileId) {
            deletionPromises.push(cloudinary.uploader.destroy(fileId, { resource_type: "video" }));
        }

        if (music.imagePath && music.imagePath.startsWith("http") && imageId) {
            deletionPromises.push(cloudinary.uploader.destroy(imageId, { resource_type: "image" }));
        }

        // Wait for all deletions to complete
        if (deletionPromises.length > 0) {
            const results = await Promise.all(deletionPromises);
        }

        await musicModal.deleteOne({ musicId });
        res.status(200).json({ message: "Music deleted successfully" });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error" });
    }
};

// Change password
export const changePassword = async (req, res) => {
    try {
        const { password, newPassword } = req.body;
        if (!password || !newPassword) return res.status(400).json({ error: "Password & New password are required." });

        // verify user
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        // Find user and validate password
        const user = await adminModel.findOne({ email: decoded.email }).select("+password");
        if (!user) return res.status(404).json({ error: "User not found" });

        const isValidUser = await bcrypt.compare(password, user.password);
        if (!isValidUser) return res.status(400).json({ error: "Invalid password" });
        if (password === newPassword) return res.status(409).json({ error: "You can't use your old password. Please choose a different one." })

        // Hash new password and store
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        await user.save();
        res.status(200).json({ message: "Password updated" });

    } catch (error) {
        res.status(500).json({ error: "Error changing password due to internal server error." })
    }
}

// Disable account
export const disableAccount = async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: "Password is required." });

        // Verify user and get credentials
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        // Find user
        const user = await adminModel.findOne({ email: decoded.email }).select("+password +sessions");
        if (!user) return res.status(404).json({ error: "User not found" });

        // Validate password
        const isValidUser = await bcrypt.compare(password, user.password);
        if (!isValidUser) return res.status(400).json({ error: "Invalid password" });

        // Find song and stop them from fetching
        await musicModal.updateMany({ adminId: user._id }, { $set: { stop_fechable: true } });

        // Make user unavailable and logout from all devices
        user.sessions = [];
        user.is_account_disabled = true;
        await user.save();

        res.clearCookie("refreshToken");
        res.status(200).json({ message: "Account disabled." });

    } catch (error) {
        res.status(500).json({ error: "Error disabling account due to internal server error." })
    }
}

// Delete all musics
export const deleteAllMusic = async (req, res) => {
    try {
        // Verifying user
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        const user = await adminModel.findOne({ email: decoded?.email }, { _id: 1 }).lean();
        if (!user || !user._id) return res.status(404).json({ error: "User not found" });

        // Deleting musics from cloudinary + database
        const musics = await musicModal.find({ adminId: user._id });

        // Batch deletion of media to handle rate limit
        const batchSize = 15;

        for (let i = 0; i < musics.length; i += batchSize) {
            const batch = musics.slice(i, i + batchSize);
            const deletes = [];

            for (const music of batch) {
                if (music.filePath?.startsWith("http")) {
                    deletes.push(cloudinary.uploader.destroy(extractPublicId(music.filePath), { resource_type: "video" }));
                }
                if (music.imagePath?.startsWith("http")) {
                    deletes.push(cloudinary.uploader.destroy(extractPublicId(music.imagePath), { resource_type: "image" }));
                }
            }
            await Promise.all(deletes); // Wait before starting next batch
        }

        await musicModal.deleteMany({ adminId: user._id });
        res.status(200).json({ message: "All musics deleted for this admin" });

    } catch (error) {
        res.status(500).json({ error: "Failed to delete all musics" });
    }
};

// Delete account
export const deleteAccount = async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: "Password is required." });

        // Verify user and get credentials
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        // Find user
        const user = await adminModel.findOne({ email: decoded.email }).select("+password +sessions");
        if (!user) return res.status(404).json({ error: "User not found" });

        // Validate password
        const isValidUser = await bcrypt.compare(password, user.password);
        if (!isValidUser) return res.status(400).json({ error: "Invalid password" });

        // Find and delete media from cloudinary
        const musics = await musicModal.find({ adminId: user._id });

        // Batch deletion of media to handle rate limit
        const batchSize = 15;

        for (let i = 0; i < musics.length; i += batchSize) {
            const batch = musics.slice(i, i + batchSize);
            const deletes = [];

            for (const music of batch) {
                if (music.filePath?.startsWith("http")) {
                    deletes.push(cloudinary.uploader.destroy(extractPublicId(music.filePath), { resource_type: "video" }));
                }
                if (music.imagePath?.startsWith("http")) {
                    deletes.push(cloudinary.uploader.destroy(extractPublicId(music.imagePath), { resource_type: "image" }));
                }
            }
            await Promise.all(deletes); // Wait before starting next batch
        }

        if (user.profileImage && user.profileImage.startsWith("http")) {
            const profileImageId = extractPublicId(user.profileImage);
            await cloudinary.uploader.destroy(profileImageId, { resource_type: 'image' });
        }

        // Delete user from database
        await musicModal.deleteMany({ adminId: user._id });
        await adminModel.deleteOne({ _id: user._id });

        res.clearCookie("refreshToken");
        res.status(200).json({ message: "Account deleted." });

    } catch (error) {
        res.status(500).json({ error: "Failed to delete account due to internal server error." });
    }
}

// Send email updation link
export const sendEmailUpdationLink = async (req, res) => {
    try {
        // Verifying user
        const accessToken = req.headers?.authorization?.split(' ')[1] || req.headers?.Authorization?.split(' ')[1];
        if (!accessToken || accessToken === 'undefined') return res.status(401).json({ error: "Unauthorized access" });
        const decoded = verifyAccessToken(accessToken);
        if (!decoded || !decoded?.email) return res.status(401).json({ error: "Unauthorized access." });

        const user = await adminModel.findOne({ email: decoded?.email }).lean();
        if (!user) return res.status(404).json({ error: "User not found" });

        // Generate token & store in email token TTL collection
        const emailUpdationToken = jwt.sign({ email: user.email, id: user._id }, process.env.EMAIL_TOKEN_SECRET, { expiresIn: '15m' });
        const hashedToken = await bcrypt.hash(emailUpdationToken, 10);

        // Check for any previously existing token and delete them, and create a latest token
        await emailUpdateModel.deleteMany({ adminId: user._id });
        await emailUpdateModel.create({ adminId: user._id, token: hashedToken });

        // Send mail
        const link = `${process.env.FRONTEND_URL}/update-email?token=${encodeURIComponent(emailUpdationToken)}`;

        const mailData = {
            to: user.email,
            subject: "Email Updation Request – Sonexa",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; color: #333;">
                    <h2 style="color: #4CAF50;">Sonexa – Email Update Request</h2>
                    <p>Hello ${user.name || "Sonexa user"},</p>
                    <p>We received a request to update your email address associated with your Sonexa account.</p>
                    <p>Please click the button below to proceed:</p>
                    <a href="${link}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Update Email</a>
                    <p>If the button above doesn’t work, copy and paste the following URL into your browser:</p>
                    <p style="word-break: break-all;"><a href="${link}" style="color: #4CAF50;">${link}</a></p>
                    <p>This link will expire in 15 minutes for your security.</p>
                    <p>Thanks,<br/>The Sonexa Team</p>
                </div>
            `
        }
        await sendMail(mailData);
        res.status(200).json({ message: "Email updation link has been sent to your email." })

    } catch (error) {
        res.status(500).json({ error: "Error sending email updation link due to internal server error." })
    }
}

// Update email
export const updateEmail = async (req, res) => {
    try {
        const { token, newEmail } = req.body;
        if (!token || !newEmail) return res.status(400).json({ error: "Token and new email are required" });
        let decoded;

        try {
            decoded = jwt.verify(token, process.env.EMAIL_TOKEN_SECRET);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(400).json({ error: "Token has expired. Please request a new one." });
            } else if (err.name === 'JsonWebTokenError') {
                return res.status(400).json({ error: "Invalid token format." });
            } else {
                return res.status(400).json({ error: "Failed to verify token." });
            }
        }

        // Find token from token TTL collection
        const emailToken = await emailUpdateModel.findOne({ adminId: decoded.id });
        if (!emailToken) return res.status(400).json({ error: "Invalid or expired token" });

        const isValid = await bcrypt.compare(token, emailToken.token);
        if (!isValid) return res.status(400).json({ error: "Invalid or expired token" });

        // Check if the new email is already in use by another user
        const existingUser = await adminModel.findOne({ email: newEmail });
        if (existingUser) return res.status(409).json({ error: "This email is already taken by another account." });

        // Find user from admin collection
        const user = await adminModel.findById(decoded.id);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (user.email === newEmail) return res.status(409).json({ error: "You can't use your current email" });
        user.email = newEmail;

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens({ username: user.username, email: newEmail });

        // Hash the refresh token
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        user.sessions = [hashedRefreshToken];

        // Save user and remove the used token from DB
        await user.save();
        await emailUpdateModel.deleteOne({ _id: emailToken._id });

        res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: "Lax", maxAge: 14 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'Email updated successfully', user, accessToken });

    } catch (err) {
        res.status(500).json({ error: "Internal server error" });
    }
};

// Generate forgot password link
export const sendForgotPasswordLink = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email is required" })

        const user = await adminModel.findOne({ email }).lean();
        if (!user) return res.status(404).json({ error: "User not found" });

        // Generate token & store in password token TTL collection
        const forgotPasswordToken = jwt.sign({ email: user.email, id: user._id }, process.env.PASSWORD_TOKEN_SECRET, { expiresIn: '15m' });
        const hashedToken = await bcrypt.hash(forgotPasswordToken, 10);

        // Check for any previously existing token and delete them, and create a latest token
        await forgotPasswordModel.deleteMany({ adminId: user._id });
        await forgotPasswordModel.create({ adminId: user._id, token: hashedToken });

        // Send mail
        const link = `${process.env.FRONTEND_URL}/reset-password?token=${encodeURIComponent(forgotPasswordToken)}`;

        const mailData = {
            to: user.email,
            subject: "Password Reset Request – Sonexa",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; color: #333;">
                    <h2 style="color: #4CAF50;">Sonexa – Password Reset Request</h2>
                    <p>Hello ${user.name || "Sonexa user"},</p>
                    <p>We received a request to reset your password.</p>
                    <p>Please click the button below to proceed:</p>
                    <a href="${link}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
                    <p>If the button above doesn’t work, copy and paste the following URL into your browser:</p>
                    <p style="word-break: break-all;"><a href="${link}" style="color: #4CAF50;">${link}</a></p>
                    <p>This link will expire in 15 minutes for your security.</p>
                    <p>Thanks,<br/>The Sonexa Team</p>
                </div>
            `
        }
        await sendMail(mailData);
        res.status(200).json({ message: "Password reset link has been sent to your email." });

    } catch (error) {
        res.status(500).json({ error: "Error generating forgot password link due to internal server error" })
    }
}

// Reset password
export const resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(404).json({ error: "Token and new password are required" });

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.PASSWORD_TOKEN_SECRET);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(400).json({ error: "Token has expired. Please request a new one." });
            } else if (err.name === 'JsonWebTokenError') {
                return res.status(400).json({ error: "Invalid token format." });
            } else {
                return res.status(400).json({ error: "Failed to verify token." });
            }
        }

        // Find token from token TTL collection
        const passwordToken = await forgotPasswordModel.findOne({ adminId: decoded.id });
        if (!passwordToken) return res.status(400).json({ error: "Invalid or expired token" });

        const isValid = await bcrypt.compare(token, passwordToken.token);
        if (!isValid) return res.status(400).json({ error: "Invalid or expired token" });

        // Find user from admin collection
        const user = await adminModel.findById(decoded.id).select("+password");
        if (!user) return res.status(404).json({ error: "User not found" });

        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) return res.status(409).json({ error: "You can't use your current password." });

        // hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        // Save user and remove the used token from DB
        await user.save();
        await forgotPasswordModel.deleteOne({ _id: passwordToken._id });
        res.status(200).json({ message: 'Password reset successfully' });

    } catch (error) {
        res.status(500).json({ error: "Error to reset password due to internal server error." });
    }
}

// Search query
export const search = async (req, res) => {
    try {
        const { query, page = 1, limit = 25 } = req.body;
        if (!query || query.trim().length === 0) return res.status(400).json({ error: 'Search query is required', songs: [], accounts: [] });

        const skip = (page - 1) * limit;
        const searchRegex = new RegExp(query.trim(), 'i');

        // Search for songs
        const songsPromise = musicModal.find({
            stop_fechable: false,
            $or: [{ title: searchRegex }, { artist: searchRegex }, { category: searchRegex }]
        })
            .populate({
                path: 'adminId',
                select: 'username _id',
                match: { is_account_disabled: false }
            })
            .skip(skip)
            .limit(limit)
            .sort({ playCount: -1, createdAt: -1 });

        // Search for accounts
        const accountsPromise = adminModel.find({
            is_account_disabled: false,
            $or: [{ username: searchRegex }, { nickname: searchRegex }, { bio: searchRegex }]
        })
            .skip(skip)
            .limit(limit)
            .sort({ createdAt: -1 });

        const [songs, accounts] = await Promise.all([songsPromise, accountsPromise]);
        res.status(200).json({ songs, accounts, page, hasMore: songs.length === limit || accounts.length === limit });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error', songs: [], accounts: [] });
    }
};











