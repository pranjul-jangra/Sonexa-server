import multer from "multer";
import path from "path";
import dotenv from "dotenv";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
dotenv.config();

// Cloudinary config
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Profile image storage
const profileImageStorage = new CloudinaryStorage({
    cloudinary,
    params: async (req, file) => {
        const publicId = `user-profile-${Date.now()}-${file.originalname.split('.')[0]}`;
        return {
            folder: "profile-images",
            public_id: publicId,
            resource_type: "image",
            format: "webp",
            transformation: [
                {
                    width: 400,
                    height: 400,
                    crop: "fill",
                    gravity: "face", // Focus on face if detected
                    quality: "auto:good"
                }
            ]
        };
    },
});

// Allowed image types
const allowedImageExtensions = [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".heic", ".heif"];

const profileImageFileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isValidType = file.mimetype.startsWith("image/") && allowedImageExtensions.includes(ext);

    if (!isValidType) {
        console.log("File rejected:", {
            extension: ext,
            mimetype: file.mimetype,
            validMimeType: isValidMimeType,
            validExtension: isValidExtension
        });
        return cb(new Error(`Invalid file type. Allowed extensions: ${allowedImageExtensions.join(', ')}`), false);
    }

    cb(null, isValidType);
};

// Multer config
const profileImageUpload = multer({
    storage: profileImageStorage,
    fileFilter: profileImageFileFilter,
    limits: { fileSize: 10 * 1024 * 1024, files: 1 },
});

export default profileImageUpload;
