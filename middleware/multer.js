import multer from "multer";
import path from "path";
import dotenv from 'dotenv'
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
dotenv.config();


// Configure cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Setup storage
const storage = new CloudinaryStorage({
    cloudinary,
    params: async (req, file) => {
        const isAudio = file.mimetype.startsWith("audio");
        const isImage = file.mimetype.startsWith("image");
        let folder, resource_type;

        if (isAudio) {
            folder = "music";
            resource_type = "video";
        } else if (isImage) {
            folder = "images";
            resource_type = "image";
        } else {
            folder = "uploads";
            resource_type = "auto";
        }

        return {
            folder,
            resource_type,
            public_id: `${Date.now()}-${file.originalname.split('.')[0]}`,
            // Comperssing images
            ...(isImage && {
                format: "webp",
                transformation: [{ width: 800, height: 800, crop: "limit" }]
            })
        };
    },
});

// Validate file type
const allowedExtensions = [
    '.mp3', '.m4a', '.wav', '.aac', '.ogg', '.aiff',
    '.jpg', '.jpeg', '.bmp', '.tif', '.tiff', '.ico', '.heic', '.heif', '.png', '.webp', '.avif'
];

const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isValidType = (file.mimetype.startsWith("audio/") || file.mimetype.startsWith("image/")) && allowedExtensions.includes(ext);

    if (!isValidType) {
        console.log(`Rejected file: ${file.originalname}, mimetype: ${file.mimetype}, extension: ${ext}`);
        return cb(new Error(`Invalid file type. Allowed: audio and image files only.`), false);
    }
    
    cb(null, isValidType);
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 50 * 1024 * 1024, files: 2 },  // 50 MB file limit
});

export default upload;