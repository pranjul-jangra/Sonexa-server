import express from 'express';
import upload from '../middleware/multer.js';
import profileImageUpload from '../middleware/profileImageUpload.js';
import {
    changePassword, deleteAccount, deleteAllMusic, deleteMusic,
    disableAccount, getMusics, getMusicsGroupedByUsers, getProfileUser,
    getUserSongs, incrementPlayCount, login, logout, logoutAll, register,
    resetPassword,
    search,
    sendEmailUpdationLink, sendForgotPasswordLink, updateEmail, updateProfile, updateProfileImage,
    updateSongMetadata, uploadMusic, verifyUser
} from '../controllers/adminController.js';



const adminRouter = express.Router();

// Singup and login
adminRouter.post('/register', register);
adminRouter.post('/login', login);

// Logging out
adminRouter.post('/logout', logout);
adminRouter.post('/logout-all', logoutAll);

// Update profile
adminRouter.post('/upload-profile-image', profileImageUpload.single('image'), updateProfileImage);
adminRouter.post('/update-profile', updateProfile);

// Refresh expired access token
adminRouter.post('/refresh', verifyUser);

// Upload | update music
adminRouter.post('/upload-music', upload.fields([{ name: "music", maxCount: 1 }, { name: "image", maxCount: 1 }]), uploadMusic);
adminRouter.post('/update-song', updateSongMetadata);
adminRouter.patch('/inc-play-count/:musicId/:visitorId', incrementPlayCount);

// Get user with user songs
adminRouter.get('/user/:adminId', getProfileUser);

// Get music
adminRouter.get('/musics', getMusics);  // get all musics on home
adminRouter.get('/grouped-musics', getMusicsGroupedByUsers);  //paginated user separated songs
adminRouter.get('/user-songs/:userId', getUserSongs); // paginated user separated songs

// Delete music
adminRouter.delete('/delete-music/:musicId', deleteMusic);
adminRouter.delete('/delete-all-music', deleteAllMusic);

// Password
adminRouter.post('/update-password', changePassword);

// Disable account
adminRouter.post('/disable-account', disableAccount);

// Delete account
adminRouter.post('/delete-account', deleteAccount);

// Update email
adminRouter.get('/send-email-updation-token', sendEmailUpdationLink);
adminRouter.post('/update-email', updateEmail);

// Reset password
adminRouter.post('/send-password-reset-token', sendForgotPasswordLink);
adminRouter.post('/reset-password', resetPassword);

// Search query
adminRouter.post('/search', search);


export default adminRouter;