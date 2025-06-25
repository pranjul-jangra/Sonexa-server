import express from 'express';
import cors from 'cors'
import dotenv from 'dotenv'
import cookieParser from "cookie-parser";
import connectDB from './config/connectDb.js';
import adminRouter from './routes/adminRoutes.js';
import errorHandler from './middleware/errorHandler.js';

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Middlewares
connectDB();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
}));
app.options(/.*/, cors());

app.set('trust proxy', true); // Required if behind a proxy (e.g., on Vercel, Render, etc.)

// Routes
app.use('/api/admin', adminRouter);


// Error handler
app.use(errorHandler);

// Listning to port
app.listen(port, () => { console.log(`Server is running...`); });