import jwt from "jsonwebtoken";
import { randomBytes } from 'crypto';

// Generate unique music id
export function generateAlphanumericId() {
    return randomBytes(16).toString('hex').slice(0, 8);
}

// Generate access and refresh tokens
export const generateTokens = (obj) => {
    try {
        const { username, email } = obj;
        if (!username || !email) return { accessToken: null, refreshToken: null, error: "Username and email are required" };

        // Generate token
        const accessToken = jwt.sign({ username, email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '3h' });
        const refreshToken = jwt.sign({ username, email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '14d' });

        return { accessToken, refreshToken, error: null };

    } catch (error) {
        return { accessToken: null, refreshToken: null, error: "Error generating tokens" };
    }
}

// Verify refresh token
export const verifyRefreshToken = (token) => {
    try {
        if (!token) return null;
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        } catch (err) {
            return null;
        }
        return decoded;

    } catch (error) {
        return null;
    }
};

// Verify access token
export const verifyAccessToken = (token) => {
    try {
        if (!token) return null;
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        } catch (err) {
            return null;
        }
        return decoded;

    } catch (error) {
        return null;
    }
}