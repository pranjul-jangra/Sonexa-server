function errorHandler(err, req, res, next) {
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal Server Error';
    console.log("Error caught by middleware:", err);

    res.status(statusCode).json({
        success: false,
        error: { message, statusCode },
    });
}

export default errorHandler;