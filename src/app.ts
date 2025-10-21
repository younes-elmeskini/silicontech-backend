import express from "express";
import userRoutes from "./routes/UserRoute";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
dotenv.config();

const app = express();

// Middleware
app.use(express.json());

app.use(cookieParser());

app.use(
  cors({
    origin: ["http://localhost:3000", "https://silicontech.elmeskini.site/"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization", "Set-Cookie"],
  })
);

app.disable("x-powered-by");

app.use(helmet());
app.set("trust proxy", 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
});

app.use(limiter);
// Routes
app.use("/", userRoutes);


export default app;
