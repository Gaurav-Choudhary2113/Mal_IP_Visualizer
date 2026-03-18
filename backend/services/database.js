import mongoose from "mongoose";

let connectionPromise = null;

export function isDatabaseConfigured() {
  return Boolean(process.env.MONGODB_URI?.trim());
}

export async function connectDatabase() {
  if (!isDatabaseConfigured()) {
    return false;
  }

  if (mongoose.connection.readyState === 1) {
    return true;
  }

  if (connectionPromise) {
    return connectionPromise;
  }

  connectionPromise = mongoose
    .connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000
    })
    .then(() => {
      console.log("[MongoDB] Connected.");
      return true;
    })
    .catch((error) => {
      connectionPromise = null;
      throw error;
    });

  return connectionPromise;
}

export async function ensureDatabaseConnection() {
  if (!isDatabaseConfigured()) {
    throw new Error("MONGODB_URI is missing.");
  }

  await connectDatabase();
}
