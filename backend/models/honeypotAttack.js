import mongoose from "mongoose";

const sourceSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true },
    port: { type: Number, default: null },
    lat: { type: Number, default: null },
    lng: { type: Number, default: null },
    country: { type: String, default: null },
    countryCode: { type: String, default: null },
    region: { type: String, default: null },
    city: { type: String, default: null },
    org: { type: String, default: null },
    asn: { type: String, default: null }
  },
  { _id: false }
);

const targetSchema = new mongoose.Schema(
  {
    label: { type: String, required: true },
    lat: { type: Number, required: true },
    lng: { type: Number, required: true },
    country: { type: String, required: true },
    countryCode: { type: String, required: true }
  },
  { _id: false }
);

const honeypotAttackSchema = new mongoose.Schema(
  {
    eventFingerprint: { type: String, required: true, unique: true, index: true },
    eventId: { type: String, required: true, index: true },
    session: { type: String, default: null, index: true },
    timestamp: { type: Date, required: true, index: true },
    ingestedAt: { type: Date, default: Date.now, index: true },
    source: { type: sourceSchema, required: true },
    target: { type: targetSchema, required: true },
    username: { type: String, default: null },
    password: { type: String, default: null },
    command: { type: String, default: null },
    wasSuccessful: { type: Boolean, default: null },
    clientVersion: { type: String, default: null },
    hassh: { type: String, default: null },
    protocol: { type: String, default: "ssh" }
  },
  {
    versionKey: false
  }
);

honeypotAttackSchema.index({ timestamp: -1 });
honeypotAttackSchema.index({ "source.ip": 1, timestamp: -1 });

const HoneypotAttack =
  mongoose.models.HoneypotAttack ||
  mongoose.model("HoneypotAttack", honeypotAttackSchema, "honeypot_attacks");

export default HoneypotAttack;
