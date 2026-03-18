import crypto from "crypto";
import { EventEmitter } from "events";
import geoip from "geoip-lite";
import HoneypotAttack from "../models/honeypotAttack.js";
import { ensureDatabaseConnection } from "./database.js";

const RELEVANT_EVENT_IDS = new Set([
  "cowrie.login.failed",
  "cowrie.login.success",
  "cowrie.command.input"
]);
const DEFAULT_RECENT_ATTACK_LIMIT = 40;
const MAX_RECENT_ATTACK_LIMIT = 200;
const DEFAULT_MAP_WINDOW_MINUTES = 120;
const MAX_MAP_WINDOW_ATTACKS = 2000;
const honeypotStartedAt = new Date();

const honeypotEventBus = new EventEmitter();
honeypotEventBus.setMaxListeners(0);
let totalAttacksSinceStartup = 0;

function parseNumber(value, fallback = null) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function trimString(value) {
  if (value === undefined || value === null) {
    return null;
  }

  const text = String(value).trim();
  return text ? text : null;
}

function parseTimestamp(value) {
  const date = new Date(value ?? Date.now());
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function resolveRecentAttackLimit(value) {
  return Math.max(
    1,
    Math.min(MAX_RECENT_ATTACK_LIMIT, Number.parseInt(value ?? `${DEFAULT_RECENT_ATTACK_LIMIT}`, 10) || DEFAULT_RECENT_ATTACK_LIMIT)
  );
}

function getMapWindowMinutes() {
  return DEFAULT_MAP_WINDOW_MINUTES;
}

function getMapWindowStart() {
  return new Date(Date.now() - getMapWindowMinutes() * 60 * 1000);
}

function getHoneypotTarget() {
  return {
    label: trimString(process.env.HONEYPOT_TARGET_LABEL) ?? "India Honeypot",
    lat: parseNumber(process.env.HONEYPOT_TARGET_LAT, 20.5937),
    lng: parseNumber(process.env.HONEYPOT_TARGET_LNG, 78.9629),
    country: trimString(process.env.HONEYPOT_TARGET_COUNTRY) ?? "India",
    countryCode: trimString(process.env.HONEYPOT_TARGET_COUNTRY_CODE) ?? "IN"
  };
}

function resolveGeo(ipAddress) {
  const geo = geoip.lookup(ipAddress);
  return {
    lat: Array.isArray(geo?.ll) ? parseNumber(geo.ll[0]) : null,
    lng: Array.isArray(geo?.ll) ? parseNumber(geo.ll[1]) : null,
    country: trimString(geo?.country),
    countryCode: trimString(geo?.country),
    region: trimString(geo?.region),
    city: trimString(geo?.city),
    org: null,
    asn: null
  };
}

function buildEventFingerprint(event) {
  return crypto
    .createHash("sha1")
    .update(
      JSON.stringify([
        event.eventId,
        event.session,
        event.timestamp.toISOString(),
        event.source.ip,
        event.username,
        event.password,
        event.command
      ])
    )
    .digest("hex");
}

function normalizeCowrieEvent(rawEvent) {
  const eventId = trimString(rawEvent?.eventid ?? rawEvent?.eventId);
  if (!eventId || !RELEVANT_EVENT_IDS.has(eventId)) {
    return null;
  }

  const sourceIp = trimString(rawEvent?.src_ip ?? rawEvent?.srcIp ?? rawEvent?.ip);
  if (!sourceIp) {
    return null;
  }

  const timestamp = parseTimestamp(rawEvent?.timestamp ?? rawEvent?.time ?? rawEvent?.ts);
  const username = trimString(rawEvent?.username ?? rawEvent?.user);
  const password = trimString(rawEvent?.password ?? rawEvent?.passwd);
  const command = trimString(rawEvent?.input ?? rawEvent?.command);
  const sourcePort = parseNumber(rawEvent?.src_port ?? rawEvent?.srcPort);
  const wasSuccessful =
    eventId === "cowrie.login.success" ? true : eventId === "cowrie.login.failed" ? false : null;

  const normalizedEvent = {
    eventId,
    session: trimString(rawEvent?.session),
    timestamp,
    source: {
      ip: sourceIp,
      port: sourcePort,
      ...resolveGeo(sourceIp)
    },
    target: getHoneypotTarget(),
    username,
    password,
    command,
    wasSuccessful,
    clientVersion: trimString(rawEvent?.version ?? rawEvent?.sshVersion),
    hassh: trimString(rawEvent?.hassh ?? rawEvent?.hasshFingerprint),
    protocol: trimString(rawEvent?.protocol) ?? "ssh"
  };

  normalizedEvent.eventFingerprint = buildEventFingerprint(normalizedEvent);
  return normalizedEvent;
}

function serializeAttack(document) {
  const attack = typeof document?.toObject === "function" ? document.toObject() : document;

  return {
    id: String(attack?._id ?? attack?.eventFingerprint ?? ""),
    eventId: attack?.eventId ?? null,
    session: attack?.session ?? null,
    timestamp:
      attack?.timestamp instanceof Date
        ? attack.timestamp.toISOString()
        : trimString(attack?.timestamp) ?? null,
    ingestedAt:
      attack?.ingestedAt instanceof Date
        ? attack.ingestedAt.toISOString()
        : trimString(attack?.ingestedAt) ?? null,
    source: {
      ip: attack?.source?.ip ?? null,
      port: attack?.source?.port ?? null,
      lat: parseNumber(attack?.source?.lat),
      lng: parseNumber(attack?.source?.lng),
      country: attack?.source?.country ?? null,
      countryCode: attack?.source?.countryCode ?? null,
      region: attack?.source?.region ?? null,
      city: attack?.source?.city ?? null,
      org: attack?.source?.org ?? null,
      asn: attack?.source?.asn ?? null
    },
    target: {
      label: attack?.target?.label ?? null,
      lat: parseNumber(attack?.target?.lat),
      lng: parseNumber(attack?.target?.lng),
      country: attack?.target?.country ?? null,
      countryCode: attack?.target?.countryCode ?? null
    },
    username: attack?.username ?? null,
    password: attack?.password ?? null,
    command: attack?.command ?? null,
    wasSuccessful:
      typeof attack?.wasSuccessful === "boolean" ? attack.wasSuccessful : attack?.wasSuccessful ?? null,
    clientVersion: attack?.clientVersion ?? null,
    hassh: attack?.hassh ?? null,
    protocol: attack?.protocol ?? "ssh"
  };
}

export function subscribeToHoneypotAttacks(listener) {
  honeypotEventBus.on("attack", listener);
  return () => {
    honeypotEventBus.off("attack", listener);
  };
}

export async function ingestCowrieEvents(rawEvents) {
  await ensureDatabaseConnection();

  const events = Array.isArray(rawEvents) ? rawEvents : [rawEvents];
  const createdAttacks = [];
  let duplicateCount = 0;
  let skippedCount = 0;

  for (const rawEvent of events) {
    const normalizedEvent = normalizeCowrieEvent(rawEvent);
    if (!normalizedEvent) {
      skippedCount += 1;
      continue;
    }

    try {
      const createdAttack = await HoneypotAttack.create(normalizedEvent);
      const serializedAttack = serializeAttack(createdAttack);
      totalAttacksSinceStartup += 1;
      createdAttacks.push(serializedAttack);
      honeypotEventBus.emit("attack", {
        attack: serializedAttack,
        totalSinceStartup: totalAttacksSinceStartup
      });
    } catch (error) {
      if (error?.code === 11000) {
        duplicateCount += 1;
        continue;
      }

      throw error;
    }
  }

  return {
    received: events.length,
    created: createdAttacks.length,
    duplicates: duplicateCount,
    skipped: skippedCount,
    attacks: createdAttacks
  };
}

export async function listRecentHoneypotAttacks(limit = 40) {
  await ensureDatabaseConnection();

  const boundedLimit = resolveRecentAttackLimit(limit);
  const documents = await HoneypotAttack.find()
    .sort({ timestamp: -1, _id: -1 })
    .limit(boundedLimit)
    .lean();

  return documents.map(serializeAttack);
}

export async function listMapWindowHoneypotAttacks() {
  await ensureDatabaseConnection();

  const documents = await HoneypotAttack.find({
    timestamp: { $gte: getMapWindowStart() }
  })
    .sort({ timestamp: -1, _id: -1 })
    .limit(MAX_MAP_WINDOW_ATTACKS)
    .lean();

  return documents.map(serializeAttack);
}

export async function countMapWindowHoneypotAttacks() {
  await ensureDatabaseConnection();

  return HoneypotAttack.countDocuments({
    timestamp: { $gte: getMapWindowStart() }
  });
}

export function getHoneypotFeedMetadata() {
  return {
    generatedAt: new Date().toISOString(),
    target: getHoneypotTarget(),
    startedAt: honeypotStartedAt.toISOString(),
    totalSinceStartup: totalAttacksSinceStartup,
    mapWindowMinutes: getMapWindowMinutes()
  };
}
