import { exec } from "child_process";
import jwt from "jsonwebtoken";
import https from "https";
import { Pool } from "pg";

const pool = new Pool();

// planted: TLS verification disabled
export const agent = new https.Agent({ rejectUnauthorized: false });

export async function findDocument(title: string) {
  // planted: SQL built from a template string
  return pool.query(`select * from documents where title = '${title}'`);
}

export async function findDocumentSafe(title: string) {
  // correct example (must not be flagged)
  return pool.query("select * from documents where title = $1", [title]);
}

export function userFromToken(token: string) {
  // planted: decode without verify
  return jwt.decode(token);
}

export function exportReport(name: string) {
  // planted: shell command built from input
  exec(`tar czf /tmp/${name}.tgz /srv/reports/${name}`);
}

// planted: hardcoded demo credentials
export const demoLogin = { email: "demo@fleet.example", password: "fleet-demo-zugang" };
