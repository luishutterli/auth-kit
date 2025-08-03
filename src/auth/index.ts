import { zValidator } from "@hono/zod-validator";
import { DatabaseError, type User } from "@luishutterli/auth-kit-types";
import { Hono } from "hono";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import z from "zod";
import { getConfig } from "../config/config";
import { getConnection } from "../db/connection";
import { dummyHashVerify, generateDBHash, verifyPassword } from "../util/hash";
import { validatePasswordWithError } from "../util/password";
import { addJWTCookie } from "./cookies";
import { createSignedJWT, JWTtoString, jwtMiddleware } from "./jwt";

const config = getConfig();

const app = new Hono();

// /signup
const signupUserSchema = z.object({
  email: z.email().max(255),
  name: z.string().min(2).max(45),
  surname: z.string().min(2).max(45),
  password: z.string().min(2),
});

app.post("/signup", zValidator("json", signupUserSchema), async (c) => {
  const { email, name, surname, password } = c.req.valid("json");
  const passwordError = validatePasswordWithError(password);
  if (passwordError) {
    return c.json({ error: passwordError }, 400);
  }

  const connection = await getConnection();
  try {
    await connection.beginTransaction();

    // Step 1: Check if user already exists
    const [existingUsers] = await connection.execute<RowDataPacket[]>(
      "SELECT * FROM TAccounts WHERE accEmail = ?",
      [email],
    );
    if (existingUsers.length > 0) {
      return c.json({ error: "Email already in use" }, 400);
    }

    // Step 2: Hash and salt the password
    const hashedPassword = generateDBHash(password);

    // Step 3: Insert the user into db (and get id)
    const [result] = await connection.execute<ResultSetHeader>(
      "insert into TAccounts (accEmail, accName, accSurname, accPasswordHash, accStatus) values (?, ?, ?, ?, 'active');",
      [email, name, surname, hashedPassword],
    );
    const userId = result.insertId;

    await connection.commit();

    // Step 4: Login the user
    const user: User = {
      id: userId,
      email,
      name,
      surname,
      emailVerified: false,
      createdAt: new Date(),
      twoFactorEnabled: false,
    };
    const jwt = createSignedJWT(user);
    addJWTCookie(c, jwt);

    console.log("New user created with id:", userId);
    return c.json({ success: true, userId }, 201);
  } catch (error) {
    await connection.rollback();
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to sign up user", error as Error);
  } finally {
    connection.release();
  }
});

// /login
const loginUserSchema = z.object({
  email: z.email(),
  password: z.string().min(2),
});

const wrongCredentialMessage = "Wrong email or password";

app.post("/login", zValidator("json", loginUserSchema), async (c) => {
  const { email, password } = c.req.valid("json");

  const connection = await getConnection();
  try {
    // Step 1: Check if user exists and get all user data
    const [users] = await connection.execute<
      RowDataPacket[] &
        {
          accId: number;
          accEmail: string;
          accName: string;
          accSurname: string;
          accPasswordHash: string;
          accEmailVerified: number;
          accCreated: Date;
        }[]
    >(
      `SELECT accId, accEmail, accName, accSurname, accPasswordHash, accEmailVerified, accCreated FROM TAccounts WHERE accEmail = ?`,
      [email],
    );

    if (users.length === 0) {
      // NOTE: To mitigate email enumeration via timing attacks, a dummy hash is calculated
      if (config.emailEnumerationProtection) dummyHashVerify();
      return c.json({ success: false, error: wrongCredentialMessage }, 401);
    }
    const userRow = users[0];

    const passwordValid = verifyPassword(userRow.accPasswordHash, password);
    if (!passwordValid) {
      return c.json({ success: false, error: wrongCredentialMessage }, 401);
    }

    // Step 2: Create User object for JWT
    const user: User = {
      id: userRow.accId,
      email: userRow.accEmail,
      name: userRow.accName,
      surname: userRow.accSurname,
      emailVerified: userRow.accEmailVerified === 1,
      createdAt: userRow.accCreated,
      twoFactorEnabled: false,
    };

    // Step 3: Create JWT and return
    const jwt = createSignedJWT(user);
    addJWTCookie(c, jwt);

    return c.json(
      {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          surname: user.surname,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      },
      200,
    );
  } catch (error) {
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to log in user", error as Error);
  } finally {
    connection.release();
  }
});

// /refresh
// TODO: IMPLEMENT

// /me
// TODO: IMPLEMENT

// /org/create
const createOrgSchema = z.object({
  name: z.string().min(3).max(255),
});
app.post("/org/create", jwtMiddleware, zValidator("json", createOrgSchema), async (c) => {
  const { name } = c.req.valid("json");

  const connection = await getConnection();
  try {
    await connection.beginTransaction();

    // Step 2: Create organization
    const [result] = await connection.execute<ResultSetHeader>(
      "insert into TOrganizations (orgName, orgStatus) values (?, 'active');",
      [name],
    );
    const orgId = result.insertId;

    // TODO: Step 3: Add current user to organization (with owner perms)

    await connection.commit();

    console.log("New organization created with id:", orgId);
    return c.json({ success: true, orgId }, 201);
  } catch (error) {
    await connection.rollback();
    if (error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError("Failed to create organization", error as Error);
  } finally {
    connection.release();
  }
});

export { app as authApp };
